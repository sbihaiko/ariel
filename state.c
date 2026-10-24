/* Ariel: the state file, the single record of installed payloads.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#if defined(__APPLE__)
// macOS hides O_NOFOLLOW behind _DARWIN_C_SOURCE once _POSIX_C_SOURCE is
// defined, and every file here is opened without following symbolic links.
#define _DARWIN_C_SOURCE 1
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ps5_at.h"
#include "sha256.h"
#include "state.h"
#include "store.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/** The state file, beside the store under Ariel's directory. **/
#define STATE_FILE "state"

/** The state file's marker, so a later reader can tell this text apart. **/
#define STATE_MARKER "ariel-state-v2"

/** The marker of the format before health checks, which is still read. **/
#define STATE_MARKER_V1 "ariel-state-v1"

/** One read of a file moving through memory. **/
#define READ_CHUNK 65536

/** One installed payload, as the state file holds it between starts. **/
struct state_payload {
  int used;
  char name[PAYLOAD_NAME_MAX + 1];
  char source[16];
  char version[64];
  uint64_t release;
  uint64_t asset;
  char sha256[SHA256_HEX_LEN + 1];
  char path[256];
  int running;
  char previous[SHA256_HEX_LEN + 1];
  uint64_t timeout;
  int failed;
};

/**
 * One mutex covers the record. The record is the state file read into memory
 * once per start, so a list and a commit see the same payloads.
 **/
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct state_payload payloads[STATE_PAYLOADS_MAX];
static int loaded;
static char state_dir[PATH_MAX];

/** Open an entry below dirfd, without following a symbolic link. **/
static int
open_entry(int dirfd, const char *name, int flags) {
  if(flags & O_CREAT) {
    return openat(dirfd, name, flags | O_NOFOLLOW | O_CLOEXEC, 0600);
  }
  return openat(dirfd, name, flags | O_NOFOLLOW | O_CLOEXEC);
}


/** Open one directory below dirfd, without following a symbolic link. **/
static int
dir_open(int dirfd, const char *name) {
  return openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}


static int
write_all(int fd, const char *buf, size_t len) {
  while(len > 0) {
    ssize_t n = write(fd, buf, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    buf += n;
    len -= (size_t)n;
  }
  return 0;
}


/** Whether text is exactly one lowercase hex SHA-256 and nothing else. **/
static int
hash_text(const char *text) {
  size_t i;

  for(i=0; i<SHA256_HEX_LEN; i++) {
    if(!((text[i] >= '0' && text[i] <= '9') ||
         (text[i] >= 'a' && text[i] <= 'f'))) {
      return 0;
    }
  }

  return text[SHA256_HEX_LEN] == '\0';
}


/** The path the state file records for one hash-addressed object. **/
static void
object_path(const char *hash, char *out, size_t size) {
  snprintf(out, size, "/data/ariel/store/objects/%s", hash);
}


/** Find one payload in the record by name. The caller holds the lock. **/
static struct state_payload *
payload_find(const char *name) {
  size_t i;

  for(i=0; i<STATE_PAYLOADS_MAX; i++) {
    if(payloads[i].used && !strcmp(payloads[i].name, name)) {
      return &payloads[i];
    }
  }

  return NULL;
}


/** Take a free slot in the record. The caller holds the lock. **/
static struct state_payload *
payload_slot(void) {
  size_t i;

  for(i=0; i<STATE_PAYLOADS_MAX; i++) {
    if(!payloads[i].used) {
      return &payloads[i];
    }
  }

  return NULL;
}


/**
 * Read the hash a Stage 1 current record holds. A record that is missing, not
 * a regular file or not a hash counts as no record. Returns 0 when hash holds
 * one.
 **/
static int
current_read(int dirfd, const char *name, char hash[SHA256_HEX_LEN + 1]) {
  char buf[SHA256_HEX_LEN + 2];
  size_t total = 0;
  int fd;

  if((fd=open_entry(dirfd, name, O_RDONLY)) < 0) {
    return -1;
  }

  while(total < sizeof(buf)) {
    ssize_t n = read(fd, buf + total, sizeof(buf) - total);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      close(fd);
      return -1;
    }
    if(n == 0) {
      break;
    }
    total += (size_t)n;
  }

  close(fd);

  if(total < SHA256_HEX_LEN) {
    return -1;
  }

  memcpy(hash, buf, SHA256_HEX_LEN);
  hash[SHA256_HEX_LEN] = '\0';

  if(!hash_text(hash)) {
    return -1;
  }

  return 0;
}


/**
 * Write the record to a temporary file and rename it over the state file, so
 * a reader never sees a partial record. The caller holds the lock. The text
 * is built on the heap: a commit runs this on a connection thread, whose
 * stack is too small for the whole record.
 **/
static int
state_save_locked(void) {
  char *body;
  size_t size = 65536;
  size_t len = 0;
  size_t i;
  int dirfd;
  int fd;
  int rc = -1;

  if(!(body=malloc(size))) {
    return -1;
  }

  len += (size_t)snprintf(body + len, size - len, "%s\n", STATE_MARKER);

  for(i=0; i<STATE_PAYLOADS_MAX; i++) {
    struct state_payload *entry = &payloads[i];
    int wrote;

    if(!entry->used) {
      continue;
    }

    wrote = snprintf(body + len, size - len,
                     "payload %s %s %s %llu %llu %s %s %d %s %llu %d\n",
                     entry->name, entry->source,
                     entry->version[0] ? entry->version : "-",
                     (unsigned long long)entry->release,
                     (unsigned long long)entry->asset, entry->sha256,
                     entry->path, entry->running, entry->previous,
                     (unsigned long long)entry->timeout, entry->failed);
    if(wrote < 0 || len + (size_t)wrote >= size) {
      free(body);
      return -1;
    }
    len += (size_t)wrote;
  }

  if((dirfd=open(state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
     < 0) {
    free(body);
    return -1;
  }

  if((fd=open_entry(dirfd, STATE_FILE ".tmp", O_WRONLY | O_CREAT | O_EXCL))
     < 0) {
    close(dirfd);
    free(body);
    return -1;
  }

  if(!write_all(fd, body, len) && !fsync(fd) && !close(fd)) {
    fd = -1;
    if(!renameat(dirfd, STATE_FILE ".tmp", dirfd, STATE_FILE)) {
      rc = 0;
    }
  }

  if(fd >= 0) {
    close(fd);
  }
  if(rc) {
    unlinkat(dirfd, STATE_FILE ".tmp", 0);
  }

  // The directory entry must be on disk before a restart can depend on it.
  fsync(dirfd);
  close(dirfd);
  free(body);

  return rc;
}


/**
 * Read one payload line of the state file into a free slot. A line that is
 * not well formed is an error: a record Ariel cannot read is not a record.
 * A v1 line has no timeout and no failed flag, so both take their defaults.
 **/
static int
parse_payload(char *line, int v1) {
  struct state_payload parsed;
  struct state_payload *slot;
  char version[64];
  unsigned long long release;
  unsigned long long asset;
  unsigned long long timeout = 0;
  int running;
  int failed = 0;
  int got;

  memset(&parsed, 0, sizeof(parsed));
  got = sscanf(line,
               "payload %32s %15s %63s %llu %llu %64s %255s %d %64s %llu %d",
               parsed.name, parsed.source, version, &release, &asset,
               parsed.sha256, parsed.path, &running, parsed.previous,
               &timeout, &failed);

  // A v1 line from before previous was recorded has eight fields; its payload
  // had no previous version.
  if(v1 && got == 8) {
    snprintf(parsed.previous, sizeof(parsed.previous), "-");
    got = 9;
  }

  if(got != (v1 ? 9 : 11) || !store_name_valid(parsed.name) ||
     !hash_text(parsed.sha256) ||
     (running != 0 && running != 1) || (failed != 0 && failed != 1) ||
     (strcmp(parsed.previous, "-") && !hash_text(parsed.previous))) {
    return -1;
  }
  parsed.timeout = (uint64_t)timeout;
  parsed.failed = failed;

  if(strcmp(version, "-")) {
    snprintf(parsed.version, sizeof(parsed.version), "%s", version);
  }

  slot = payload_slot();
  if(!slot || payload_find(parsed.name)) {
    return -1;
  }

  parsed.used = 1;
  parsed.release = (uint64_t)release;
  parsed.asset = (uint64_t)asset;
  parsed.running = running;
  *slot = parsed;

  return 0;
}


/**
 * Read one whole file, at most limit bytes, into a fresh buffer. A file that
 * is not a regular file, or that is larger, is refused. Returns the buffer
 * and its length, or NULL. The chunk is on the heap: this runs at start and
 * on a connection thread alike.
 **/
static char *
file_read(int dirfd, const char *name, size_t limit, size_t *len) {
  struct stat st;
  char *buf;
  unsigned char *chunk;
  size_t got = 0;
  int fd;

  *len = 0;

  if((fd=open_entry(dirfd, name, O_RDONLY)) < 0) {
    return NULL;
  }

  if(fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
     (uint64_t)st.st_size > limit) {
    close(fd);
    return NULL;
  }

  if(!(buf=malloc((size_t)st.st_size + 1)) || !(chunk=malloc(READ_CHUNK))) {
    free(buf);
    close(fd);
    return NULL;
  }

  while(got < (size_t)st.st_size) {
    size_t want = (size_t)st.st_size - got;
    ssize_t n;

    if(want > READ_CHUNK) {
      want = READ_CHUNK;
    }

    n = read(fd, chunk, want);
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      free(chunk);
      free(buf);
      close(fd);
      return NULL;
    }
    if(n == 0) {
      break;
    }
    memcpy(buf + got, chunk, (size_t)n);
    got += (size_t)n;
  }

  free(chunk);
  close(fd);
  buf[got] = '\0';
  *len = got;

  return buf;
}


/** Read the state file into the record. Returns 0, or -1 when unreadable. **/
static int
state_read(void) {
  char *text;
  char *line;
  size_t len;
  int dirfd;
  int seen = 0;
  int v1 = 0;
  int rc = -1;

  if((dirfd=open(state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
     < 0) {
    return -1;
  }

  text = file_read(dirfd, STATE_FILE, 65536, &len);
  close(dirfd);

  if(!text) {
    return -1;
  }

  line = text;
  while(*line) {
    char *next = strchr(line, '\n');

    if(next) {
      *next = '\0';
      next++;
    }

    if(!seen) {
      if(!strcmp(line, STATE_MARKER_V1)) {
        v1 = 1;
      } else if(strcmp(line, STATE_MARKER)) {
        free(text);
        return -1;
      }
      seen = 1;
    } else if(*line && parse_payload(line, v1)) {
      free(text);
      return -1;
    }

    if(!next) {
      break;
    }
    line = next;
  }

  if(seen) {
    rc = 0;
  }

  free(text);
  return rc;
}


/**
 * Build the record once from Stage 1's per-name current records: each record
 * names the hash of a push, and a push has no release. The current records
 * stay where they are; a later start never reads them again.
 **/
static int
state_migrate(void) {
  struct dirent *entry;
  int root_fd = -1;
  int store_fd = -1;
  int current_fd = -1;
  DIR *list = NULL;
  int rc = -1;

  if((root_fd=open(state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
     < 0 || (store_fd=dir_open(root_fd, "store")) < 0 ||
     (current_fd=dir_open(store_fd, "current")) < 0) {
    goto out;
  }

  if(!(list=fdopendir(current_fd))) {
    goto out;
  }
  current_fd = -1;

  while((entry=readdir(list))) {
    char hash[SHA256_HEX_LEN + 1];
    struct state_payload *slot;

    if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
      continue;
    }

    // A record Stage 1 would not trust is not a payload: skip it.
    if(!store_name_valid(entry->d_name) ||
       current_read(dirfd(list), entry->d_name, hash)) {
      continue;
    }

    slot = payload_slot();
    if(!slot) {
      goto out;
    }

    memset(slot, 0, sizeof(*slot));
    slot->used = 1;
    snprintf(slot->name, sizeof(slot->name), "%s", entry->d_name);
    snprintf(slot->source, sizeof(slot->source), "push");
    snprintf(slot->sha256, sizeof(slot->sha256), "%s", hash);
    snprintf(slot->previous, sizeof(slot->previous), "-");
    object_path(hash, slot->path, sizeof(slot->path));
  }

  rc = state_save_locked();

out:
  if(list) {
    closedir(list);
  }
  if(current_fd >= 0) {
    close(current_fd);
  }
  if(store_fd >= 0) {
    close(store_fd);
  }
  if(root_fd >= 0) {
    close(root_fd);
  }

  return rc;
}


int
state_open(const char *dir) {
  struct stat st;
  int dirfd;
  int exists;
  int rc;

  pthread_mutex_lock(&lock);

  snprintf(state_dir, sizeof(state_dir), "%s", dir);
  memset(payloads, 0, sizeof(payloads));
  loaded = 0;

  if((dirfd=open(state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
     < 0) {
    pthread_mutex_unlock(&lock);
    return -1;
  }
  exists = fstatat(dirfd, STATE_FILE, &st, AT_SYMLINK_NOFOLLOW) == 0;
  close(dirfd);

  // The file is the record from the moment it exists. Only a start that finds
  // none builds it, and it builds it from the current records exactly once.
  if(exists) {
    rc = state_read();
  } else {
    rc = state_migrate();
  }

  // No run outlives the process that started it, so no payload is running
  // when Ariel starts and none is started again here.
  if(!rc) {
    size_t i;

    for(i=0; i<STATE_PAYLOADS_MAX; i++) {
      payloads[i].running = 0;
    }
    loaded = 1;
  }

  pthread_mutex_unlock(&lock);
  return rc;
}


int
state_record(const char *name, const char *hash, const char *previous) {
  struct state_payload *entry;
  int rc;

  pthread_mutex_lock(&lock);

  if(!loaded) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  entry = payload_find(name);

  if(!entry && !(entry=payload_slot())) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  if(!entry->used) {
    memset(entry, 0, sizeof(*entry));
    entry->used = 1;
    snprintf(entry->name, sizeof(entry->name), "%s", name);
    snprintf(entry->source, sizeof(entry->source), "push");
  }

  if(strcmp(entry->sha256, hash)) {
    entry->failed = 0;
  }
  snprintf(entry->sha256, sizeof(entry->sha256), "%s", hash);
  snprintf(entry->previous, sizeof(entry->previous), "%s", previous);
  object_path(hash, entry->path, sizeof(entry->path));
  entry->running = 0;

  rc = state_save_locked();
  pthread_mutex_unlock(&lock);

  return rc;
}


int
state_previous(const char *name, char *previous, size_t size) {
  struct state_payload *entry;

  pthread_mutex_lock(&lock);

  if(!loaded) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  entry = payload_find(name);
  snprintf(previous, size, "%s", entry ? entry->previous : "-");

  pthread_mutex_unlock(&lock);
  return 0;
}


int
state_referenced(const char *hash, const char *name) {
  size_t i;
  int found = 0;

  pthread_mutex_lock(&lock);
  for(i=0; i<STATE_PAYLOADS_MAX; i++) {
    struct state_payload *entry = &payloads[i];

    if(!entry->used || !strcmp(entry->name, name)) {
      continue;
    }
    if(!strcmp(entry->sha256, hash) || !strcmp(entry->previous, hash)) {
      found = 1;
    }
  }
  pthread_mutex_unlock(&lock);

  return found;
}


int
state_list(state_payload_t *entries, size_t max, size_t *count) {
  size_t i;
  size_t n = 0;

  pthread_mutex_lock(&lock);

  if(!loaded) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  for(i=0; i<STATE_PAYLOADS_MAX && n<max; i++) {
    struct state_payload *entry = &payloads[i];

    if(!entry->used) {
      continue;
    }

    memset(&entries[n], 0, sizeof(entries[n]));
    snprintf(entries[n].name, sizeof(entries[n].name), "%s", entry->name);
    snprintf(entries[n].source, sizeof(entries[n].source), "%s", entry->source);
    snprintf(entries[n].version, sizeof(entries[n].version), "%s",
             entry->version);
    entries[n].release = entry->release;
    entries[n].asset = entry->asset;
    snprintf(entries[n].sha256, sizeof(entries[n].sha256), "%s", entry->sha256);
    snprintf(entries[n].path, sizeof(entries[n].path), "%s", entry->path);
    entries[n].running = entry->running;
    snprintf(entries[n].previous, sizeof(entries[n].previous), "%s",
             entry->previous);
    entries[n].timeout = entry->timeout;
    entries[n].failed = entry->failed;
    n++;
  }

  pthread_mutex_unlock(&lock);
  *count = n;

  return 0;
}


int
state_health_set(const char *name, uint64_t timeout) {
  struct state_payload *entry;
  int rc = -1;

  pthread_mutex_lock(&lock);

  if(loaded && (entry=payload_find(name))) {
    entry->timeout = timeout;
    rc = state_save_locked();
  }

  pthread_mutex_unlock(&lock);
  return rc;
}


int
state_failed_set(const char *name, int failed) {
  struct state_payload *entry;
  int rc = -1;

  pthread_mutex_lock(&lock);

  if(loaded && (entry=payload_find(name))) {
    entry->failed = failed;
    rc = state_save_locked();
  }

  pthread_mutex_unlock(&lock);
  return rc;
}


int
state_health_get(const char *name, uint64_t *timeout, int *failed) {
  struct state_payload *entry;
  int rc = -1;

  pthread_mutex_lock(&lock);

  if(loaded && (entry=payload_find(name))) {
    *timeout = entry->timeout;
    *failed = entry->failed;
    rc = 0;
  }

  pthread_mutex_unlock(&lock);
  return rc;
}
