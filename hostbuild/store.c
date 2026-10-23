/* Ariel host build: staging, approvals and the hash-addressed store.

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
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha256.h"
#include "store.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/** At most this many staged objects wait for a commit. **/
#define STAGING_MAX   8

/** Staging holds at most this many bytes in total, and one upload is at
    most this large. **/
#define STAGING_BYTES_MAX (64ULL * 1024ULL * 1024ULL)

/** At most this many approvals are remembered at once. **/
#define APPROVALS_MAX 16

/** At most this many approvals wait for a decision at once. **/
#define PENDING_MAX   3

/** The longest text the controller shows for one approval. **/
#define PROMPT_MAX    256

/** One read or write of an object moving into the store. **/
#define MOVE_CHUNK    65536

/** One object is at most 64 MiB, the same limit an upload has. **/
#define OBJECT_LIMIT  (64ULL * 1024ULL * 1024ULL)

/** An approval is good for this long after it was requested. **/
#define APPROVAL_EXPIRY_MS 120000ULL

/** A staging object nobody committed leaves after this long. **/
#define STAGING_TTL_MS     900000ULL

/** At most one notification is shown every this many milliseconds. **/
#define NOTIFICATION_GAP_MS 10000ULL

/** One member of the staging table. **/
struct staged {
  int used;
  char id[APPROVAL_ID_MAX];
  char approval_id[APPROVAL_ID_MAX];
  approval_facts_t facts;
  uint64_t reserved;
  uint64_t created_ms;
};

/** One member of the approval table. **/
struct approval {
  int used;
  int decided;
  int approved;
  int expired;
  char id[APPROVAL_ID_MAX];
  uint64_t created_ms;
};

/**
 * One mutex covers the staging table, the approval table and the pending
 * count. Consuming an approval is atomic because no other connection can
 * look at the tables while a commit holds it.
 **/
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct staged staged[STAGING_MAX];
static struct approval approvals[APPROVALS_MAX];
static unsigned long staging_count;
static unsigned long approval_count;
static uint64_t staging_bytes;
static int notified;
static uint64_t last_notification_ms;
static char state_dir[PATH_MAX];
static platform_t *platform;

/* The directory helpers every entry below Ariel's directory goes through. */
static int state_open(void);
static int dir_open(int dirfd, const char *name);
static int dir_make(int dirfd, const char *name);
static void staging_clear(void);
static void expire_locked(uint64_t now);
static void *expiry_run(void *arg);


/** Give a staging entry back: its slot and the bytes it reserved. The
    caller holds the lock and deals with its file where needed. **/
static void
staged_release(struct staged *entry) {
  staging_bytes -= entry->reserved;
  memset(entry, 0, sizeof(*entry));
}


/** The platform clock in milliseconds. The caller holds the lock, so no
    entry can be newer than the time it reads. **/
static uint64_t
now_ms(void) {
  struct timespec now;

  platform->clock(platform, &now);

  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000ULL;
}


/** How long ago then was, or 0 when then is not in the past. **/
static uint64_t
elapsed_ms(uint64_t now, uint64_t then) {
  return now > then ? now - then : 0;
}


int
store_name_valid(const char *name) {
  size_t len = strlen(name);
  size_t i;

  if(len < 1 || len > PAYLOAD_NAME_MAX) {
    return 0;
  }
  if(!((name[0] >= 'a' && name[0] <= 'z') ||
       (name[0] >= '0' && name[0] <= '9'))) {
    return 0;
  }

  for(i=0; i<len; i++) {
    char c = name[i];

    if(!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
         c == '-' || c == '_')) {
      return 0;
    }
  }

  return 1;
}


/** An empty slot, or NULL when the table is full. **/
static struct staged *
staged_slot(void) {
  int i;

  for(i=0; i<STAGING_MAX; i++) {
    if(!staged[i].used) {
      return &staged[i];
    }
  }
  return NULL;
}


static struct staged *
staged_find(const char *id) {
  int i;

  for(i=0; i<STAGING_MAX; i++) {
    if(staged[i].used && !strcmp(staged[i].id, id)) {
      return &staged[i];
    }
  }
  return NULL;
}


/** An empty slot, or NULL when the table is full. **/
static struct approval *
approval_slot(void) {
  int i;

  for(i=0; i<APPROVALS_MAX; i++) {
    if(!approvals[i].used) {
      return &approvals[i];
    }
  }
  return NULL;
}


static struct approval *
approval_find(const char *id) {
  int i;

  for(i=0; i<APPROVALS_MAX; i++) {
    if(approvals[i].used && !strcmp(approvals[i].id, id)) {
      return &approvals[i];
    }
  }
  return NULL;
}


static int
pending_count(void) {
  int i;
  int count = 0;

  for(i=0; i<APPROVALS_MAX; i++) {
    if(approvals[i].used && !approvals[i].decided && !approvals[i].expired) {
      count++;
    }
  }
  return count;
}


static int
path_in(char *out, size_t size, const char *sub) {
  if(snprintf(out, size, "%s/%s", state_dir, sub) >= (int)size) {
    return -1;
  }
  return 0;
}


/**
 * Open an entry below dirfd. Every entry is opened relative to Ariel's
 * directory, without following a symbolic link, and a file this creates
 * belongs to its owner alone.
 **/
static int
open_entry(int dirfd, const char *name, int flags) {
  if(flags & O_CREAT) {
    return openat(dirfd, name, flags | O_NOFOLLOW | O_CLOEXEC, 0600);
  }
  return openat(dirfd, name, flags | O_NOFOLLOW | O_CLOEXEC);
}


int
store_init(const char *dir, platform_t *p) {
  pthread_t thread;
  int state_fd;
  int store_fd;
  int wake;
  int rc = -1;

  pthread_mutex_lock(&lock);
  snprintf(state_dir, sizeof(state_dir), "%s", dir);
  platform = p;
  staging_bytes = 0;
  notified = 0;
  last_notification_ms = 0;
  memset(staged, 0, sizeof(staged));
  memset(approvals, 0, sizeof(approvals));
  pthread_mutex_unlock(&lock);

  // No approval survives the process, so no staging object may either.
  staging_clear();

  if((state_fd=state_open()) < 0) {
    return -1;
  }

  if(dir_make(state_fd, "store")) {
    close(state_fd);
    return -1;
  }

  if((store_fd=dir_open(state_fd, "store")) >= 0) {
    if(!dir_make(store_fd, "objects") && !dir_make(store_fd, "current")) {
      rc = 0;
    }
    close(store_fd);
  }

  close(state_fd);

  if(rc) {
    return rc;
  }

  // Expiry runs on the clock, so a staging object leaves at its TTL even
  // when no request comes to notice.
  wake = platform->wake_new ? platform->wake_new(platform) : -1;
  if(pthread_create(&thread, NULL, expiry_run, (void*)(intptr_t)wake)) {
    if(wake >= 0 && platform->wake_close) {
      platform->wake_close(platform, wake);
    }
    return -1;
  }
  pthread_detach(thread);

  return 0;
}


void
store_staging_next_id(char *id, size_t size) {
  pthread_mutex_lock(&lock);
  snprintf(id, size, "s-%lx", ++staging_count);
  pthread_mutex_unlock(&lock);
}


int
store_staging_create(const char *staging_id, uint64_t size) {
  char dir[PATH_MAX];
  struct staged *slot;
  uint64_t now;
  int fd = -1;
  int dirfd;

  pthread_mutex_lock(&lock);
  now = now_ms();
  expire_locked(now);

  // The declared size is reserved before the bytes arrive, so two uploads
  // in flight cannot both pass a check the total would fail.
  if(size > STAGING_BYTES_MAX || staging_bytes > STAGING_BYTES_MAX - size) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  slot = staged_slot();

  if(slot) {
    memset(slot, 0, sizeof(*slot));
    slot->used = 1;
    slot->created_ms = now;
    slot->reserved = size;
    snprintf(slot->id, sizeof(slot->id), "%s", staging_id);
    staging_bytes += size;
  }

  pthread_mutex_unlock(&lock);

  if(slot && !path_in(dir, sizeof(dir), "staging") &&
     (dirfd=open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)) >= 0) {
    fd = open_entry(dirfd, staging_id, O_WRONLY | O_CREAT | O_EXCL);
    close(dirfd);
  }

  if(fd < 0 && slot) {
    pthread_mutex_lock(&lock);
    staged_release(slot);
    pthread_mutex_unlock(&lock);
  }

  return fd;
}


/** Delete every staging object a previous process left behind. **/
static void
staging_clear(void) {
  char dir[PATH_MAX];
  struct dirent *entry;
  DIR *list;
  int dirfd;

  if(path_in(dir, sizeof(dir), "staging")) {
    return;
  }

  if((dirfd=open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)) < 0) {
    return;
  }

  if(!(list=fdopendir(dirfd))) {
    close(dirfd);
    return;
  }

  while((entry=readdir(list))) {
    if(strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
      unlinkat(dirfd, entry->d_name, 0);
    }
  }

  closedir(list);
}


/** Delete one staging object by name, without following the entry. **/
static void
staging_unlink(const char *staging_id) {
  char dir[PATH_MAX];
  int dirfd;

  if(path_in(dir, sizeof(dir), "staging")) {
    return;
  }

  if((dirfd=open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)) < 0) {
    return;
  }

  unlinkat(dirfd, staging_id, 0);
  close(dirfd);
}


/**
 * Drop what the clock has outlived. An approval stops counting as pending
 * after its expiry, but its row stays until a commit finds it or its
 * staging object leaves, so a late commit can say approval_expired. A
 * staging object nobody committed leaves after its TTL, together with its
 * approval. The caller holds the lock.
 **/
static void
expire_locked(uint64_t now) {
  int i;

  for(i=0; i<APPROVALS_MAX; i++) {
    if(approvals[i].used && !approvals[i].expired &&
       elapsed_ms(now, approvals[i].created_ms) >= APPROVAL_EXPIRY_MS) {
      approvals[i].expired = 1;
    }
  }

  for(i=0; i<STAGING_MAX; i++) {
    struct staged *entry = &staged[i];

    if(!entry->used || elapsed_ms(now, entry->created_ms) < STAGING_TTL_MS) {
      continue;
    }

    {
      struct approval *request = approval_find(entry->approval_id);

      staging_unlink(entry->id);
      staged_release(entry);
      if(request) {
        memset(request, 0, sizeof(*request));
      }
    }
  }
}


/**
 * How long until the next staging object reaches its TTL. With none staged,
 * no object can leave sooner than one TTL from now. The caller holds the
 * lock and has just expired what the clock outlived.
 **/
static uint64_t
next_expiry_locked(uint64_t now) {
  uint64_t left = STAGING_TTL_MS;
  int i;

  for(i=0; i<STAGING_MAX; i++) {
    uint64_t age;

    if(!staged[i].used) {
      continue;
    }
    age = elapsed_ms(now, staged[i].created_ms);
    if(age < STAGING_TTL_MS && STAGING_TTL_MS - age < left) {
      left = STAGING_TTL_MS - age;
    }
  }

  return left;
}


/** Throw away every wake a clock advance left in the pipe. **/
static void
wake_drain(int wake) {
  char buf[64];

  while(read(wake, buf, sizeof(buf)) > 0) {
  }
}


/**
 * The expiry waiter: drop what the clock outlived, then wait for the next
 * expiry. With a wake pipe only a clock advance can bring it, and the
 * advance wakes the poll; without one the platform clock is real time.
 **/
static void *
expiry_run(void *arg) {
  int wake = (int)(intptr_t)arg;

  while(1) {
    struct pollfd pfd = {.fd = wake, .events = POLLIN};
    uint64_t now;
    uint64_t left;

    pthread_mutex_lock(&lock);
    now = now_ms();
    expire_locked(now);
    left = next_expiry_locked(now);
    pthread_mutex_unlock(&lock);

    if(wake < 0) {
      poll(NULL, 0, (int)left);
      continue;
    }

    if(platform->wake_idle) {
      platform->wake_idle(platform, wake, -1, 1);
    }
    poll(&pfd, 1, -1);
    if(platform->wake_idle) {
      platform->wake_idle(platform, wake, -1, 0);
    }
    wake_drain(wake);
  }

  return NULL;
}


void
store_staging_discard(const char *staging_id) {
  struct staged *slot;

  staging_unlink(staging_id);

  pthread_mutex_lock(&lock);
  if((slot=staged_find(staging_id))) {
    staged_release(slot);
  }
  pthread_mutex_unlock(&lock);
}


int
store_approval_request(const approval_facts_t *facts, char *id,
                       size_t idlen, char *prompt, size_t promptlen) {
  struct approval *slot;
  uint64_t now;

  pthread_mutex_lock(&lock);
  now = now_ms();
  expire_locked(now);

  if(pending_count() >= PENDING_MAX || !(slot=approval_slot())) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  // A flood of requests must not wear the owner down: one prompt per
  // notification window, and a refused one takes no slot and shows no
  // prompt.
  if(notified &&
     elapsed_ms(now, last_notification_ms) < NOTIFICATION_GAP_MS) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  memset(slot, 0, sizeof(*slot));
  slot->used = 1;
  slot->created_ms = now;
  snprintf(slot->id, sizeof(slot->id), "a-%lx", ++approval_count);

  snprintf(prompt, promptlen,
           "payload %s (%llu bytes, sha256 %s) will run",
           facts->name, (unsigned long long)facts->size, facts->sha256);

  if(snprintf(id, idlen, "%s", slot->id) >= (int)idlen) {
    slot->used = 0;
    pthread_mutex_unlock(&lock);
    return -1;
  }

  notified = 1;
  last_notification_ms = now;

  pthread_mutex_unlock(&lock);
  return 0;
}


int
store_approval_decide(const char *id, int approved) {
  struct approval *request;

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());
  request = approval_find(id);

  if(!request || request->decided || request->expired) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  request->decided = 1;
  request->approved = approved;
  pthread_mutex_unlock(&lock);

  return 0;
}


void
store_stage(const char *staging_id, const approval_facts_t *facts,
            const char *approval_id) {
  struct staged *slot;

  pthread_mutex_lock(&lock);
  slot = staged_find(staging_id);

  if(slot) {
    uint64_t created_ms = slot->created_ms;
    uint64_t reserved = slot->reserved;

    memset(slot, 0, sizeof(*slot));
    slot->used = 1;
    slot->created_ms = created_ms;
    slot->reserved = reserved;
    snprintf(slot->id, sizeof(slot->id), "%s", staging_id);
    snprintf(slot->approval_id, sizeof(slot->approval_id), "%s",
             approval_id);
    slot->facts = *facts;
  }

  pthread_mutex_unlock(&lock);
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


/** Open Ariel's state directory itself. **/
static int
state_open(void) {
  return open(state_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}


/** Open one directory below dirfd, without following a symbolic link. **/
static int
dir_open(int dirfd, const char *name) {
  return openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}


/** Make one directory below dirfd; an existing directory is fine. **/
static int
dir_make(int dirfd, const char *name) {
  return mkdirat(dirfd, name, 0700) && errno != EEXIST ? -1 : 0;
}


static int
entry_regular(int fd) {
  struct stat st;

  return fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
}


/**
 * Read the current record of one payload name: the hash of the object it
 * points at. A record that is missing, not a regular file or not a hash
 * counts as no record. Returns 0 when hash holds a record.
 **/
static int
current_read(int dirfd, const char *name, char hash[SHA256_HEX_LEN + 1]) {
  char buf[SHA256_HEX_LEN + 2];
  size_t total = 0;
  int fd;

  if((fd=open_entry(dirfd, name, O_RDONLY)) < 0) {
    return -1;
  }

  if(!entry_regular(fd)) {
    close(fd);
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

  return 0;
}


/**
 * Replace one payload name's current record through a temporary file and
 * an atomic rename, so a reader never sees a partial record.
 **/
static int
current_write(int dirfd, const char *name, const char *hash) {
  char tmp[PAYLOAD_NAME_MAX + 32];
  int fd;

  if(snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", name, (long)getpid()) >=
     (int)sizeof(tmp)) {
    return -1;
  }

  if((fd=open_entry(dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
    return -1;
  }

  if(write_all(fd, hash, strlen(hash)) || write_all(fd, "\n", 1) ||
     fsync(fd) || close(fd)) {
    unlinkat(dirfd, tmp, 0);
    return -1;
  }

  if(renameat(dirfd, tmp, dirfd, name)) {
    unlinkat(dirfd, tmp, 0);
    return -1;
  }

  return 0;
}


/**
 * Copy the staging object into a temporary object, hashing the bytes as
 * they pass, so the object that enters the store is exactly the bytes the
 * hash covers. Returns 0 on success.
 **/
static int
object_copy(int src, int dst, uint64_t *total, char hex[SHA256_HEX_LEN + 1]) {
  unsigned char buf[MOVE_CHUNK];
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;

  sha256_init(&hash);
  *total = 0;

  while(1) {
    ssize_t n = read(src, buf, sizeof(buf));

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(n == 0) {
      break;
    }

    sha256_update(&hash, buf, (size_t)n);
    if(write_all(dst, (const char*)buf, (size_t)n)) {
      return -1;
    }
    *total += (uint64_t)n;
  }

  sha256_final(&hash, digest);
  sha256_hex(digest, hex);

  return 0;
}


/**
 * Drop a staged entry and its approval: the staging object leaves the
 * disk and the tables forget both. The caller holds the lock.
 **/
static void
staged_consume(struct staged *entry, struct approval *request) {
  staging_unlink(entry->id);
  staged_release(entry);

  if(request) {
    memset(request, 0, sizeof(*request));
  }
}


/**
 * The approval is granted: hash the staging object again, put it in the
 * store under its hash, point the payload name's current record at it and
 * delete the object it replaces. The caller holds the lock.
 **/
static int
staged_install(struct staged *entry, struct approval *request,
               store_install_t *install) {
  char tmp[SHA256_HEX_LEN + 32];
  char hash[SHA256_HEX_LEN + 1];
  char old[SHA256_HEX_LEN + 1];
  struct stat st;
  uint64_t total = 0;
  int have_old = 0;
  int existed = 0;
  int state_fd = -1;
  int staging_fd = -1;
  int store_fd = -1;
  int objects_fd = -1;
  int current_fd = -1;
  int src = -1;
  int dst = -1;
  int rc = STORE_APPROVAL_STALE;

  if((state_fd=state_open()) < 0) {
    return STORE_APPROVAL_STALE;
  }

  if((staging_fd=dir_open(state_fd, "staging")) < 0) {
    goto out;
  }

  src = open_entry(staging_fd, entry->id, O_RDONLY);
  if(src < 0 || !entry_regular(src)) {
    // The bytes the owner approved are gone or are not a regular file.
    staged_consume(entry, request);
    goto out;
  }

  if((store_fd=dir_open(state_fd, "store")) < 0 ||
     (objects_fd=dir_open(store_fd, "objects")) < 0 ||
     (current_fd=dir_open(store_fd, "current")) < 0) {
    goto out;
  }

  if(snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", entry->facts.sha256,
              (long)getpid()) >= (int)sizeof(tmp)) {
    goto out;
  }

  if((dst=open_entry(objects_fd, tmp, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
    goto out;
  }

  if(object_copy(src, dst, &total, hash)) {
    goto out_temp;
  }

  if(total != entry->facts.size || strcmp(hash, entry->facts.sha256)) {
    // The object changed after the approval: it no longer is what the
    // owner agreed to, so it leaves the console.
    staged_consume(entry, request);
    rc = STORE_APPROVAL_STALE;
    goto out_temp;
  }

  if(fsync(dst)) {
    goto out_temp;
  }

  if(close(dst)) {
    dst = -1;
    goto out_temp;
  }
  dst = -1;

  existed = fstatat(objects_fd, hash, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISREG(st.st_mode);

  if(renameat(objects_fd, tmp, objects_fd, hash)) {
    goto out_temp;
  }

  if(current_read(current_fd, entry->facts.name, old) == 0) {
    have_old = 1;
  }

  if(current_write(current_fd, entry->facts.name, hash)) {
    if(!existed) {
      unlinkat(objects_fd, hash, 0);
    }
    goto out;
  }

  // Stage 1 keeps one build per name: the object the new one replaces goes.
  if(have_old && strcmp(old, hash) && !existed) {
    unlinkat(objects_fd, old, 0);
  }

  snprintf(install->name, sizeof(install->name), "%s", entry->facts.name);
  snprintf(install->sha256, sizeof(install->sha256), "%s", hash);
  staged_consume(entry, request);

  rc = STORE_INSTALLED;

out_temp:
  if(dst >= 0) {
    close(dst);
    unlinkat(objects_fd, tmp, 0);
  }
out:
  if(src >= 0) {
    close(src);
  }
  if(current_fd >= 0) {
    close(current_fd);
  }
  if(objects_fd >= 0) {
    close(objects_fd);
  }
  if(store_fd >= 0) {
    close(store_fd);
  }
  if(staging_fd >= 0) {
    close(staging_fd);
  }
  if(state_fd >= 0) {
    close(state_fd);
  }
  return rc;
}


int
store_commit(const char *staging_id, store_install_t *install,
             char *approval_id, size_t idlen) {
  struct staged *entry;
  struct approval *request;
  int outcome;

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());

  entry = staged_find(staging_id);
  request = entry ? approval_find(entry->approval_id) : NULL;

  if(!request) {
    // An unknown staging ID and a lost approval both mean: push again.
    outcome = STORE_APPROVAL_STALE;
  } else if(request->expired) {
    // The owner's window closed: the object leaves the console and the
    // agent pushes the build again.
    staging_unlink(entry->id);
    staged_release(entry);
    memset(request, 0, sizeof(*request));
    outcome = STORE_APPROVAL_EXPIRED;
  } else if(!request->decided) {
    snprintf(approval_id, idlen, "%s", request->id);
    outcome = STORE_APPROVAL_REQUIRED;
  } else if(!request->approved) {
    // A denial is terminal: the bytes leave the console for good.
    staging_unlink(entry->id);
    staged_release(entry);
    memset(request, 0, sizeof(*request));
    outcome = STORE_APPROVAL_DENIED;
  } else {
    outcome = staged_install(entry, request, install);
  }

  pthread_mutex_unlock(&lock);
  return outcome;
}


/** Read a whole object into memory, hashing the same bytes on the way. **/
static int
object_load(int fd, store_object_t *object, char hex[SHA256_HEX_LEN + 1]) {
  unsigned char digest[SHA256_DIGEST_LEN];
  struct stat st;
  unsigned char *bytes;
  sha256_t hash;
  size_t alloc;
  size_t len = 0;

  if(fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
     (uint64_t)st.st_size > OBJECT_LIMIT) {
    return -1;
  }

  // One byte past the size just checked tells a file that grew apart.
  alloc = (size_t)st.st_size + 1;

  if(!(bytes = malloc(alloc))) {
    return -1;
  }

  sha256_init(&hash);

  while(1) {
    ssize_t n;

    if(len == alloc) {
      // The object grew since it was checked: it is no longer trusted.
      free(bytes);
      return -1;
    }

    n = read(fd, bytes + len, alloc - len);
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      free(bytes);
      return -1;
    }
    if(n == 0) {
      break;
    }

    sha256_update(&hash, bytes + len, (size_t)n);
    len += (size_t)n;
  }

  sha256_final(&hash, digest);
  sha256_hex(digest, hex);

  object->bytes = bytes;
  object->size = len;
  return 0;
}


int
store_run_load(const char *name, store_object_t *object) {
  char computed[SHA256_HEX_LEN + 1];
  char expected[SHA256_HEX_LEN + 1];
  int objects_fd = -1;
  int current_fd = -1;
  int store_fd = -1;
  int state_fd = -1;
  int fd = -1;
  int rc = STORE_RUN_STALE;

  object->bytes = NULL;
  object->size = 0;

  if(!store_name_valid(name)) {
    return STORE_RUN_UNKNOWN;
  }

  pthread_mutex_lock(&lock);

  if((state_fd=state_open()) < 0 ||
     (store_fd=dir_open(state_fd, "store")) < 0 ||
     (current_fd=dir_open(store_fd, "current")) < 0) {
    goto out;
  }

  if(current_read(current_fd, name, expected) < 0) {
    rc = STORE_RUN_UNKNOWN;
    goto out;
  }

  if((objects_fd=dir_open(store_fd, "objects")) < 0) {
    goto out;
  }

  // Open the object through the record, without following a link, and
  // read it once. The bytes that are hashed are the bytes that run.
  // O_NONBLOCK keeps a FIFO with no writer from hanging the open while the
  // store lock is held; object_load rejects anything but a regular file.
  if((fd=open_entry(objects_fd, expected, O_RDONLY | O_NONBLOCK)) < 0) {
    goto out;
  }

  if(object_load(fd, object, computed)) {
    goto out;
  }

  if(strcmp(computed, expected)) {
    // The object changed behind Ariel's back: it never runs.
    store_object_free(object);
    goto out;
  }

  rc = STORE_RUN_OK;

out:
  if(fd >= 0) {
    close(fd);
  }
  if(objects_fd >= 0) {
    close(objects_fd);
  }
  if(current_fd >= 0) {
    close(current_fd);
  }
  if(store_fd >= 0) {
    close(store_fd);
  }
  if(state_fd >= 0) {
    close(state_fd);
  }

  pthread_mutex_unlock(&lock);
  return rc;
}


void
store_object_free(store_object_t *object) {
  free(object->bytes);
  object->bytes = NULL;
  object->size = 0;
}
