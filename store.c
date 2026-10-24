/* Ariel: staging, approvals and the hash-addressed store.

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

#include "approval.h"
#include "autoload.h"
#include "protected.h"
#include "sha256.h"
#include "store.h"
#include "ps5_at.h"

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

/**
 * At most this many consumed nonces are remembered, newest last. A nonce
 * is only good for one approval window, and no approval outlives the
 * process, so the oldest can go: what a restart must never allow is the
 * nonce of a signature the owner gave a moment ago.
 **/
#define NONCES_MAX 1024

/** The file in Ariel's directory that holds the consumed nonces. **/
#define NONCES_FILE "nonces"

/** The audit log: one appended line per action Ariel takes. **/
#define AUDIT_FILE "audit.log"

/**
 * The journal: the one store change in progress, under store/. It is replaced
 * as a whole, so a start reads either the record before a phase or after it.
 **/
#define JOURNAL_FILE "journal"
#define JOURNAL_TMP "journal.tmp"
#define JOURNAL_MARKER "ariel-journal-v2"
#define JOURNAL_MARKER_V1 "ariel-journal-v1"
#define AUTOLOAD_FILE "autoload"
#define AUTOLOAD_TMP "autoload.tmp"

/** One member of the approval table. **/
struct approval {
  int used;
  int decided;
  int approved;
  int expired;
  int consumed;
  int released;
  int gated;
  char id[APPROVAL_ID_MAX];
  uint64_t created_ms;
  approval_challenge_t challenge;
  approval_facts_t facts;
};

/**
 * One mutex covers the staging table, the approval table and the pending
 * count. Consuming an approval is atomic because no other connection can
 * look at the tables while a commit holds it.
 **/
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct staged staged[STAGING_MAX];
static struct approval approvals[APPROVALS_MAX];
static unsigned char nonces[NONCES_MAX][APPROVAL_NONCE_LEN];
static size_t nonce_count;
static unsigned long staging_count;
static unsigned long approval_count;
static uint64_t staging_bytes;
static int notified;
static uint64_t last_notification_ms;
static char state_dir[PATH_MAX];
static platform_t *platform;

/* The directory helpers every entry below Ariel's directory goes through. */
static int root_open(void);
static int dir_open(int dirfd, const char *name);
static int dir_make(int dirfd, const char *name);
static void staging_clear(void);
static void expire_locked(uint64_t now);
static struct approval *rollback_open_find(const char *name);
static void *expiry_run(void *arg);
static int nonces_load(void);
static int write_all(int fd, const char *buf, size_t len);
static int audit_append_locked(const char *kind, const char *name,
                               const char *id, const char *sha256);
static int transaction_recover_locked(int state_fd, int store_fd);
static int recover_at_start(int state_fd);
static int autoload_make(int state_fd);


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


/**
 * An empty slot, or NULL when no row can give one up. A row gives its slot
 * up only once it has answered (consumed, expired or denied) and nothing
 * still needs it: a payload's staged object must find its row at commit, so
 * a payload row waits for its release; a gated row has no staged object and
 * goes once it has answered. The oldest such row goes first.
 **/
static struct approval *
approval_slot(void) {
  struct approval *oldest = NULL;
  int i;

  for(i=0; i<APPROVALS_MAX; i++) {
    if(!approvals[i].used) {
      return &approvals[i];
    }
  }

  for(i=0; i<APPROVALS_MAX; i++) {
    struct approval *slot = &approvals[i];

    if(!(slot->released || slot->gated) ||
       !(slot->consumed || slot->expired || (slot->decided && !slot->approved))) {
      continue;
    }
    if(!oldest || slot->created_ms < oldest->created_ms) {
      oldest = slot;
    }
  }

  if(oldest) {
    memset(oldest, 0, sizeof(*oldest));
  }
  return oldest;
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
    if(approvals[i].used && !approvals[i].decided && !approvals[i].expired &&
       !approvals[i].consumed) {
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


/**
 * Make an empty file below dirfd if none exists, so the protected-object
 * check has an inode to compare. An existing file is kept as it is.
 **/
static int
file_make(int dirfd, const char *name) {
  int fd = open_entry(dirfd, name, O_WRONLY | O_CREAT);

  if(fd < 0) {
    return -1;
  }
  return close(fd);
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
  protected_init(dir);
  platform = p;
  staging_bytes = 0;
  notified = 0;
  last_notification_ms = 0;
  memset(staged, 0, sizeof(staged));
  memset(approvals, 0, sizeof(approvals));
  nonce_count = 0;
  pthread_mutex_unlock(&lock);

  // No approval survives the process, so no staging object may either.
  staging_clear();

  if((state_fd=root_open()) < 0) {
    return -1;
  }

  // A nonce consumed before this start must stay consumed: an unreadable
  // record is an error, never an empty one.
  if(nonces_load()) {
    close(state_fd);
    return -1;
  }

  if(file_make(state_fd, "approvals") || file_make(state_fd, "nonces")) {
    close(state_fd);
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

  // The state file is built from Stage 1's current records, which live under
  // the store just made; a start that finds the file leaves those alone.
  if(!rc && state_open(state_dir)) {
    rc = -1;
  }

  // A change the last run left in the journal finishes before anything else
  // is served: it rolls back when it had not committed and forward when it had.
  // It runs before the default list is made, which must not replace a list a
  // committed change still names.
  if(!rc && recover_at_start(state_fd)) {
    rc = -1;
  }

  if(!rc && autoload_make(state_fd)) {
    rc = -1;
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
 * Drop a staged entry: its file, its slot and its bytes. The approval it
 * names is released, so its row may be given up once it has answered. The
 * caller holds the lock.
 **/
static void
staged_leave(struct staged *entry) {
  struct approval *request = approval_find(entry->approval_id);

  staging_unlink(entry->id);
  staged_release(entry);

  if(request) {
    request->released = 1;
  }
}


/**
 * Drop what the clock has outlived. An approval stops counting as pending
 * after its expiry, but its row stays, so a later question can still say
 * expired and a late commit can say approval_expired. A staging object
 * nobody committed leaves after its TTL; its approval stays too, answered
 * as expired rather than forgotten. A rollback stages nothing, so an
 * expired one is released here and its row can be given up. The caller
 * holds the lock.
 **/
static void
expire_locked(uint64_t now) {
  int i;

  for(i=0; i<APPROVALS_MAX; i++) {
    struct approval *request = &approvals[i];

    if(request->used && !request->expired &&
       elapsed_ms(now, request->created_ms) >= APPROVAL_EXPIRY_MS) {
      request->expired = 1;
      if(!strcmp(request->facts.command, "payload.rollback")) {
        request->released = 1;
      }
    }
  }

  for(i=0; i<STAGING_MAX; i++) {
    struct staged *entry = &staged[i];

    if(!entry->used || elapsed_ms(now, entry->created_ms) < STAGING_TTL_MS) {
      continue;
    }

    staged_leave(entry);
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


/** Whether a nonce was consumed. The caller holds the lock. **/
static int
nonce_consumed(const unsigned char *nonce) {
  size_t i;

  for(i=0; i<nonce_count; i++) {
    if(!memcmp(nonces[i], nonce, APPROVAL_NONCE_LEN)) {
      return 1;
    }
  }
  return 0;
}


/**
 * Write the nonces to the state directory through a temporary file and an
 * atomic rename, so a reader never sees a partial record and a crash keeps
 * the old one whole. The file is on disk when this returns 0.
 **/
static int
nonces_write(const unsigned char list[][APPROVAL_NONCE_LEN], size_t count) {
  char tmp[64];
  char line[2 * APPROVAL_NONCE_LEN + 2];
  size_t i;
  int dirfd;
  int synced;
  int closed;
  int fd;

  if((dirfd=root_open()) < 0) {
    return -1;
  }

  snprintf(tmp, sizeof(tmp), NONCES_FILE ".tmp.%ld", (long)getpid());

  if((fd=open_entry(dirfd, tmp, O_WRONLY | O_CREAT | O_TRUNC)) < 0) {
    close(dirfd);
    return -1;
  }

  for(i=0; i<count; i++) {
    approval_hex_encode(list[i], APPROVAL_NONCE_LEN, line);
    line[2 * APPROVAL_NONCE_LEN] = '\n';
    if(write_all(fd, line, sizeof(line) - 1)) {
      goto fail;
    }
  }

  // Close on both outcomes: fail closes only a descriptor still open.
  synced = fsync(fd);
  closed = close(fd);
  fd = -1;
  if(synced || closed) {
    goto fail;
  }

  if(renameat(dirfd, tmp, dirfd, NONCES_FILE)) {
    fd = -1;
    goto fail;
  }

  // The rename is only durable once the directory is.
  if(fsync(dirfd)) {
    close(dirfd);
    return -1;
  }

  close(dirfd);
  return 0;

fail:
  if(fd >= 0) {
    close(fd);
  }
  unlinkat(dirfd, tmp, 0);
  close(dirfd);
  return -1;
}


/** Read the consumed nonces back at start. A missing file is no nonces. **/
static int
nonces_load(void) {
  char line[2 * APPROVAL_NONCE_LEN + 2];
  FILE *file;
  int dirfd;
  int fd;
  int rc = 0;

  if((dirfd=root_open()) < 0) {
    return -1;
  }

  fd = open_entry(dirfd, NONCES_FILE, O_RDONLY);
  close(dirfd);

  if(fd < 0) {
    return errno == ENOENT ? 0 : -1;
  }

  if(!(file=fdopen(fd, "r"))) {
    close(fd);
    return -1;
  }

  pthread_mutex_lock(&lock);
  while(fgets(line, sizeof(line), file)) {
    size_t len = strlen(line);

    if(len != sizeof(line) - 1 || line[len - 1] != '\n') {
      rc = -1;
      break;
    }
    line[len - 1] = '\0';

    if(nonce_count >= NONCES_MAX ||
       approval_hex_decode(line, nonces[nonce_count], APPROVAL_NONCE_LEN)) {
      rc = -1;
      break;
    }
    nonce_count++;
  }
  if(ferror(file)) {
    rc = -1;
  }
  if(rc) {
    nonce_count = 0;
  }
  pthread_mutex_unlock(&lock);

  fclose(file);
  return rc;
}


/**
 * Record a nonce as consumed on disk, and then in memory. The record is
 * written before the approval is marked decided, so the action it allows
 * never runs on a nonce the disk has not seen. The caller holds the lock.
 **/
static int
nonce_consume(const unsigned char *nonce) {
  static unsigned char next[NONCES_MAX][APPROVAL_NONCE_LEN];
  size_t keep = nonce_count < NONCES_MAX ? nonce_count : NONCES_MAX - 1;
  size_t drop = nonce_count - keep;

  memcpy(next, nonces[drop], keep * APPROVAL_NONCE_LEN);
  memcpy(next[keep], nonce, APPROVAL_NONCE_LEN);

  if(nonces_write((const unsigned char (*)[APPROVAL_NONCE_LEN])next,
                  keep + 1)) {
    return -1;
  }

  memcpy(nonces, next, (keep + 1) * APPROVAL_NONCE_LEN);
  nonce_count = keep + 1;
  return 0;
}


/** Write the decimal digits of value. **/
static void
decimal(uint64_t value, char *out, size_t size) {
  snprintf(out, size, "%llu", (unsigned long long)value);
}


/** The option that names the requested value of an attribute command. **/
static const char *
value_key(const char *command) {
  if(!strcmp(command, "chmod")) {
    return "mode";
  }
  return !strcmp(command, "chown") ? "owner" : "group";
}


/**
 * The action an approval is of, with its options. A payload's build is an
 * action on its name. A gated command is an action on its target, with the
 * entry's kind and identity, or with the argument count of a command nothing
 * implements, and with the requested value of chmod, chown or chgrp. A kill
 * is an action on its pid, with the hash of its pid and start, its signal and
 * start. A rollback is an action on its name, with the build it replaces. An
 * exec is an action on its program, with the hash of its bytes, its argument
 * count and the hash of its arguments. env and export name one variable, so
 * they have no options.
 * A reptyr is an action on its pid with its start, and a PS5 built-in also
 * carries its arguments after the target as text, arg1 first, so the owner
 * reads them. text holds the numbers the options point at.
 **/
static void
action_build(const approval_facts_t *facts, approval_action_t *action,
             approval_option_t options[APPROVAL_OPTIONS_MAX],
             char text[4][24]) {
  static const char *const arg_keys[BUILTIN_ARGS_MAX] = {
    "arg1", "arg2", "arg3", "arg4", "arg5",
  };
  size_t i;

  if(facts->target[0]) {
    action->command = facts->command;
    action->target = facts->target;
    action->destination = facts->dest[0] ? facts->dest : NULL;
    action->sha256 = facts->sha256[0] ? facts->sha256 : APPROVAL_NO_HASH;
    if(!strcmp(facts->command, "kill")) {
      options[0].key = "signal";
      options[0].value = facts->signal;
      options[1].key = "start";
      options[1].value = facts->start;
      action->noptions = 2;
    } else if(!strcmp(facts->command, "exec")) {
      decimal(facts->argc, text[0], sizeof(text[0]));
      options[0].key = "argc";
      options[0].value = text[0];
      options[1].key = "args";
      options[1].value = facts->args;
      action->noptions = 2;
    } else if(!strcmp(facts->command, "env") ||
              !strcmp(facts->command, "export")) {
      action->noptions = 0;
    } else if(!strcmp(facts->command, "reptyr")) {
      action->sha256 = facts->sha256;
      options[0].key = "start";
      options[0].value = facts->start;
      action->noptions = 1;
    } else if(facts->kind[0]) {
      size_t n = 0;

      if(!strcmp(facts->command, "run")) {
        action->sha256 = facts->sha256;
      }
      decimal(facts->dev, text[0], sizeof(text[0]));
      decimal(facts->ino, text[1], sizeof(text[1]));
      options[n].key = "kind";
      options[n++].value = facts->kind;
      options[n].key = "dev";
      options[n++].value = text[0];
      options[n].key = "ino";
      options[n++].value = text[1];
      if(facts->fstype[0]) {
        options[n].key = "fstype";
        options[n++].value = facts->fstype;
        options[n].key = "from";
        options[n++].value = facts->from;
      }
      if(facts->type[0]) {
        decimal(facts->major, text[2], sizeof(text[2]));
        decimal(facts->minor, text[3], sizeof(text[3]));
        options[n].key = "type";
        options[n++].value = facts->type;
        options[n].key = "major";
        options[n++].value = text[2];
        options[n].key = "minor";
        options[n++].value = text[3];
      }
      action->noptions = n;
    } else {
      decimal(facts->argc, text[0], sizeof(text[0]));
      options[0].key = "argc";
      options[0].value = text[0];
      action->noptions = 1;
    }
    if(facts->value[0]) {
      options[action->noptions].key = value_key(facts->command);
      options[action->noptions].value = facts->value;
      action->noptions++;
    }
    for(i=0; i<BUILTIN_ARGS_MAX && facts->arg[i][0]; i++) {
      options[action->noptions].key = arg_keys[i];
      options[action->noptions].value = facts->arg[i];
      action->noptions++;
    }
  } else if(!strcmp(facts->command, "payload.rollback")) {
    options[0].key = "replaces";
    options[0].value = facts->replaces;
    action->command = facts->command;
    action->target = facts->name;
    action->destination = NULL;
    action->sha256 = facts->sha256;
    action->noptions = 1;
  } else {
    decimal(facts->size, text[0], sizeof(text[0]));
    options[0].key = "size";
    options[0].value = text[0];
    options[1].key = "run";
    options[1].value = "1";
    action->command = facts->command;
    action->target = facts->name;
    action->destination = NULL;
    action->sha256 = facts->sha256;
    action->noptions = facts->run ? 2 : 1;
    if(!strncmp(facts->command, "autoload.", 9)) {
      action->noptions = 0;
    }
  }

  action->options = options;
}


int
store_approval_request(const approval_facts_t *facts,
                       approval_challenge_t *challenge, char *prompt,
                       size_t promptlen) {
  char text[4][24];
  char id[APPROVAL_ID_MAX] = {0};
  approval_option_t options[APPROVAL_OPTIONS_MAX];
  approval_action_t action;
  struct approval *slot;
  const char *console;
  uint64_t now;
  int rollback;
  int tries;
  int len;

  rollback = !strcmp(facts->command, "payload.rollback");

  // The approval is of this one action. What the owner reads and signs is
  // the output of the one encoder, and a build whose facts it refuses can
  // not be approved at all.
  action_build(facts, &action, options, text);

  pthread_mutex_lock(&lock);
  now = now_ms();
  expire_locked(now);

  // Two requests for one rollback can both have found none open before
  // either inserted; the second must not open a second approval for it.
  if(pending_count() >= PENDING_MAX ||
     (rollback && rollback_open_find(facts->name)) ||
     !(slot=approval_slot())) {
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
  console = platform->console_id(platform);

  // The nonce comes from the platform's CSPRNG. One that was already
  // consumed is never offered again.
  for(tries=0; tries<4; tries++) {
    if(platform->random(platform, slot->challenge.nonce,
                        sizeof(slot->challenge.nonce))) {
      pthread_mutex_unlock(&lock);
      return -1;
    }
    if(!nonce_consumed(slot->challenge.nonce)) {
      break;
    }
  }

  len = approval_canonical(&action, slot->challenge.action,
                           sizeof(slot->challenge.action));
  if(tries == 4 || len < 0 || !console ||
     strlen(console) > APPROVAL_CONSOLE_MAX) {
    memset(slot, 0, sizeof(*slot));
    pthread_mutex_unlock(&lock);
    return -1;
  }

  slot->used = 1;
  slot->created_ms = now;
  slot->gated = facts->target[0] != '\0';
  slot->facts = *facts;
  // Built once outside the table: GCC's -Wrestrict reads a copy from
  // slot->id into slot->challenge.id as an overlap in `approvals`.
  snprintf(id, sizeof(id), "a-%lx", ++approval_count);
  memcpy(slot->id, id, sizeof(slot->id));
  memcpy(slot->challenge.id, id, sizeof(slot->challenge.id));
  snprintf(slot->challenge.console, sizeof(slot->challenge.console), "%s",
           console);
  slot->challenge.action_len = (size_t)len;
  slot->challenge.issued_ms = now;
  slot->challenge.expires_ms = now + APPROVAL_EXPIRY_MS;

  if(!strncmp(facts->command, "autoload.", 9)) {
    snprintf(prompt, promptlen, "%s %s (list sha256 %s) will change autoload",
             facts->command, facts->name, facts->sha256);
  } else if(rollback) {
    snprintf(prompt, promptlen,
             "payload %s rolls back to %s, replacing %s",
             facts->name, facts->sha256, facts->replaces);
  } else if(slot->gated && !strcmp(facts->command, "kill")) {
    snprintf(prompt, promptlen, "kill %s with %s (start %s) will run",
             facts->target, facts->signal, facts->start);
  } else if(slot->gated && !strcmp(facts->command, "run")) {
    snprintf(prompt, promptlen, "run %s (sha256 %s) will run", facts->target,
             facts->sha256);
  } else if(slot->gated) {
    snprintf(prompt, promptlen, "%s %s%s%s will run", facts->command,
             facts->target, facts->dest[0] ? " " : "", facts->dest);
  } else {
    snprintf(prompt, promptlen,
             "payload %s (%llu bytes, sha256 %s) will run",
             facts->name, (unsigned long long)facts->size, facts->sha256);
  }

  *challenge = slot->challenge;
  notified = 1;
  last_notification_ms = now;

  pthread_mutex_unlock(&lock);
  return 0;
}


/**
 * Whether two targets are the same action on the same object: the same
 * kind, device and inode, the same requested value and destination, the same
 * mount or mknod options, the same signal and process start for a kill, and
 * the same content hash, argument count and argument hash.
 **/
static int
same_identity(const approval_facts_t *a, const approval_facts_t *b) {
  return !strcmp(a->kind, b->kind) && a->dev == b->dev && a->ino == b->ino &&
         a->argc == b->argc && !strcmp(a->args, b->args) &&
         !strcmp(a->signal, b->signal) && !strcmp(a->start, b->start) &&
         !strcmp(a->value, b->value) && !strcmp(a->dest, b->dest) &&
         !strcmp(a->fstype, b->fstype) && !strcmp(a->from, b->from) &&
         !strcmp(a->type, b->type) && a->major == b->major &&
         a->minor == b->minor &&
         !strcmp(a->sha256, b->sha256) &&
         !memcmp(a->arg, b->arg, sizeof(a->arg));
}


/**
 * The gate for a gated command, one check per attempt. An open row (not
 * consumed, expired or released) for the same command, target and destination
 * is the only one that can answer; there is at most one. The caller holds the
 * lock.
 **/
static struct approval *
gate_row(const approval_facts_t *facts) {
  int i;

  for(i=0; i<APPROVALS_MAX; i++) {
    struct approval *row = &approvals[i];

    if(row->used && row->gated && !row->consumed && !row->expired &&
       !row->released && !strcmp(row->facts.command, facts->command) &&
       !strcmp(row->facts.target, facts->target) &&
       !strcmp(row->facts.dest, facts->dest)) {
      return row;
    }
  }
  return NULL;
}


int
store_gate_check(const approval_facts_t *facts,
                 approval_challenge_t *challenge) {
  char text[4][24];
  approval_option_t options[APPROVAL_OPTIONS_MAX];
  approval_action_t action;
  char canonical[APPROVAL_ACTION_MAX + 1];
  struct approval *row;
  int rc;

  action_build(facts, &action, options, text);
  if(approval_canonical(&action, canonical, sizeof(canonical)) < 0) {
    return STORE_GATE_REFUSED;
  }

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());
  row = gate_row(facts);

  if(!row) {
    rc = STORE_GATE_NEW;
  } else if(!row->decided) {
    if(same_identity(&row->facts, facts)) {
      *challenge = row->challenge;
      rc = STORE_GATE_PENDING;
    } else {
      // The entry changed while the owner was asked: the question is stale.
      row->decided = 1;
      row->approved = 0;
      row->released = 1;
      rc = STORE_GATE_NEW;
    }
  } else if(!row->approved) {
    *challenge = row->challenge;
    row->released = 1;
    rc = STORE_GATE_DENIED;
  } else {
    // The owner signed this command: the signature is spent by this answer.
    *challenge = row->challenge;
    row->consumed = 1;
    rc = same_identity(&row->facts, facts) ? STORE_GATE_GO : STORE_GATE_STALE;
  }

  pthread_mutex_unlock(&lock);
  return rc;
}


int
store_approval_grant(const char *id, const unsigned char *signature,
                     const char *console, const char *action_sha256) {
  unsigned char message[APPROVAL_MESSAGE_MAX];
  unsigned char digest[SHA256_DIGEST_LEN];
  char digest_hex[SHA256_HEX_LEN + 1];
  sha256_t hash;
  struct approval *request;
  int len;
  int rc;

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());
  request = approval_find(id);

  if(!request || request->consumed || request->released) {
    // Spent, or its staged object has left: a signature for it answers stale.
    rc = STORE_GRANT_UNKNOWN;
  } else if(request->expired) {
    rc = STORE_GRANT_EXPIRED;
  } else if(nonce_consumed(request->challenge.nonce) ||
            (request->decided && request->approved)) {
    // A signature is good once. Whatever it was, this one is spent.
    rc = STORE_GRANT_REPLAYED;
  } else if(request->decided) {
    rc = STORE_GRANT_DENIED;
  } else if(console &&
            strcmp(console, request->challenge.console)) {
    rc = STORE_GRANT_WRONG_CONSOLE;
  } else if(action_sha256 &&
            (sha256_init(&hash),
             sha256_update(&hash, request->challenge.action,
                           request->challenge.action_len),
             sha256_final(&hash, digest), sha256_hex(digest, digest_hex),
             strcmp(action_sha256, digest_hex))) {
    rc = STORE_GRANT_WRONG_ACTION;
  } else {
    len = approval_message(request->challenge.console,
                           request->challenge.action,
                           request->challenge.action_len,
                           request->challenge.nonce,
                           request->challenge.issued_ms,
                           request->challenge.expires_ms,
                           message, sizeof(message));

    // The platform checks the signature against the key pinned in the
    // build, over the exact bytes of this approval's challenge.
    if(len < 0 || platform->verify(platform, message, (size_t)len,
                                   signature)) {
      rc = STORE_GRANT_INVALID;
    } else if(nonce_consume(request->challenge.nonce)) {
      // Not recorded on disk: the action must not be allowed to run.
      rc = STORE_GRANT_ERROR;
    } else {
      request->decided = 1;
      request->approved = 1;
      rc = STORE_GRANT_OK;
    }
  }

  pthread_mutex_unlock(&lock);
  return rc;
}


int
store_approval_deny(const char *id) {
  struct approval *request;

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());
  request = approval_find(id);

  if(!request || request->decided || request->expired || request->consumed) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  request->decided = 1;
  request->approved = 0;
  pthread_mutex_unlock(&lock);

  return 0;
}


int
store_approval_facts(const char *id, approval_facts_t *facts) {
  struct approval *request;
  int found;

  pthread_mutex_lock(&lock);
  request = approval_find(id);
  found = request != NULL;

  if(found) {
    *facts = request->facts;
  }
  pthread_mutex_unlock(&lock);

  return found ? 0 : -1;
}


int
store_approval_status(const char *id) {
  struct approval *request;
  int status;

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());
  request = approval_find(id);

  if(!request) {
    status = STORE_STATUS_UNKNOWN;
  } else if(request->consumed) {
    status = STORE_STATUS_CONSUMED;
  } else if(request->expired) {
    status = STORE_STATUS_EXPIRED;
  } else if(!request->decided) {
    status = STORE_STATUS_PENDING;
  } else if(request->approved) {
    status = STORE_STATUS_GRANTED;
  } else {
    status = STORE_STATUS_DENIED;
  }

  pthread_mutex_unlock(&lock);
  return status;
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
root_open(void) {
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


/** The path the state file records for one hash-addressed object. **/
static void
object_path(const char *hash, char *out, size_t size) {
  snprintf(out, size, "/data/ariel/store/objects/%s", hash);
}


/** Whether objects holds hash as a regular file. **/
static int
object_present(int objects_fd, const char *hash) {
  struct stat st;

  if(fstatat(objects_fd, hash, &st, AT_SYMLINK_NOFOLLOW)) {
    return 0;
  }

  return S_ISREG(st.st_mode) ? 1 : 0;
}


/** One transaction's record, as the journal holds it between phases. **/
struct journal {
  char kind[16];
  char phase[16];
  char name[PAYLOAD_NAME_MAX + 1];
  char hash[SHA256_HEX_LEN + 1];
  char previous[SHA256_HEX_LEN + 1];
  char drop[SHA256_HEX_LEN + 1];
};


/** Fire the platform's fault hook at a named step, when a build has one. **/
static void
fault_at(const char *step) {
  if(platform->fault) {
    platform->fault(platform, step);
  }
}


/** Whether text is one lowercase hex SHA-256 and nothing else. **/
static int
hash_text(const char *text) {
  size_t i;

  if(strlen(text) != SHA256_HEX_LEN) {
    return 0;
  }

  for(i=0; i<SHA256_HEX_LEN; i++) {
    if(!((text[i] >= '0' && text[i] <= '9') ||
         (text[i] >= 'a' && text[i] <= 'f'))) {
      return 0;
    }
  }

  return 1;
}


/**
 * Create name below dirfd with text, flushed to disk. A leftover of the same
 * name is removed first. Returns 0, or -1 with nothing left behind.
 **/
static int
tmp_write(int dirfd, const char *name, const char *text, size_t len) {
  int fd;

  unlinkat(dirfd, name, 0);

  if((fd=open_entry(dirfd, name, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
    return -1;
  }

  if(write_all(fd, text, len) || fsync(fd)) {
    close(fd);
    unlinkat(dirfd, name, 0);
    return -1;
  }

  if(close(fd)) {
    unlinkat(dirfd, name, 0);
    return -1;
  }

  return 0;
}


/**
 * Remove the new object and the new current record of a transaction that did
 * not commit, and flush what that changed. Missing files are not an error.
 * The caller holds the lock.
 **/
static void
tmp_discard(int store_fd, const char *name, const char *hash) {
  char tmp_object[SHA256_HEX_LEN + 8];
  char tmp_current[PAYLOAD_NAME_MAX + 8];
  int objects_fd;
  int current_fd;

  snprintf(tmp_object, sizeof(tmp_object), "%s.tmp", hash);
  snprintf(tmp_current, sizeof(tmp_current), "%s.tmp", name);

  if((objects_fd=dir_open(store_fd, "objects")) >= 0) {
    unlinkat(objects_fd, tmp_object, 0);
    fsync(objects_fd);
    close(objects_fd);
  }

  if((current_fd=dir_open(store_fd, "current")) >= 0) {
    unlinkat(current_fd, tmp_current, 0);
    fsync(current_fd);
    close(current_fd);
  }
}


/**
 * Replace the journal with one record: the temporary file is flushed, renamed
 * over the journal and the store directory flushed. The caller holds the lock.
 **/
static int
journal_write(int store_fd, const struct journal *j) {
  char text[256];
  int len;

  len = snprintf(text, sizeof(text), JOURNAL_MARKER "\n%s %s %s %s %s %s\n",
                 j->kind, j->phase, j->name, j->hash, j->previous, j->drop);
  if(len < 0 || len >= (int)sizeof(text)) {
    return -1;
  }

  if(tmp_write(store_fd, JOURNAL_TMP, text, (size_t)len)) {
    return -1;
  }

  if(renameat(store_fd, JOURNAL_TMP, store_fd, JOURNAL_FILE)) {
    unlinkat(store_fd, JOURNAL_TMP, 0);
    return -1;
  }

  return fsync(store_fd);
}


/**
 * Read the journal. Returns 0 with the record, 1 when no change is in
 * progress, or -1 when the journal is not a record Ariel wrote.
 **/
static int
journal_read(int store_fd, struct journal *j) {
  char text[256];
  size_t total = 0;
  int fd;

  if((fd=open_entry(store_fd, JOURNAL_FILE, O_RDONLY)) < 0) {
    return errno == ENOENT ? 1 : -1;
  }

  while(total < sizeof(text) - 1) {
    ssize_t n = read(fd, text + total, sizeof(text) - 1 - total);

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
  text[total] = '\0';

  // A v1 record predates autoload, so it is always a payload change.
  if(!strncmp(text, JOURNAL_MARKER_V1 "\n", strlen(JOURNAL_MARKER_V1) + 1)) {
    if(sscanf(text, JOURNAL_MARKER_V1 "\n%15s %32s %64s %64s %64s", j->phase,
              j->name, j->hash, j->previous, j->drop) != 5) {
      return -1;
    }
    snprintf(j->kind, sizeof(j->kind), "payload");
  } else if(sscanf(text, JOURNAL_MARKER "\n%15s %15s %32s %64s %64s %64s",
                   j->kind, j->phase, j->name, j->hash, j->previous,
                   j->drop) != 6) {
    return -1;
  }

  if((strcmp(j->kind, "payload") && strcmp(j->kind, "autoload")) ||
     (strcmp(j->phase, "prepared") && strcmp(j->phase, "committed")) ||
     !store_name_valid(j->name) || !hash_text(j->hash) ||
     (strcmp(j->previous, "-") && !hash_text(j->previous)) ||
     (strcmp(j->drop, "-") && !hash_text(j->drop))) {
    return -1;
  }

  return 0;
}


/** Remove the journal once its change is finished. The caller holds the lock. **/
static int
journal_clear(int store_fd) {
  if(unlinkat(store_fd, JOURNAL_FILE, 0) && errno != ENOENT) {
    return -1;
  }

  return fsync(store_fd);
}


/**
 * Undo a change that had not committed: remove its new files, record the
 * rollback and clear the journal. The caller holds the lock.
 **/
static int
transaction_rollback_locked(int store_fd, const char *name, const char *hash) {
  tmp_discard(store_fd, name, hash);

  if(audit_append_locked("rollback", name, "-", hash)) {
    return -1;
  }

  return journal_clear(store_fd);
}


/**
 * Finish a committed change: move its new files into place, point the name's
 * record at the new object and drop the build it displaces from the previous
 * slot. Each step is safe to repeat, so a crash in any of them is recovered by
 * running this again. The caller holds the lock.
 **/
static int
transaction_roll_forward_locked(int store_fd, const struct journal *j) {
  char tmp_object[SHA256_HEX_LEN + 8];
  char tmp_current[PAYLOAD_NAME_MAX + 8];
  int objects_fd = -1;
  int current_fd = -1;
  int rc = -1;

  snprintf(tmp_object, sizeof(tmp_object), "%s.tmp", j->hash);
  snprintf(tmp_current, sizeof(tmp_current), "%s.tmp", j->name);

  if((objects_fd=dir_open(store_fd, "objects")) < 0 ||
     (current_fd=dir_open(store_fd, "current")) < 0) {
    goto out;
  }

  // A rename that already happened leaves no temporary file behind.
  if((renameat(objects_fd, tmp_object, objects_fd, j->hash) &&
      errno != ENOENT) ||
     (renameat(current_fd, tmp_current, current_fd, j->name) &&
      errno != ENOENT) ||
     fsync(objects_fd) || fsync(current_fd)) {
    goto out;
  }

  // The name may point only at an object the store holds.
  if(!object_present(objects_fd, j->hash)) {
    audit_append_locked("rollforward_refused", j->name, "-", j->hash);
    goto out;
  }

  fault_at("renamed");

  if(state_record(j->name, j->hash, j->previous)) {
    goto out;
  }

  if(strcmp(j->drop, "-") && unlinkat(objects_fd, j->drop, 0) &&
     errno != ENOENT) {
    goto out;
  }

  if(fsync(objects_fd)) {
    goto out;
  }

  rc = 0;

out:
  if(objects_fd >= 0) {
    close(objects_fd);
  }
  if(current_fd >= 0) {
    close(current_fd);
  }

  return rc;
}


/** The SHA-256 of len bytes of text, as lowercase hex. **/
static void
text_hash(const char *text, size_t len, char hex[SHA256_HEX_LEN + 1]) {
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;

  sha256_init(&hash);
  sha256_update(&hash, text, len);
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
}


/**
 * Read a small file below dirfd into buf, NUL-terminated. Returns its length,
 * or -1 when it is missing, unreadable or longer than size - 1.
 **/
static int
text_read(int dirfd, const char *name, char *buf, size_t size) {
  size_t total = 0;
  char probe;
  int fd;

  if((fd=open_entry(dirfd, name, O_RDONLY)) < 0) {
    return -1;
  }

  while(total < size - 1) {
    ssize_t n = read(fd, buf + total, size - 1 - total);

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

  if(total == size - 1 && read(fd, &probe, 1) != 0) {
    close(fd);
    return -1;
  }

  close(fd);
  buf[total] = '\0';
  return (int)total;
}


/**
 * Write the list's first text, with a journal record, at the moment of the
 * change: prepared, then committed, then the rename that makes the new list
 * the list. A failure before the rename leaves the old list. Returns -1 when
 * the list did not change, 0 when it changed and is audited, and 1 when it
 * changed but its audit line or journal close failed. The caller holds the
 * lock.
 **/
static int
autoload_transaction_locked(int state_fd, int store_fd, const char *text,
                            const char *old_hash, const char *new_hash,
                            const char *kind, const char *name, const char *id) {
  struct journal j;
  int unrecorded;

  memset(&j, 0, sizeof(j));
  snprintf(j.kind, sizeof(j.kind), "autoload");
  snprintf(j.phase, sizeof(j.phase), "prepared");
  snprintf(j.name, sizeof(j.name), "%s", AUTOLOAD_FILE);
  snprintf(j.hash, sizeof(j.hash), "%s", new_hash);
  snprintf(j.previous, sizeof(j.previous), "%s", old_hash);
  snprintf(j.drop, sizeof(j.drop), "-");

  if(tmp_write(state_fd, AUTOLOAD_TMP, text, strlen(text))) {
    return -1;
  }

  if(journal_write(store_fd, &j)) {
    unlinkat(state_fd, AUTOLOAD_TMP, 0);
    return -1;
  }

  fault_at("prepared");

  snprintf(j.phase, sizeof(j.phase), "committed");
  if(journal_write(store_fd, &j)) {
    unlinkat(state_fd, AUTOLOAD_TMP, 0);
    journal_clear(store_fd);
    return -1;
  }

  fault_at("committed");

  if(renameat(state_fd, AUTOLOAD_TMP, state_fd, AUTOLOAD_FILE)) {
    unlinkat(state_fd, AUTOLOAD_TMP, 0);
    journal_clear(store_fd);
    return -1;
  }

  // The list is in place from here on, so the edit stands. An unflushed rename
  // keeps its journal for recovery; a failed audit line or clear is reported.
  if(fsync(state_fd)) {
    return 1;
  }

  unrecorded = audit_append_locked(kind, name, id, new_hash) != 0;
  if(journal_clear(store_fd)) {
    unrecorded = 1;
  }
  return unrecorded;
}


/**
 * Finish an autoload change the journal names: a prepared one is dropped, a
 * committed one is put in place, and each is audited. The caller holds the
 * lock.
 **/
static int
autoload_recover_locked(int state_fd, int store_fd, const struct journal *j) {
  char text[AUTOLOAD_TEXT_MAX];
  char hex[SHA256_HEX_LEN + 1];
  int len;

  if(!strcmp(j->phase, "prepared")) {
    unlinkat(state_fd, AUTOLOAD_TMP, 0);
    if(fsync(state_fd) ||
       audit_append_locked("rollback", AUTOLOAD_FILE, "-", j->hash)) {
      return -1;
    }
    return journal_clear(store_fd);
  }

  len = text_read(state_fd, AUTOLOAD_TMP, text, sizeof(text));
  if(len >= 0) {
    text_hash(text, (size_t)len, hex);
    if(strcmp(hex, j->hash) || renameat(state_fd, AUTOLOAD_TMP, state_fd,
                                        AUTOLOAD_FILE) ||
       fsync(state_fd)) {
      return -1;
    }
  } else {
    len = text_read(state_fd, AUTOLOAD_FILE, text, sizeof(text));
    if(len < 0) {
      return -1;
    }
    text_hash(text, (size_t)len, hex);
    if(strcmp(hex, j->hash)) {
      audit_append_locked("rollforward_refused", AUTOLOAD_FILE, "-", j->hash);
      return -1;
    }
  }

  if(audit_append_locked("rollforward", AUTOLOAD_FILE, "-", j->hash)) {
    return -1;
  }
  return journal_clear(store_fd);
}


/**
 * Finish the change the journal names, if one is in progress: roll back a
 * prepared change, roll forward a committed one, and audit which. Running it
 * again after it finished finds no journal and does nothing. The caller holds
 * the lock.
 **/
static int
transaction_recover_locked(int state_fd, int store_fd) {
  struct journal j;
  int rc;

  rc = journal_read(store_fd, &j);
  if(rc == 1) {
    return 0;
  }
  if(rc) {
    return -1;
  }

  if(!strcmp(j.kind, "autoload")) {
    return autoload_recover_locked(state_fd, store_fd, &j);
  }

  if(!strcmp(j.phase, "prepared")) {
    return transaction_rollback_locked(store_fd, j.name, j.hash);
  }

  if(transaction_roll_forward_locked(store_fd, &j) ||
     audit_append_locked("rollforward", j.name, "-", j.hash)) {
    return -1;
  }

  return journal_clear(store_fd);
}


/**
 * Recover at start, under the lock: the state record is loaded first, so a
 * roll forward can record the commit in it.
 **/
static int
recover_at_start(int state_fd) {
  int store_fd;
  int rc = -1;

  pthread_mutex_lock(&lock);
  if((store_fd=dir_open(state_fd, "store")) >= 0) {
    rc = transaction_recover_locked(state_fd, store_fd);
    close(store_fd);
  }
  pthread_mutex_unlock(&lock);

  return rc;
}


/**
 * Copy the staging object into a temporary object, hashing the bytes as
 * they pass, so the object that enters the store is exactly the bytes the
 * hash covers. buf holds MOVE_CHUNK bytes. Returns 0 on success.
 **/
static int
object_copy_into(int src, int dst, uint64_t *total,
                 char hex[SHA256_HEX_LEN + 1], unsigned char *buf) {
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;

  sha256_init(&hash);
  *total = 0;

  while(1) {
    ssize_t n = read(src, buf, MOVE_CHUNK);

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
 * object_copy_into with its chunk on the heap: commits run on a connection
 * thread, whose stack is too small for a MOVE_CHUNK frame.
 **/
static int
object_copy(int src, int dst, uint64_t *total, char hex[SHA256_HEX_LEN + 1]) {
  unsigned char *buf;
  int rc;

  if(!(buf=malloc(MOVE_CHUNK))) {
    return -1;
  }
  rc = object_copy_into(src, dst, total, hex, buf);
  free(buf);

  return rc;
}


/**
 * Drop a staged entry. The approval is marked consumed rather than
 * forgotten: the action it allowed has happened, and a later question must
 * still be able to say so. The caller holds the lock.
 **/
static void
staged_consume(struct staged *entry, struct approval *request) {
  staged_leave(entry);

  if(request) {
    request->consumed = 1;
  }
}


/**
 * The approval is granted: hash the staging object again, then change the
 * store through the journal. The new files are written beside the old ones and
 * flushed, and the journal marks the change prepared. It is marked committed
 * before anything is renamed, so a crash from then on rolls forward. The state
 * record takes the new hash, with the build it replaces as previous. The caller
 * holds the lock.
 **/
static int
staged_install(struct staged *entry, struct approval *request,
               store_install_t *install) {
  struct journal j;
  char tmp_object[SHA256_HEX_LEN + 8];
  char tmp_current[PAYLOAD_NAME_MAX + 8];
  char current_text[SHA256_HEX_LEN + 2];
  char hash[SHA256_HEX_LEN + 1];
  char old[SHA256_HEX_LEN + 1];
  char previous[SHA256_HEX_LEN + 1];
  uint64_t total = 0;
  int state_fd = -1;
  int staging_fd = -1;
  int store_fd = -1;
  int objects_fd = -1;
  int current_fd = -1;
  int src = -1;
  int dst = -1;
  int rc = STORE_APPROVAL_STALE;

  if((state_fd=root_open()) < 0) {
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

  // A change an earlier step left in the journal finishes before this one.
  if(transaction_recover_locked(state_fd, store_fd)) {
    goto out;
  }

  tmp_discard(store_fd, entry->facts.name, entry->facts.sha256);

  snprintf(tmp_object, sizeof(tmp_object), "%s.tmp", entry->facts.sha256);
  snprintf(tmp_current, sizeof(tmp_current), "%s.tmp", entry->facts.name);

  if((dst=open_entry(objects_fd, tmp_object, O_WRONLY | O_CREAT | O_EXCL)) < 0) {
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

  snprintf(current_text, sizeof(current_text), "%s\n", entry->facts.sha256);
  if(tmp_write(current_fd, tmp_current, current_text, SHA256_HEX_LEN + 1)) {
    goto out_temp;
  }

  if(current_read(current_fd, entry->facts.name, old)) {
    snprintf(old, sizeof(old), "-");
  }
  if(state_previous(entry->facts.name, previous, sizeof(previous))) {
    goto out_temp;
  }

  memset(&j, 0, sizeof(j));
  snprintf(j.kind, sizeof(j.kind), "payload");
  snprintf(j.name, sizeof(j.name), "%s", entry->facts.name);
  snprintf(j.hash, sizeof(j.hash), "%s", entry->facts.sha256);

  // The build the record names now becomes previous, unless this commit
  // repeats it; the build previous named before is dropped once replaced,
  // unless another name still holds it.
  if(strcmp(old, "-") && strcmp(old, j.hash)) {
    snprintf(j.previous, sizeof(j.previous), "%s", old);
  } else {
    snprintf(j.previous, sizeof(j.previous), "%s", previous);
  }
  if(strcmp(previous, "-") && strcmp(previous, j.previous) &&
     strcmp(previous, j.hash) && !state_referenced(previous, j.name)) {
    snprintf(j.drop, sizeof(j.drop), "%s", previous);
  } else {
    snprintf(j.drop, sizeof(j.drop), "-");
  }

  snprintf(j.phase, sizeof(j.phase), "prepared");
  if(journal_write(store_fd, &j)) {
    goto out_rollback;
  }
  fault_at("prepared");

  // A failed committed mark may still have reached the disk, so nothing is
  // rolled back here. The journal names what the next start must finish.
  snprintf(j.phase, sizeof(j.phase), "committed");
  if(journal_write(store_fd, &j)) {
    goto out;
  }
  fault_at("committed");

  // On failure the journal stays committed, and the next start or commit
  // finishes the change.
  if(transaction_roll_forward_locked(store_fd, &j)) {
    goto out;
  }

  // A journal that survives this is finished later, and finishing it again is safe.
  journal_clear(store_fd);

  snprintf(install->name, sizeof(install->name), "%s", entry->facts.name);
  snprintf(install->sha256, sizeof(install->sha256), "%s", entry->facts.sha256);
  object_path(entry->facts.sha256, install->path, sizeof(install->path));
  staged_consume(entry, request);

  rc = STORE_INSTALLED;
  goto out;

out_rollback:
  transaction_rollback_locked(store_fd, entry->facts.name, entry->facts.sha256);
  goto out;

out_temp:
  if(dst >= 0) {
    close(dst);
  }
  tmp_discard(store_fd, entry->facts.name, entry->facts.sha256);
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
  } else if(request->consumed) {
    // The action this approval allowed already ran.
    outcome = STORE_APPROVAL_STALE;
  } else if(request->expired) {
    // The owner's window closed: the object leaves the console and the
    // agent pushes the build again. The approval stays, so a later question
    // can still say it expired.
    staged_leave(entry);
    outcome = STORE_APPROVAL_EXPIRED;
  } else if(!request->decided) {
    snprintf(approval_id, idlen, "%s", request->id);
    outcome = STORE_APPROVAL_REQUIRED;
  } else if(!request->approved) {
    // A denial is terminal: the bytes leave the console for good. The
    // approval stays, answered as decided and not approved.
    staged_leave(entry);
    outcome = STORE_APPROVAL_DENIED;
  } else {
    outcome = staged_install(entry, request, install);
  }

  pthread_mutex_unlock(&lock);
  return outcome;
}


int
store_rollback_target(const char *name, approval_facts_t *facts) {
  char current[SHA256_HEX_LEN + 1];
  char previous[SHA256_HEX_LEN + 1];
  int state_fd = -1;
  int store_fd = -1;
  int current_fd = -1;
  int rc = STORE_ROLLBACK_ERROR;

  if((state_fd=root_open()) < 0 ||
     (store_fd=dir_open(state_fd, "store")) < 0 ||
     (current_fd=dir_open(store_fd, "current")) < 0) {
    goto out;
  }

  errno = 0;
  if(current_read(current_fd, name, current)) {
    rc = errno == ENOENT ? STORE_ROLLBACK_UNKNOWN : STORE_ROLLBACK_ERROR;
    goto out;
  }

  if(state_previous(name, previous, sizeof(previous))) {
    goto out;
  }

  if(!strcmp(previous, "-")) {
    rc = STORE_ROLLBACK_NO_PREVIOUS;
    goto out;
  }

  memset(facts, 0, sizeof(*facts));
  snprintf(facts->command, sizeof(facts->command), "%s", "payload.rollback");
  snprintf(facts->name, sizeof(facts->name), "%s", name);
  snprintf(facts->sha256, sizeof(facts->sha256), "%s", previous);
  snprintf(facts->replaces, sizeof(facts->replaces), "%s", current);
  rc = STORE_ROLLBACK_OK;

out:
  if(current_fd >= 0) {
    close(current_fd);
  }
  if(store_fd >= 0) {
    close(store_fd);
  }
  if(state_fd >= 0) {
    close(state_fd);
  }
  return rc;
}


/** The newest rollback approval of name that is neither spent nor released. **/
static struct approval *
rollback_open_find(const char *name) {
  struct approval *newest = NULL;
  int i;

  for(i=0; i<APPROVALS_MAX; i++) {
    struct approval *request = &approvals[i];

    if(request->used && !request->consumed && !request->released &&
       !strcmp(request->facts.command, "payload.rollback") &&
       !strcmp(request->facts.name, name) &&
       (!newest || request->created_ms > newest->created_ms)) {
      newest = request;
    }
  }
  return newest;
}


/** Make the list with Ariel alone when no list exists yet. **/
static int
autoload_make(int state_fd) {
  int fd;

  if((fd=open_entry(state_fd, AUTOLOAD_FILE, O_RDONLY)) >= 0) {
    close(fd);
    return 0;
  }
  if(errno != ENOENT) {
    return -1;
  }

  if(tmp_write(state_fd, AUTOLOAD_TMP, AUTOLOAD_DEFAULT,
               strlen(AUTOLOAD_DEFAULT)) ||
     renameat(state_fd, AUTOLOAD_TMP, state_fd, AUTOLOAD_FILE) ||
     fsync(state_fd)) {
    unlinkat(state_fd, AUTOLOAD_TMP, 0);
    return -1;
  }

  return 0;
}


int
store_autoload_show(char *buf, size_t size) {
  int state_fd;
  int len;

  pthread_mutex_lock(&lock);
  state_fd = root_open();
  len = state_fd < 0 ? -1 : text_read(state_fd, AUTOLOAD_FILE, buf, size);
  if(state_fd >= 0) {
    close(state_fd);
  }
  pthread_mutex_unlock(&lock);

  return len;
}


/**
 * The owner approved a rollback: check that the store still holds the facts
 * approved, then change it through the journal, as an install does. The build
 * restored becomes current and the one it replaces becomes previous; nothing
 * is dropped. A rollback whose facts moved on is stale, and its approval is
 * spent. The caller holds the lock.
 **/
static int
rollback_apply_locked(struct approval *request, store_install_t *install) {
  const char *name = request->facts.name;
  approval_facts_t live;
  struct journal j;
  char current_text[SHA256_HEX_LEN + 2];
  char tmp_current[PAYLOAD_NAME_MAX + 8];
  int state_fd = -1;
  int store_fd = -1;
  int objects_fd = -1;
  int current_fd = -1;
  int target;
  int rc = STORE_ROLLBACK_FAILED;

  if((state_fd=root_open()) < 0 ||
     (store_fd=dir_open(state_fd, "store")) < 0 ||
     (objects_fd=dir_open(store_fd, "objects")) < 0 ||
     (current_fd=dir_open(store_fd, "current")) < 0) {
    goto out;
  }

  // A change an earlier step left in the journal finishes before this one.
  if(transaction_recover_locked(state_fd, store_fd)) {
    goto out;
  }

  // An unreadable store is not a changed one: the grant stays for a retry.
  target = store_rollback_target(name, &live);
  if(target == STORE_ROLLBACK_ERROR) {
    goto out;
  }

  if(target != STORE_ROLLBACK_OK ||
     strcmp(live.sha256, request->facts.sha256) ||
     strcmp(live.replaces, request->facts.replaces) ||
     !object_present(objects_fd, live.sha256)) {
    request->consumed = 1;
    request->released = 1;
    rc = STORE_APPROVAL_STALE;
    goto out;
  }

  snprintf(current_text, sizeof(current_text), "%s\n", live.sha256);
  snprintf(tmp_current, sizeof(tmp_current), "%s.tmp", name);
  if(tmp_write(current_fd, tmp_current, current_text, SHA256_HEX_LEN + 1)) {
    goto out;
  }

  memset(&j, 0, sizeof(j));
  snprintf(j.kind, sizeof(j.kind), "payload");
  snprintf(j.name, sizeof(j.name), "%s", name);
  snprintf(j.hash, sizeof(j.hash), "%s", live.sha256);
  snprintf(j.previous, sizeof(j.previous), "%s", live.replaces);
  snprintf(j.drop, sizeof(j.drop), "-");

  snprintf(j.phase, sizeof(j.phase), "prepared");
  if(journal_write(store_fd, &j)) {
    transaction_rollback_locked(store_fd, name, live.sha256);
    goto out;
  }
  fault_at("prepared");

  snprintf(j.phase, sizeof(j.phase), "committed");
  if(journal_write(store_fd, &j)) {
    goto out;
  }
  fault_at("committed");

  if(transaction_roll_forward_locked(store_fd, &j)) {
    goto out;
  }

  journal_clear(store_fd);

  snprintf(install->name, sizeof(install->name), "%s", name);
  snprintf(install->sha256, sizeof(install->sha256), "%s", live.sha256);
  object_path(live.sha256, install->path, sizeof(install->path));
  request->consumed = 1;
  request->released = 1;

  rc = STORE_INSTALLED;

out:
  if(current_fd >= 0) {
    close(current_fd);
  }
  if(objects_fd >= 0) {
    close(objects_fd);
  }
  if(store_fd >= 0) {
    close(store_fd);
  }
  if(state_fd >= 0) {
    close(state_fd);
  }
  return rc;
}


/**
 * Apply an approved autoload edit, under the lock, against the list as it is
 * now: an approval whose list has changed since it was asked is stale. The
 * caller holds the lock.
 **/
static int
autoload_apply_locked(struct approval *request) {
  char text[AUTOLOAD_TEXT_MAX];
  char next[AUTOLOAD_TEXT_MAX];
  char hex[SHA256_HEX_LEN + 1];
  char next_hex[SHA256_HEX_LEN + 1];
  int state_fd;
  int store_fd;
  int len;
  int applied;
  const char *kind;
  int add = !strcmp(request->facts.command, "autoload.add");
  int outcome = STORE_AUTOLOAD_FAILED;

  if((state_fd=root_open()) < 0) {
    return STORE_AUTOLOAD_FAILED;
  }
  if((store_fd=dir_open(state_fd, "store")) < 0) {
    close(state_fd);
    return STORE_AUTOLOAD_FAILED;
  }

  len = text_read(state_fd, AUTOLOAD_FILE, text, sizeof(text));
  if(len >= 0) {
    text_hash(text, (size_t)len, hex);

    if(strcmp(hex, request->facts.sha256) ||
       autoload_edit(text, add, request->facts.name, next, sizeof(next)) !=
         AUTOLOAD_OK) {
      outcome = STORE_AUTOLOAD_STALE;
    } else {
      text_hash(next, strlen(next), next_hex);
      kind = add ? "autoload_add" : "autoload_remove";
      applied = autoload_transaction_locked(state_fd, store_fd, next, hex,
                                            next_hex, kind,
                                            request->facts.name, request->id);
      if(applied >= 0) {
        request->consumed = 1;
        request->released = 1;
        outcome = applied ? STORE_AUTOLOAD_UNRECORDED : STORE_AUTOLOAD_APPLIED;
      }
    }
  }

  close(store_fd);
  close(state_fd);
  return outcome;
}


int
store_rollback(const char *name, char *approval_id, size_t idlen,
               store_install_t *install) {
  struct approval *request;
  int outcome;

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());
  request = rollback_open_find(name);

  if(!request) {
    outcome = STORE_APPROVAL_NEW;
  } else {
    snprintf(approval_id, idlen, "%s", request->id);

    if(!request->decided) {
      outcome = STORE_APPROVAL_REQUIRED;
    } else if(!request->approved) {
      request->released = 1;
      outcome = STORE_APPROVAL_DENIED;
    } else {
      outcome = rollback_apply_locked(request, install);
    }
  }

  pthread_mutex_unlock(&lock);
  return outcome;
}


int
store_autoload_apply(const char *id, const char *command, const char *name,
                     approval_challenge_t *challenge) {
  struct approval *request;
  int outcome;

  pthread_mutex_lock(&lock);
  expire_locked(now_ms());
  request = approval_find(id);

  if(!request) {
    outcome = STORE_AUTOLOAD_UNKNOWN;
  } else if(request->consumed) {
    outcome = STORE_AUTOLOAD_STALE;
  } else if(request->expired) {
    outcome = STORE_AUTOLOAD_EXPIRED;
  } else if(!request->decided) {
    *challenge = request->challenge;
    outcome = STORE_AUTOLOAD_PENDING;
  } else if(!request->approved) {
    outcome = STORE_AUTOLOAD_DENIED;
  } else if(strcmp(request->facts.command, command) ||
            strcmp(request->facts.name, name)) {
    outcome = STORE_AUTOLOAD_STALE;
  } else {
    outcome = autoload_apply_locked(request);
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

  if((state_fd=root_open()) < 0 ||
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

  snprintf(object->sha256, sizeof(object->sha256), "%s", computed);
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


/** The file in the logs directory that holds one payload's output. **/
#define LOGS_DIR "logs"

int
store_log_open(const char *name, int create) {
  char file[PAYLOAD_NAME_MAX + 8];
  int state_fd;
  int logs_fd = -1;
  int fd = -1;

  if(snprintf(file, sizeof(file), "%s.log", name) >= (int)sizeof(file)) {
    return -1;
  }

  if((state_fd=root_open()) < 0) {
    return -1;
  }

  if(create && dir_make(state_fd, LOGS_DIR)) {
    goto out;
  }

  if((logs_fd=dir_open(state_fd, LOGS_DIR)) < 0) {
    goto out;
  }

  if(create) {
    fd = open_entry(logs_fd, file, O_WRONLY | O_CREAT | O_TRUNC);
  } else {
    fd = open_entry(logs_fd, file, O_RDONLY);
  }

out:
  if(logs_fd >= 0) {
    close(logs_fd);
  }
  close(state_fd);
  return fd;
}


int
store_list(state_payload_t *entries, size_t max, size_t *count) {
  return state_list(entries, max, count);
}


/**
 * Append one action to the audit log. The line is flushed before it returns,
 * so a crash cannot lose an action that already happened.
 **/
static int
audit_append_locked(const char *kind, const char *name, const char *id,
                    const char *sha256) {
  char line[AUDIT_LINE_MAX];
  int len;
  int fd;
  int state_fd;
  int rc;

  len = snprintf(line, sizeof(line), "%llu %s %s %s %s\n",
                 (unsigned long long)now_ms(), kind, name, id, sha256);
  if(len < 0 || len >= (int)sizeof(line)) {
    return -1;
  }

  if((state_fd=root_open()) < 0) {
    return -1;
  }
  fd = open_entry(state_fd, AUDIT_FILE, O_WRONLY | O_CREAT | O_APPEND);
  close(state_fd);
  if(fd < 0) {
    return -1;
  }

  rc = write_all(fd, line, (size_t)len) || fsync(fd) ? -1 : 0;
  if(close(fd)) {
    rc = -1;
  }

  return rc;
}


int
store_audit_append(const char *kind, const char *name, const char *id,
                   const char *sha256) {
  int rc;

  pthread_mutex_lock(&lock);
  rc = audit_append_locked(kind, name, id, sha256);
  pthread_mutex_unlock(&lock);

  return rc;
}


/**
 * Read the log's complete lines into the newest window of kept, and copy the
 * window into buf. The caller holds the lock: the window is static, and no
 * append can land half-written in the middle of the read.
 **/
static int
audit_tail_locked(unsigned long n, char *buf, size_t size) {
  static char kept[AUDIT_TAIL_MAX][AUDIT_LINE_MAX];
  char line[AUDIT_LINE_MAX];
  unsigned long count = 0;
  unsigned long start;
  unsigned long i;
  size_t used = 0;
  FILE *file;
  int state_fd;
  int fd;

  if((state_fd=root_open()) < 0) {
    return -1;
  }

  fd = open_entry(state_fd, AUDIT_FILE, O_RDONLY);
  close(state_fd);

  // A log that does not exist yet has no events.
  if(fd < 0) {
    if(size > 0) {
      buf[0] = '\0';
    }
    return 0;
  }

  if(!(file=fdopen(fd, "r"))) {
    close(fd);
    return -1;
  }

  if(n == 0 || n > AUDIT_TAIL_MAX) {
    n = AUDIT_TAIL_MAX;
  }

  while(fgets(line, sizeof(line), file)) {
    size_t len = strlen(line);
    int c;

    if(len == 0 || line[len - 1] != '\n') {
      // A line longer than the buffer: drop its rest, up to the newline.
      while((c=fgetc(file)) != '\n' && c != EOF) {
      }
      continue;
    }
    snprintf(kept[count % AUDIT_TAIL_MAX], AUDIT_LINE_MAX, "%s", line);
    count++;
  }

  fclose(file);

  if(count > n) {
    start = count - n;
  } else {
    start = 0;
  }

  for(i=start; i<count; i++) {
    const char *text = kept[i % AUDIT_TAIL_MAX];
    size_t len = strlen(text);

    if(used + len >= size) {
      return -1;
    }
    memcpy(buf + used, text, len);
    used += len;
  }

  if(used < size) {
    buf[used] = '\0';
  }
  return (int)used;
}


int
store_audit_tail(unsigned long n, char *buf, size_t size) {
  int rc;

  pthread_mutex_lock(&lock);
  rc = audit_tail_locked(n, buf, size);
  pthread_mutex_unlock(&lock);

  return rc;
}
