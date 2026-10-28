/* Ariel: the named record of the console's state.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <mntent.h>
#else
#include <sys/mount.h>
#include <sys/sysctl.h>
#endif

#include "answer.h"
#include "runs.h"
#include "trace.h"

/** The most records kept at once; the oldest is dropped first. **/
#define TRACE_RECORDS 8

/** The longest name a record takes. **/
#define TRACE_NAME_MAX 32

/** The most escaped bytes a name shows; a longer one is cut and ends in '~'. **/
#define TRACE_TEXT_MAX 64

/** The entries each section shows before it is cut. **/
#define TRACE_SHOW_MOUNTS 8
#define TRACE_SHOW_TITLES 32
#define TRACE_SHOW_METADATA 32
#define TRACE_SHOW_LICENCES 32
#define TRACE_SHOW_PAYLOADS 8

/** The directories a title's size walks down before it gives up. **/
#define TRACE_DEPTH 8

/** The digits that open a record's file name: its sequence number. **/
#define TRACE_SEQ_DIGITS 8

struct names {
  char **item;
  size_t count;
  size_t cap;
};

struct entry {
  unsigned long long seq;
  char file[NAME_MAX + 1];
  char name[TRACE_NAME_MAX + 1];
};

struct entries {
  struct entry *item;
  size_t count;
  size_t cap;
};

struct record {
  char *text;
  size_t len;
  int full;
};

struct going {
  size_t total;
  char names[RUNS_MAX][PAYLOAD_NAME_MAX + 1];
};

struct mounts {
  size_t total;
  char target[TRACE_SHOW_MOUNTS][TRACE_TEXT_MAX + 1];
  char source[TRACE_SHOW_MOUNTS][TRACE_TEXT_MAX + 1];
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char state_dir[PATH_MAX];
static char trace_dir[PATH_MAX];


void
trace_init(const char *dir) {
  snprintf(state_dir, sizeof(state_dir), "%s", dir);
  snprintf(trace_dir, sizeof(trace_dir), "%s/trace", dir);
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


static void
reply(int fd, const char *word, int status) {
  char line[64];

  snprintf(line, sizeof(line), "%s\nexit %d\n", word, status);
  (void)write_all(fd, line, strlen(line));
}


static int
valid_name(const char *name) {
  size_t i;
  size_t len = strlen(name);

  if(len == 0 || len > TRACE_NAME_MAX) {
    return 0;
  }
  for(i=0; i<len; i++) {
    unsigned char c = (unsigned char)name[i];

    if(c < 0x21 || c > 0x7e || c == '/') {
      return 0;
    }
  }
  return 1;
}


static void
add_line(struct record *record, const char *format, ...) {
  va_list args;
  size_t room = CONTENT_CAP - record->len;
  int n;

  if(record->full) {
    return;
  }
  va_start(args, format);
  n = vsnprintf(record->text + record->len, room, format, args);
  va_end(args);
  if(n < 0 || (size_t)n + 2 > room) {
    record->full = 1;
    return;
  }
  record->len += (size_t)n;
  record->text[record->len++] = '\n';
  record->text[record->len] = '\0';
}


/* Bytes outside letters, digits, '.', '_' and '-' are %XX; a cut name ends in '~'. */
static size_t
escaped_width(unsigned char c) {
  return isalnum(c) || c == '.' || c == '_' || c == '-' ? 1 : 3;
}


static void
escape(char *out, const char *in) {
  const unsigned char *p = (const unsigned char *)in;
  size_t total = 0;
  size_t limit = TRACE_TEXT_MAX;
  size_t len = 0;
  size_t i;

  for(i=0; p[i]; i++) {
    total += escaped_width(p[i]);
  }
  if(total > TRACE_TEXT_MAX) {
    limit = TRACE_TEXT_MAX - 1;
  }
  for(i=0; p[i] && len + escaped_width(p[i]) <= limit; i++) {
    if(escaped_width(p[i]) == 1) {
      out[len++] = (char)p[i];
    } else {
      snprintf(out + len, 4, "%%%02X", p[i]);
      len += 3;
    }
  }
  if(p[i]) {
    out[len++] = '~';
  }
  out[len] = '\0';
}


static void
cut(struct record *record, size_t shown, size_t total) {
  if(total > shown) {
    add_line(record, "truncated %zu of %zu", shown, total);
  }
}


static int
join(char *out, size_t size, const char *base, const char *rel) {
  return snprintf(out, size, "%s/%s", base, rel) < (int)size ? 0 : -1;
}


static int
names_add(struct names *list, const char *name) {
  char **grown;
  char *copy;

  if(list->count == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 64;

    grown = realloc(list->item, cap * sizeof(*grown));
    if(!grown) {
      return -1;
    }
    list->item = grown;
    list->cap = cap;
  }
  copy = strdup(name);
  if(!copy) {
    return -1;
  }
  list->item[list->count++] = copy;
  return 0;
}


static void
names_free(struct names *list) {
  size_t i;

  for(i=0; i<list->count; i++) {
    free(list->item[i]);
  }
  free(list->item);
  memset(list, 0, sizeof(*list));
}


static int
names_cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}


/* The entries of path, sorted by name. A missing directory has none; with
   dirs set, only directories are listed. */
static int
list_names(const char *path, int dirs, struct names *list) {
  DIR *dir;
  struct dirent *ent;
  struct stat st;
  char child[PATH_MAX];

  memset(list, 0, sizeof(*list));
  dir = opendir(path);
  if(!dir) {
    return errno == ENOENT ? 0 : -1;
  }
  while((ent = readdir(dir))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(dirs) {
      if(join(child, sizeof(child), path, ent->d_name) ||
         lstat(child, &st) || !S_ISDIR(st.st_mode)) {
        continue;
      }
    }
    if(names_add(list, ent->d_name)) {
      closedir(dir);
      names_free(list);
      return -1;
    }
  }
  closedir(dir);
  qsort(list->item, list->count, sizeof(*list->item), names_cmp);
  return 0;
}


/* The bytes under path, symbolic links not followed. A tree deeper than
   TRACE_DEPTH is an error, not a partial sum. */
static long long
tree_bytes(const char *path, int depth) {
  struct stat st;
  DIR *dir;
  struct dirent *ent;
  char child[PATH_MAX];
  long long total = 0;

  if(depth > TRACE_DEPTH || lstat(path, &st)) {
    return -1;
  }
  if(S_ISREG(st.st_mode)) {
    return (long long)st.st_size;
  }
  if(!S_ISDIR(st.st_mode)) {
    return 0;
  }
  dir = opendir(path);
  if(!dir) {
    return -1;
  }
  while((ent = readdir(dir))) {
    long long bytes;

    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(join(child, sizeof(child), path, ent->d_name)) {
      closedir(dir);
      return -1;
    }
    bytes = tree_bytes(child, depth + 1);
    if(bytes < 0) {
      closedir(dir);
      return -1;
    }
    total += bytes;
  }
  closedir(dir);
  return total;
}


static int
boot_time(time_t *boot) {
#if defined(__linux__)
  char line[256];
  unsigned long long secs = 0;
  FILE *file = fopen("/proc/stat", "r");
  int found = 0;

  if(!file) {
    return -1;
  }
  while(!found && fgets(line, sizeof(line), file)) {
    found = sscanf(line, "btime %llu", &secs) == 1;
  }
  fclose(file);
  if(!found) {
    return -1;
  }
  *boot = (time_t)secs;
  return 0;
#else
  struct timeval tv;
  size_t size = sizeof(tv);

  if(sysctlbyname("kern.boottime", &tv, &size, NULL, 0)) {
    return -1;
  }
  *boot = tv.tv_sec;
  return 0;
#endif
}


static void
visit_mount(void *ctx, const char *target, const char *source) {
  struct mounts *mounts = ctx;

  if(mounts->total < TRACE_SHOW_MOUNTS) {
    escape(mounts->target[mounts->total], target);
    escape(mounts->source[mounts->total], source);
  }
  mounts->total++;
}


static int
visit_mounts(void (*visit)(void *, const char *, const char *), void *ctx) {
#if defined(__linux__)
  struct mntent *ent;
  FILE *file = setmntent("/proc/self/mounts", "r");

  if(!file) {
    return -1;
  }
  while((ent = getmntent(file))) {
    visit(ctx, ent->mnt_dir, ent->mnt_fsname);
  }
  endmntent(file);
  return 0;
#else
  struct statfs *mounts;
  int count = getmntinfo(&mounts, MNT_NOWAIT);
  int i;

  if(count < 0) {
    return -1;
  }
  for(i=0; i<count; i++) {
    visit(ctx, mounts[i].f_mntonname, mounts[i].f_mntfromname);
  }
  return 0;
#endif
}


static void
visit_going(void *ctx, const char *name) {
  struct going *going = ctx;

  if(going->total < RUNS_MAX) {
    snprintf(going->names[going->total], sizeof(going->names[0]), "%s", name);
    going->total++;
  }
}


static int
going_cmp(const void *a, const void *b) {
  return strcmp((const char *)a, (const char *)b);
}


static int
fill_record(platform_t *platform, struct record *record) {
  char apps[PATH_MAX];
  char path[PATH_MAX];
  char esc[TRACE_TEXT_MAX + 1];
  struct names list;
  struct statvfs vfs;
  struct mounts mounts;
  struct going going;
  time_t now = time(NULL);
  time_t boot;
  size_t i;
  size_t shown;

  if(boot_time(&boot) || statvfs(state_dir, &vfs)) {
    return -1;
  }

  add_line(record, "clock %lld", (long long)now);
  add_line(record, "uptime %lld", (long long)(now > boot ? now - boot : 0));
  add_line(record, "boot %lld", (long long)boot);
  add_line(record, "space %llu %llu",
           (unsigned long long)vfs.f_bavail * vfs.f_frsize,
           (unsigned long long)vfs.f_blocks * vfs.f_frsize);

  memset(&mounts, 0, sizeof(mounts));
  if(visit_mounts(visit_mount, &mounts)) {
    return -1;
  }
  add_line(record, "mounts %zu", mounts.total);
  shown = mounts.total < TRACE_SHOW_MOUNTS ? mounts.total : TRACE_SHOW_MOUNTS;
  for(i=0; i<shown; i++) {
    add_line(record, "mount %s %s", mounts.target[i], mounts.source[i]);
  }
  cut(record, shown, mounts.total);

  if(join(apps, sizeof(apps), platform->fs_root, "user/app") ||
     list_names(apps, 1, &list)) {
    return -1;
  }
  add_line(record, "titles %zu", list.count);
  shown = list.count < TRACE_SHOW_TITLES ? list.count : TRACE_SHOW_TITLES;
  for(i=0; i<shown; i++) {
    long long bytes = -1;

    if(!join(path, sizeof(path), apps, list.item[i])) {
      bytes = tree_bytes(path, 0);
    }
    escape(esc, list.item[i]);
    if(bytes < 0) {
      add_line(record, "title %s -", esc);
    } else {
      add_line(record, "title %s %lld", esc, bytes);
    }
  }
  cut(record, shown, list.count);
  names_free(&list);

  if(join(path, sizeof(path), platform->fs_root, "user/appmeta") ||
     list_names(path, 0, &list)) {
    return -1;
  }
  add_line(record, "metadata %zu", list.count);
  shown = list.count < TRACE_SHOW_METADATA ? list.count : TRACE_SHOW_METADATA;
  for(i=0; i<shown; i++) {
    escape(esc, list.item[i]);
    add_line(record, "meta %s", esc);
  }
  cut(record, shown, list.count);
  names_free(&list);

  if(join(path, sizeof(path), platform->fs_root, "user/license") ||
     list_names(path, 0, &list)) {
    return -1;
  }
  add_line(record, "licences %zu", list.count);
  shown = list.count < TRACE_SHOW_LICENCES ? list.count : TRACE_SHOW_LICENCES;
  for(i=0; i<shown; i++) {
    escape(esc, list.item[i]);
    add_line(record, "licence %s", esc);
  }
  cut(record, shown, list.count);
  names_free(&list);

  memset(&going, 0, sizeof(going));
  runs_visit_going(visit_going, &going);
  qsort(going.names, going.total, sizeof(going.names[0]), going_cmp);
  shown = going.total < TRACE_SHOW_PAYLOADS ? going.total : TRACE_SHOW_PAYLOADS;
  add_line(record, "payloads %zu", going.total);
  for(i=0; i<shown; i++) {
    escape(esc, going.names[i]);
    add_line(record, "payload %s", esc);
  }
  cut(record, shown, going.total);

  return record->full ? -1 : 0;
}


/* The record file name: the sequence number, '_', then the name. */
static const char *
record_name(const char *file, unsigned long long *seq) {
  unsigned long long n = 0;
  size_t i;

  for(i=0; i<TRACE_SEQ_DIGITS; i++) {
    if(!isdigit((unsigned char)file[i])) {
      return NULL;
    }
    n = n * 10 + (unsigned long long)(file[i] - '0');
  }
  if(file[TRACE_SEQ_DIGITS] != '_' || !file[TRACE_SEQ_DIGITS + 1]) {
    return NULL;
  }
  *seq = n;
  return file + TRACE_SEQ_DIGITS + 1;
}


static int
seq_cmp(const void *a, const void *b) {
  const struct entry *x = a;
  const struct entry *y = b;

  return x->seq < y->seq ? -1 : x->seq > y->seq;
}


/* The records in the trace directory, oldest first. A missing directory has
   none. Files that are not records are left alone. */
static int
scan(struct entries *list) {
  DIR *dir;
  struct dirent *ent;

  list->count = 0;
  dir = opendir(trace_dir);
  if(!dir) {
    return errno == ENOENT ? 0 : -1;
  }
  while((ent = readdir(dir))) {
    unsigned long long seq;
    const char *name = record_name(ent->d_name, &seq);
    struct entry *e;

    if(!name || strlen(name) > TRACE_NAME_MAX) {
      continue;
    }
    if(list->count == list->cap) {
      size_t cap = list->cap ? list->cap * 2 : 16;
      struct entry *grown = realloc(list->item, cap * sizeof(*grown));

      if(!grown) {
        closedir(dir);
        return -1;
      }
      list->item = grown;
      list->cap = cap;
    }
    e = &list->item[list->count++];
    e->seq = seq;
    snprintf(e->file, sizeof(e->file), "%s", ent->d_name);
    snprintf(e->name, sizeof(e->name), "%s", name);
  }
  closedir(dir);
  qsort(list->item, list->count, sizeof(*list->item), seq_cmp);
  return 0;
}


static int
store_record(const char *text, size_t len, const char *final) {
  char pending[PATH_MAX];
  int fd;

  if(join(pending, sizeof(pending), trace_dir, ".pending")) {
    return -1;
  }
  fd = open(pending, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
  if(fd < 0) {
    return -1;
  }
  if(write_all(fd, text, len) || fsync(fd)) {
    close(fd);
    return -1;
  }
  if(close(fd)) {
    return -1;
  }
  return rename(pending, final);
}


static void
write_record(platform_t *platform, int fd, const char *name, int replace) {
  struct entries list;
  struct record record;
  char path[PATH_MAX];
  char existing[PATH_MAX];
  unsigned long long seq = 1;
  int found = 0;
  size_t i;

  memset(&list, 0, sizeof(list));
  record.text = NULL;

  if(mkdir(trace_dir, 0700) && errno != EEXIST) {
    goto fail;
  }
  if(scan(&list)) {
    goto fail;
  }
  for(i=0; i<list.count; i++) {
    if(!strcmp(list.item[i].name, name)) {
      found = 1;
    }
  }
  if(found && !replace) {
    reply(fd, "trace_exists", 96);
    goto out;
  }
  if(list.count) {
    seq = list.item[list.count - 1].seq + 1;
  }

  record.text = malloc(CONTENT_CAP + 1);
  if(!record.text) {
    goto fail;
  }
  record.len = 0;
  record.full = 0;
  record.text[0] = '\0';
  if(fill_record(platform, &record)) {
    goto fail;
  }

  snprintf(path, sizeof(path), "%s/%08llu_%s", trace_dir, seq, name);
  if(store_record(record.text, record.len, path)) {
    goto fail;
  }
  for(i=0; i<list.count; i++) {
    if(strcmp(list.item[i].name, name)) {
      continue;
    }
    if(join(existing, sizeof(existing), trace_dir, list.item[i].file) ||
       unlink(existing)) {
      goto fail;
    }
  }

  if(scan(&list)) {
    goto fail;
  }
  for(i=0; i + TRACE_RECORDS < list.count; i++) {
    if(join(existing, sizeof(existing), trace_dir, list.item[i].file) ||
       unlink(existing)) {
      goto fail;
    }
  }

  (void)write_all(fd, record.text, record.len);
  (void)write_all(fd, "exit 0\n", 7);
  goto out;

fail:
  reply(fd, "operation_failed", 1);
out:
  free(record.text);
  free(list.item);
}


void
trace_command(platform_t *platform, int fd, int argc, char *argv[]) {
  int replace;

  if(argc < 2) {
    reply(fd, "missing_operand", 1);
    return;
  }
  if(!valid_name(argv[1])) {
    reply(fd, "bad_path", 1);
    return;
  }
  if(argc > 3 || (argc == 3 && strcmp(argv[2], "--replace"))) {
    reply(fd, "bad_option", 1);
    return;
  }
  replace = argc == 3;

  pthread_mutex_lock(&lock);
  write_record(platform, fd, argv[1], replace);
  pthread_mutex_unlock(&lock);
}
