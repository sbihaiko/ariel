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
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "answer.h"
#include "runs.h"
#include "trace.h"

/** The most records kept at once; the oldest is dropped first. **/
#define TRACE_RECORDS 8

/** The longest name a record takes. **/
#define TRACE_NAME_MAX 32

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
  size_t shown;
  char names[TRACE_SHOW_PAYLOADS][PAYLOAD_NAME_MAX + 1];
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


/* Each byte outside letters, digits, '.', '_' and '-' is written %XX, as the
   canonical action does (docs/exit-codes.md). */
static void
escape(char *out, size_t size, const char *in) {
  const unsigned char *p = (const unsigned char *)in;
  size_t len = 0;

  for(; *p && len + 4 <= size; p++) {
    if(isalnum(*p) || *p == '.' || *p == '_' || *p == '-') {
      out[len++] = (char)*p;
    } else {
      len += (size_t)snprintf(out + len, size - len, "%%%02X", *p);
    }
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
  struct timeval tv;
  size_t size = sizeof(tv);

  if(sysctlbyname("kern.boottime", &tv, &size, NULL, 0)) {
    return -1;
  }
  *boot = tv.tv_sec;
  return 0;
}


static void
visit_going(void *ctx, const char *name) {
  struct going *going = ctx;

  if(going->shown < TRACE_SHOW_PAYLOADS) {
    snprintf(going->names[going->shown], sizeof(going->names[0]), "%s", name);
    going->shown++;
  }
  going->total++;
}


static int
going_cmp(const void *a, const void *b) {
  return strcmp((const char *)a, (const char *)b);
}


static int
fill_record(platform_t *platform, struct record *record) {
  char apps[PATH_MAX];
  char path[PATH_MAX];
  char esc[3 * PATH_MAX + 1];
  char esc2[3 * PATH_MAX + 1];
  struct names list;
  struct statvfs vfs;
  struct statfs *mounts;
  struct going going;
  time_t now = time(NULL);
  time_t boot;
  int count;
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

  count = getmntinfo(&mounts, MNT_NOWAIT);
  if(count < 0) {
    return -1;
  }
  add_line(record, "mounts %d", count);
  shown = (size_t)count < TRACE_SHOW_MOUNTS ? (size_t)count : TRACE_SHOW_MOUNTS;
  for(i=0; i<shown; i++) {
    escape(esc, sizeof(esc), mounts[i].f_mntonname);
    escape(esc2, sizeof(esc2), mounts[i].f_mntfromname);
    add_line(record, "mount %s %s", esc, esc2);
  }
  cut(record, shown, (size_t)count);

  if(join(apps, sizeof(apps), platform->fs_root, "user/app") ||
     list_names(apps, 1, &list)) {
    return -1;
  }
  add_line(record, "titles %zu", list.count);
  shown = list.count < TRACE_SHOW_TITLES ? list.count : TRACE_SHOW_TITLES;
  for(i=0; i<shown; i++) {
    long long bytes;

    if(join(path, sizeof(path), apps, list.item[i])) {
      names_free(&list);
      return -1;
    }
    bytes = tree_bytes(path, 0);
    if(bytes < 0) {
      names_free(&list);
      return -1;
    }
    escape(esc, sizeof(esc), list.item[i]);
    add_line(record, "title %s %lld", esc, bytes);
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
    escape(esc, sizeof(esc), list.item[i]);
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
    escape(esc, sizeof(esc), list.item[i]);
    add_line(record, "licence %s", esc);
  }
  cut(record, shown, list.count);
  names_free(&list);

  memset(&going, 0, sizeof(going));
  runs_visit_going(visit_going, &going);
  qsort(going.names, going.shown, sizeof(going.names[0]), going_cmp);
  add_line(record, "payloads %zu", going.total);
  for(i=0; i<going.shown; i++) {
    escape(esc, sizeof(esc), going.names[i]);
    add_line(record, "payload %s", esc);
  }
  cut(record, going.shown, going.total);

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
  char found_file[NAME_MAX + 1] = "";
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
      snprintf(found_file, sizeof(found_file), "%s", list.item[i].file);
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
  if(found && join(existing, sizeof(existing), trace_dir, found_file)) {
    goto fail;
  }
  if(found && unlink(existing)) {
    goto fail;
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
