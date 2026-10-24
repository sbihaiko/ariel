/* Ariel: the noninteractive command runner.

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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "protected.h"
#include "runner.h"
#include "sha256.h"

#define IO_CHUNK     1024
#define OUT_LINE_CAP 1536

#define STATUS_PROTECTED 87


static void
put(int fd, const char *buf, size_t len) {
  while(len > 0) {
    ssize_t n = write(fd, buf, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return;
    }
    buf += n;
    len -= (size_t)n;
  }
}


static void
say(int fd, const char *text) {
  put(fd, text, strlen(text));
}


static void
report(const char *cmd, const char *path, int errfd, int err) {
  say(errfd, cmd);
  say(errfd, ": ");
  say(errfd, path);
  say(errfd, ": ");
  say(errfd, strerror(err));
  say(errfd, "\n");
}


static int
bad_arguments(const char *cmd, int errfd) {
  say(errfd, cmd);
  say(errfd, ": bad arguments\n");
  return 1;
}


static int
refuse_relative(const char *path, int errfd) {
  if(path[0] != '/') {
    say(errfd, "relative_path\n");
    return 1;
  }
  return 0;
}


// Reads up to cap bytes, fewer only at end of file; -1 on error.
static ssize_t
fill(int fd, char *buf, size_t cap) {
  size_t total = 0;

  while(total < cap) {
    ssize_t n = read(fd, buf + total, cap - total);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(n == 0) {
      break;
    }
    total += (size_t)n;
  }
  return (ssize_t)total;
}


static int
name_cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}


static int
run_ls(int argc, char *const argv[], int outfd, int errfd) {
  char **names = NULL;
  size_t count = 0;
  size_t cap = 0;
  struct dirent *ent;
  DIR *dir;
  size_t i;
  int rc = 0;

  if(argc != 2 || argv[1][0] != '/') {
    say(errfd, "relative_path\n");
    return 1;
  }

  if(!(dir = opendir(argv[1]))) {
    say(errfd, "ls: ");
    say(errfd, argv[1]);
    say(errfd, ": ");
    say(errfd, strerror(errno));
    say(errfd, "\n");
    return 1;
  }

  while((ent = readdir(dir))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(count == cap) {
      char **grown = realloc(names, (cap ? cap * 2 : 64) * sizeof(*names));

      if(!grown) {
        rc = 1;
        break;
      }
      names = grown;
      cap = cap ? cap * 2 : 64;
    }
    if(!(names[count] = strdup(ent->d_name))) {
      rc = 1;
      break;
    }
    count++;
  }
  closedir(dir);

  if(rc) {
    say(errfd, "ls: out of memory\n");
  } else {
    qsort(names, count, sizeof(*names), name_cmp);
    for(i=0; i<count; i++) {
      say(outfd, names[i]);
      say(outfd, "\n");
    }
  }

  for(i=0; i<count; i++) {
    free(names[i]);
  }
  free(names);

  return rc;
}


// The open follows symbolic links; O_NONBLOCK keeps a FIFO from blocking.
static int
open_target(const char *cmd, const char *path, int errfd, int *fd) {
  int state;
  int err;

  if(refuse_relative(path, errfd)) {
    return 1;
  }

  if((*fd=open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)) < 0) {
    report(cmd, path, errfd, errno);
    return 1;
  }

  state = protected_object(*fd);
  if(state == 0) {
    return 0;
  }
  err = errno;
  close(*fd);

  if(state > 0) {
    say(errfd, "protected\n");
    return STATUS_PROTECTED;
  }
  report(cmd, path, errfd, err);
  return 1;
}


static int
stat_target(const char *cmd, const char *path, int errfd, struct stat *st) {
  int fd;
  int rc;
  int err;

  if((rc=open_target(cmd, path, errfd, &fd))) {
    return rc;
  }
  if(fstat(fd, st)) {
    err = errno;
    close(fd);
    report(cmd, path, errfd, err);
    return 1;
  }
  close(fd);
  return 0;
}


static int
run_stat(int argc, char *const argv[], int outfd, int errfd) {
  char line[OUT_LINE_CAP];
  struct stat st;
  int rc;

  if(argc != 2) {
    return bad_arguments("stat", errfd);
  }
  if((rc=stat_target("stat", argv[1], errfd, &st))) {
    return rc;
  }

  snprintf(line, sizeof(line), "%s: %lld bytes, mode %o, inode %llu\n",
           argv[1], (long long)st.st_size, (unsigned)(st.st_mode & 07777),
           (unsigned long long)st.st_ino);
  say(outfd, line);
  return 0;
}


static int
run_file(int argc, char *const argv[], int outfd, int errfd) {
  struct stat st;
  const char *kind;
  int rc;

  if(argc != 2) {
    return bad_arguments("file", errfd);
  }
  if((rc=stat_target("file", argv[1], errfd, &st))) {
    return rc;
  }

  if(S_ISDIR(st.st_mode)) {
    kind = "directory";
  } else if(S_ISREG(st.st_mode)) {
    kind = "regular file";
  } else if(S_ISFIFO(st.st_mode)) {
    kind = "fifo";
  } else if(S_ISCHR(st.st_mode)) {
    kind = "character device";
  } else if(S_ISBLK(st.st_mode)) {
    kind = "block device";
  } else if(S_ISSOCK(st.st_mode)) {
    kind = "socket";
  } else {
    kind = "unknown";
  }

  say(outfd, argv[1]);
  say(outfd, ": ");
  say(outfd, kind);
  say(outfd, "\n");
  return 0;
}


static int
run_cat(int argc, char *const argv[], int outfd, int errfd) {
  char buf[IO_CHUNK];
  char last = '\n';
  ssize_t n;
  int fd;
  int rc;

  if(argc != 2) {
    return bad_arguments("cat", errfd);
  }
  if((rc=open_target("cat", argv[1], errfd, &fd))) {
    return rc;
  }

  for(;;) {
    n = read(fd, buf, sizeof(buf));
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      break;
    }
    put(outfd, buf, (size_t)n);
    last = buf[n - 1];
  }

  if(n < 0) {
    int err = errno;

    close(fd);
    report("cat", argv[1], errfd, err);
    return 1;
  }
  close(fd);

  // A reply is one line per result, so the exit line never follows text.
  if(last != '\n') {
    say(outfd, "\n");
  }
  return 0;
}


// Reads one line, newline included, into a growing buffer. Returns its length,
// -1 at end of file, or -2 when the buffer cannot grow.
static ssize_t
next_line(FILE *file, char **line, size_t *cap) {
  size_t len = 0;
  int c;

  while((c=getc(file)) != EOF) {
    if(len + 2 > *cap) {
      size_t next = *cap ? *cap * 2 : 128;
      char *grown = realloc(*line, next);

      if(!grown) {
        return -2;
      }
      *line = grown;
      *cap = next;
    }
    (*line)[len++] = (char)c;
    if(c == '\n') {
      break;
    }
  }
  if(len == 0) {
    return -1;
  }
  (*line)[len] = '\0';
  return (ssize_t)len;
}


static int
run_grep(int argc, char *const argv[], int outfd, int errfd) {
  char *line = NULL;
  size_t cap = 0;
  regex_t re;
  ssize_t len;
  int matched = 0;
  int failed;
  int fd;
  int rc;
  FILE *file;

  if(argc != 3) {
    return bad_arguments("grep", errfd);
  }
  if(regcomp(&re, argv[1], REG_NOSUB)) {
    say(errfd, "grep: bad pattern\n");
    return 1;
  }
  if((rc=open_target("grep", argv[2], errfd, &fd))) {
    regfree(&re);
    return rc;
  }
  if(!(file=fdopen(fd, "r"))) {
    close(fd);
    regfree(&re);
    say(errfd, "grep: out of memory\n");
    return 1;
  }

  while((len=next_line(file, &line, &cap)) >= 0) {
    size_t text = (size_t)len;

    if(line[text - 1] == '\n') {
      line[--text] = '\0';
    }
    if(regexec(&re, line, 0, NULL, 0) == 0) {
      matched = 1;
      put(outfd, line, text);
      say(outfd, "\n");
    }
  }

  failed = len == -2 || ferror(file);
  fclose(file);
  free(line);
  regfree(&re);

  if(failed) {
    say(errfd, "grep: read error\n");
    return 1;
  }
  return matched ? 0 : 1;
}


static int
run_cmp(int argc, char *const argv[], int outfd, int errfd) {
  char left[IO_CHUNK];
  char right[IO_CHUNK];
  char line[OUT_LINE_CAP];
  ssize_t a;
  ssize_t b;
  int fa;
  int fb;
  int rc;
  int err;

  if(argc != 3) {
    return bad_arguments("cmp", errfd);
  }
  if((rc=open_target("cmp", argv[1], errfd, &fa))) {
    return rc;
  }
  if((rc=open_target("cmp", argv[2], errfd, &fb))) {
    close(fa);
    return rc;
  }

  rc = 0;
  for(;;) {
    a = fill(fa, left, sizeof(left));
    b = fill(fb, right, sizeof(right));
    if(a < 0 || b < 0) {
      err = errno;
      report("cmp", a < 0 ? argv[1] : argv[2], errfd, err);
      rc = 1;
      break;
    }
    if(a != b) {
      snprintf(line, sizeof(line), "cmp: EOF on %s\n",
               a < b ? argv[1] : argv[2]);
      say(outfd, line);
      rc = 1;
      break;
    }
    if(a == 0) {
      break;
    }
    if(memcmp(left, right, (size_t)a)) {
      snprintf(line, sizeof(line), "%s %s differ\n", argv[1], argv[2]);
      say(outfd, line);
      rc = 1;
      break;
    }
  }

  close(fa);
  close(fb);
  return rc;
}


static void
hex_row(char *out, size_t size, unsigned long offset, const char *buf,
        size_t n) {
  size_t pos;
  size_t i;

  pos = (size_t)snprintf(out, size, "%08lx  ", offset);
  for(i=0; i<16; i++) {
    if(i < n) {
      pos += (size_t)snprintf(out + pos, size - pos, "%02x ",
                              (unsigned char)buf[i]);
    } else {
      pos += (size_t)snprintf(out + pos, size - pos, "   ");
    }
    if(i == 7) {
      pos += (size_t)snprintf(out + pos, size - pos, " ");
    }
  }
  pos += (size_t)snprintf(out + pos, size - pos, " |");
  for(i=0; i<n; i++) {
    unsigned char c = (unsigned char)buf[i];

    out[pos++] = isprint(c) ? (char)c : '.';
  }
  snprintf(out + pos, size - pos, "|\n");
}


static int
run_hexdump(int argc, char *const argv[], int outfd, int errfd) {
  char buf[16];
  char line[OUT_LINE_CAP];
  unsigned long offset = 0;
  ssize_t n;
  int fd;
  int rc;
  int err;

  if(argc != 2) {
    return bad_arguments("hexdump", errfd);
  }
  if((rc=open_target("hexdump", argv[1], errfd, &fd))) {
    return rc;
  }

  for(;;) {
    n = fill(fd, buf, sizeof(buf));
    if(n < 0) {
      err = errno;
      close(fd);
      report("hexdump", argv[1], errfd, err);
      return 1;
    }
    if(n == 0) {
      break;
    }
    hex_row(line, sizeof(line), offset, buf, (size_t)n);
    say(outfd, line);
    offset += (unsigned long)n;
  }
  close(fd);

  snprintf(line, sizeof(line), "%08lx\n", offset);
  say(outfd, line);
  return 0;
}


static int
run_df(int argc, char *const argv[], int outfd, int errfd) {
  char line[OUT_LINE_CAP];
  struct statvfs vfs;

  if(argc != 2) {
    return bad_arguments("df", errfd);
  }
  if(refuse_relative(argv[1], errfd)) {
    return 1;
  }
  if(statvfs(argv[1], &vfs)) {
    report("df", argv[1], errfd, errno);
    return 1;
  }

  snprintf(line, sizeof(line),
           "%s: %llu bytes total, %llu bytes free, %llu bytes available\n",
           argv[1],
           (unsigned long long)vfs.f_blocks * vfs.f_frsize,
           (unsigned long long)vfs.f_bfree * vfs.f_frsize,
           (unsigned long long)vfs.f_bavail * vfs.f_frsize);
  say(outfd, line);
  return 0;
}


static char *
join_path(const char *dir, const char *name) {
  size_t dirlen = strlen(dir);
  int slash = dirlen == 0 || dir[dirlen - 1] != '/';
  char *path = malloc(dirlen + (size_t)slash + strlen(name) + 1);

  if(path) {
    strcpy(path, dir);
    if(slash) {
      strcat(path, "/");
    }
    strcat(path, name);
  }
  return path;
}


static int
push_path(char ***stack, size_t *count, size_t *cap, char *path) {
  if(*count == *cap) {
    size_t next = *cap ? *cap * 2 : 16;
    char **grown = realloc(*stack, next * sizeof(**stack));

    if(!grown) {
      return -1;
    }
    *stack = grown;
    *cap = next;
  }
  (*stack)[(*count)++] = path;
  return 0;
}


static int
run_find(int argc, char *const argv[], int outfd, int errfd) {
  char **todo = NULL;
  size_t count = 0;
  size_t cap = 0;
  struct stat st;
  struct dirent *ent;
  DIR *dir;
  char *root;
  int failed = 0;
  int oom = 0;
  size_t i;

  if(argc != 2) {
    return bad_arguments("find", errfd);
  }
  if(refuse_relative(argv[1], errfd)) {
    return 1;
  }
  if(lstat(argv[1], &st)) {
    report("find", argv[1], errfd, errno);
    return 1;
  }

  say(outfd, argv[1]);
  say(outfd, "\n");
  if(!S_ISDIR(st.st_mode)) {
    return 0;
  }

  root = strdup(argv[1]);
  if(!root || push_path(&todo, &count, &cap, root)) {
    free(root);
    free(todo);
    say(errfd, "find: out of memory\n");
    return 1;
  }

  while(count > 0 && !oom) {
    char *here = todo[--count];

    if(!(dir=opendir(here))) {
      report("find", here, errfd, errno);
      failed = 1;
      free(here);
      continue;
    }

    while((ent = readdir(dir))) {
      char *child;
      struct stat child_st;

      if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
        continue;
      }
      if(!(child=join_path(here, ent->d_name))) {
        oom = 1;
        break;
      }
      if(lstat(child, &child_st)) {
        report("find", child, errfd, errno);
        failed = 1;
        free(child);
        continue;
      }
      say(outfd, child);
      say(outfd, "\n");

      if(S_ISDIR(child_st.st_mode)) {
        if(push_path(&todo, &count, &cap, child)) {
          free(child);
          oom = 1;
          break;
        }
      } else {
        free(child);
      }
    }
    closedir(dir);
    free(here);
  }

  for(i=0; i<count; i++) {
    free(todo[i]);
  }
  free(todo);

  if(oom) {
    say(errfd, "find: out of memory\n");
    return 1;
  }
  return failed;
}


static int
run_sha256sum(int argc, char *const argv[], int outfd, int errfd) {
  unsigned char digest[SHA256_DIGEST_LEN];
  char hex[SHA256_HEX_LEN + 1];
  char buf[IO_CHUNK];
  char line[OUT_LINE_CAP];
  sha256_t hash;
  ssize_t n;
  int fd;
  int rc;
  int err;

  if(argc != 2) {
    return bad_arguments("sha256sum", errfd);
  }
  if((rc=open_target("sha256sum", argv[1], errfd, &fd))) {
    return rc;
  }

  sha256_init(&hash);
  for(;;) {
    n = fill(fd, buf, sizeof(buf));
    if(n < 0) {
      err = errno;
      close(fd);
      report("sha256sum", argv[1], errfd, err);
      return 1;
    }
    if(n == 0) {
      break;
    }
    sha256_update(&hash, buf, (size_t)n);
  }
  close(fd);

  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
  snprintf(line, sizeof(line), "%s  %s\n", hex, argv[1]);
  say(outfd, line);
  return 0;
}


typedef int (*file_command_fn)(int argc, char *const argv[], int outfd,
                               int errfd);

static const struct {
  const char *name;
  file_command_fn run;
} file_commands[] = {
  {"stat", run_stat},
  {"file", run_file},
  {"cat", run_cat},
  {"grep", run_grep},
  {"find", run_find},
  {"cmp", run_cmp},
  {"hexdump", run_hexdump},
  {"df", run_df},
  {"sha256sum", run_sha256sum},
};


int
runner_run(int argc, char *const argv[], int outfd, int errfd, int *status) {
  size_t i;

  if(argc == 1 && !strcmp(argv[0], "pwd")) {
    say(outfd, "/\n");
    *status = 0;
    return 0;
  }

  if(argc >= 1 && !strcmp(argv[0], "ls")) {
    *status = run_ls(argc, argv, outfd, errfd);
    return 0;
  }

  if(argc >= 1 && !strcmp(argv[0], "cd")) {
    say(errfd, "no_working_directory\n");
    *status = 1;
    return 0;
  }

  for(i=0; argc >= 1 && i<sizeof(file_commands)/sizeof(file_commands[0]); i++) {
    if(!strcmp(argv[0], file_commands[i].name)) {
      *status = file_commands[i].run(argc, argv, outfd, errfd);
      return 0;
    }
  }

  return -1;
}
