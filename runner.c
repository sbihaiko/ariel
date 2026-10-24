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

// sync() is not POSIX; glibc declares it only with _DEFAULT_SOURCE.
#define _DEFAULT_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "json.h"
#include "protected.h"
#include "readers.h"
#include "runner.h"
#include "sha256.h"

#define IO_CHUNK     1024
#define OUT_LINE_CAP 1536

#define STATUS_PROTECTED 87

#define SUM_BLOCK 8192
#define SFO_MAGIC 0x46535000u
#define SFO_HEADER 20
#define SFO_ENTRY 16
#define SFO_TYPE_STR 2
#define SFO_TYPE_INT 4
#define SFO_MAX_SIZE (1024 * 1024)
#define SLEEP_MAX 60


static const struct {
  const char *name;
  const char *summary;
} commands[] = {
  {"authid", "print the authid of this process"},
  {"cat", "print an absolute file"},
  {"cmp", "compare two absolute files"},
  {"df", "print the free space of an absolute path"},
  {"echo", "print the operands"},
  {"file", "print the kind of an absolute path"},
  {"find", "list an absolute tree"},
  {"grep", "print the lines of an absolute file that match"},
  {"help", "list the commands"},
  {"hexdump", "print an absolute file in hex"},
  {"id", "print the user and group ids"},
  {"ls", "list the entries of an absolute directory"},
  {"procstat", "print one process by pid"},
  {"ps", "list the processes"},
  {"pwd", "print the working directory"},
  {"read", "print a range of an absolute file, with its size and SHA-256"},
  {"sfoinfo", "print the entries of an absolute PARAM.SFO"},
  {"sha256sum", "print the SHA-256 of an absolute file"},
  {"sleep", "pause for up to 60 seconds"},
  {"stat", "print the size, mode and inode of an absolute path"},
  {"sum", "print the BSD checksum of an absolute file"},
  {"sync", "write cached data to disk"},
  {"sysctl", "print a kernel parameter"},
};


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


/**
 * The word a failed file operation answers. A legacy command names what
 * went wrong instead of leaving the agent to read a strerror string.
 **/
static const char *
errno_word(int err) {
  switch(err) {
  case ENOENT:
    return "no_such_file";
  case ENOTDIR:
    return "not_a_directory";
  case EISDIR:
    return "is_a_directory";
  case ELOOP:
    return "symbolic_link";
  default:
    return "operation_failed";
  }
}


static void
report(const char *cmd, const char *path, int errfd, int err) {
  (void)cmd;
  (void)path;
  say(errfd, errno_word(err));
  say(errfd, "\n");
}


static void
say_bytes(int fd, const void *data, size_t len) {
  put(fd, data, len);
}


static void
say_failure(int errfd, const char *command, const char *path, int err) {
  report(command, path, errfd, err);
}


static int
bad_arguments(const char *cmd, int errfd) {
  (void)cmd;
  say(errfd, "bad_argument\n");
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
run_ls(int json, int argc, char *const argv[], int outfd, int errfd) {
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
    int err = errno;

    report("ls", argv[1], errfd, err);
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
    say(errfd, "operation_failed\n");
  } else {
    qsort(names, count, sizeof(*names), name_cmp);
    for(i=0; i<count; i++) {
      if(json) {
        say(outfd, "{\"name\":");
        json_say_string(outfd, names[i]);
        say(outfd, "}\n");
      } else {
        say(outfd, names[i]);
        say(outfd, "\n");
      }
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
run_stat(int json, int argc, char *const argv[], int outfd, int errfd) {
  char line[OUT_LINE_CAP];
  struct stat st;
  int rc;

  if(argc != 2) {
    return bad_arguments("stat", errfd);
  }
  if((rc=stat_target("stat", argv[1], errfd, &st))) {
    return rc;
  }

  if(json) {
    say(outfd, "{\"path\":");
    json_say_string(outfd, argv[1]);
    snprintf(line, sizeof(line),
             ",\"bytes\":%lld,\"mode\":\"%o\",\"inode\":%llu}\n",
             (long long)st.st_size, (unsigned)(st.st_mode & 07777),
             (unsigned long long)st.st_ino);
    say(outfd, line);
    return 0;
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
    say(errfd, "bad_argument\n");
    return 1;
  }
  if((rc=open_target("grep", argv[2], errfd, &fd))) {
    regfree(&re);
    return rc;
  }
  if(!(file=fdopen(fd, "r"))) {
    close(fd);
    regfree(&re);
    say(errfd, "operation_failed\n");
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
    say(errfd, "operation_failed\n");
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
run_df(int json, int argc, char *const argv[], int outfd, int errfd) {
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

  if(json) {
    say(outfd, "{\"path\":");
    json_say_string(outfd, argv[1]);
    snprintf(line, sizeof(line),
             ",\"total_bytes\":%llu,\"free_bytes\":%llu,\"available_bytes\":%llu}\n",
             (unsigned long long)vfs.f_blocks * vfs.f_frsize,
             (unsigned long long)vfs.f_bfree * vfs.f_frsize,
             (unsigned long long)vfs.f_bavail * vfs.f_frsize);
    say(outfd, line);
    return 0;
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


static void
say_path(int json, int fd, const char *path) {
  if(json) {
    say(fd, "{\"path\":");
    json_say_string(fd, path);
    say(fd, "}\n");
  } else {
    say(fd, path);
    say(fd, "\n");
  }
}


static int
run_find(int json, int argc, char *const argv[], int outfd, int errfd) {
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

  say_path(json, outfd, argv[1]);
  if(!S_ISDIR(st.st_mode)) {
    return 0;
  }

  root = strdup(argv[1]);
  if(!root || push_path(&todo, &count, &cap, root)) {
    free(root);
    free(todo);
    say(errfd, "operation_failed\n");
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
      say_path(json, outfd, child);

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
    say(errfd, "operation_failed\n");
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


static int
read_number(const char *text, uint64_t *value) {
  unsigned long long parsed;
  char *end;

  if(!isdigit((unsigned char)text[0])) {
    return -1;
  }
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if(errno || *end) {
    return -1;
  }
  *value = parsed;
  return 0;
}


static int
run_read(int argc, char *const argv[], int outfd, int errfd) {
  unsigned char digest[SHA256_DIGEST_LEN];
  char hex[SHA256_HEX_LEN + 1];
  char header[128];
  char marker[96];
  char buf[IO_CHUNK];
  uint64_t offset = 0;
  uint64_t limit = UINT64_MAX;
  uint64_t value;
  uint64_t size = 0;
  uint64_t wanted;
  uint64_t shown;
  sha256_t hash;
  struct stat st;
  ssize_t got;
  ssize_t n;
  char *body;
  int seen = 0;
  int fd;
  int rc;
  int i;

  if(argc < 2) {
    say(errfd, "missing_operand\n");
    return 1;
  }

  for(i=2; i<argc; i+=2) {
    int is_offset = !strcmp(argv[i], "--offset");
    int bit = is_offset ? 1 : 2;

    if(i + 1 == argc || (!is_offset && strcmp(argv[i], "--limit")) ||
       (seen & bit) || read_number(argv[i + 1], &value)) {
      say(errfd, "bad_option\n");
      return 1;
    }
    seen |= bit;
    if(is_offset) {
      offset = value;
    } else {
      limit = value;
    }
  }

  if((rc=open_target("read", argv[1], errfd, &fd))) {
    return rc;
  }
  if(fstat(fd, &st)) {
    int err = errno;

    close(fd);
    report("read", argv[1], errfd, err);
    return 1;
  }
  if(!S_ISREG(st.st_mode)) {
    close(fd);
    say(errfd, S_ISDIR(st.st_mode) ? "is_a_directory\n" : "not_a_file\n");
    return 1;
  }

  // The header carries the whole file's hash, so the whole file is read first.
  sha256_init(&hash);
  for(;;) {
    n = fill(fd, buf, sizeof(buf));
    if(n < 0) {
      int err = errno;

      close(fd);
      report("read", argv[1], errfd, err);
      return 1;
    }
    if(n == 0) {
      break;
    }
    sha256_update(&hash, buf, (size_t)n);
    size += (uint64_t)n;
  }
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);

  if(offset > size) {
    close(fd);
    say(errfd, "bad_range\n");
    return 1;
  }

  wanted = size - offset < limit ? size - offset : limit;
  shown = wanted < OUTPUT_CAP ? wanted : OUTPUT_CAP;

  body = malloc(shown ? shown : 1);
  if(!body) {
    close(fd);
    say(errfd, "operation_failed\n");
    return 1;
  }
  got = lseek(fd, (off_t)offset, SEEK_SET) < 0 ? -1 :
        fill(fd, body, (size_t)shown);
  close(fd);
  if(got != (ssize_t)shown) {
    free(body);
    say(errfd, "operation_failed\n");
    return 1;
  }

  snprintf(header, sizeof(header), "bytes %llu %s %llu\n",
           (unsigned long long)size, hex, (unsigned long long)shown);
  say(outfd, header);
  put(outfd, body, (size_t)shown);
  free(body);

  if(wanted > shown) {
    snprintf(marker, sizeof(marker), "truncated %llu of %llu\n",
             (unsigned long long)shown, (unsigned long long)wanted);
    say(outfd, marker);
  }
  return 0;
}


static int
run_echo(int argc, char *const argv[], int outfd) {
  for(int i=1; i<argc; i++) {
    if(i > 1) {
      say(outfd, " ");
    }
    say(outfd, argv[i]);
  }
  say(outfd, "\n");
  return 0;
}


static int
run_help(int outfd) {
  char line[256];
  size_t i;

  for(i=0; i<sizeof(commands)/sizeof(commands[0]); i++) {
    snprintf(line, sizeof(line), "%-10s %s\n",
             commands[i].name, commands[i].summary);
    say(outfd, line);
  }
  return 0;
}


static int
run_id(int outfd) {
  char line[128];

  snprintf(line, sizeof(line), "uid=%u gid=%u euid=%u egid=%u\n",
           (unsigned)getuid(), (unsigned)getgid(),
           (unsigned)geteuid(), (unsigned)getegid());
  say(outfd, line);
  return 0;
}


static int
run_sleep(int argc, char *const argv[], int errfd) {
  struct timespec want;
  struct timespec rest;
  unsigned long seconds;
  char *end;

  if(argc < 2) {
    say(errfd, "missing_operand\n");
    return 1;
  }

  errno = 0;
  seconds = strtoul(argv[1], &end, 10);
  if(!isdigit((unsigned char)argv[1][0]) || *end || errno ||
     seconds > SLEEP_MAX) {
    say(errfd, "bad_duration\n");
    return 1;
  }

  want.tv_sec = (time_t)seconds;
  want.tv_nsec = 0;
  while(nanosleep(&want, &rest) < 0 && errno == EINTR) {
    want = rest;
  }
  return 0;
}


static int
run_sum(int argc, char *const argv[], int outfd, int errfd) {
  int rc;
  unsigned long checksum = 0;
  unsigned char buf[SUM_BLOCK];
  char digits[16];
  ssize_t n;
  size_t i;
  int fd;

  if(argc < 2) {
    say(errfd, "missing_operand\n");
    return 1;
  }
  if(argv[1][0] != '/') {
    say(errfd, "relative_path\n");
    return 1;
  }

  if((rc=open_target("sum", argv[1], errfd, &fd))) {
    return rc;
  }

  while((n = read(fd, buf, sizeof(buf))) != 0) {
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      say_failure(errfd, "sum", argv[1], errno);
      close(fd);
      return 1;
    }
    for(i=0; i<(size_t)n; i++) {
      checksum = (checksum & 1) ? (checksum >> 1) + 0x8000 : checksum >> 1;
      checksum = (checksum + buf[i]) & 0xffff;
    }
  }
  close(fd);

  snprintf(digits, sizeof(digits), "%05lu ", checksum);
  say(outfd, digits);
  say(outfd, argv[1]);
  say(outfd, "\n");
  return 0;
}


static uint32_t
le32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
         (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}


static uint16_t
le16(const unsigned char *p) {
  return (uint16_t)(p[0] | p[1] << 8);
}


static void
say_sfo_value(int outfd, const unsigned char *val, uint32_t len, uint32_t type) {
  char pair[4];
  uint32_t i;

  if(type == SFO_TYPE_STR) {
    if(len && val[len-1] == 0) {
      len--;
    }
    say(outfd, "'");
    say_bytes(outfd, val, len);
    say(outfd, "'");
  } else if(type == SFO_TYPE_INT && len >= 4) {
    char hex[16];

    snprintf(hex, sizeof(hex), "0x%08x", le32(val));
    say(outfd, hex);
  } else {
    char head[32];

    snprintf(head, sizeof(head), "%u, 0x", (unsigned)type);
    say(outfd, head);
    for(i=0; i<len; i++) {
      snprintf(pair, sizeof(pair), "%02x", val[i]);
      say(outfd, pair);
    }
  }
}


static int
run_sfoinfo(int argc, char *const argv[], int outfd, int errfd) {
  int rc;
  unsigned char *buf;
  struct stat st;
  uint64_t size;
  uint32_t count;
  uint32_t keys;
  uint32_t data;
  uint32_t i;
  size_t got = 0;
  ssize_t n;
  int fd;

  if(argc < 2) {
    say(errfd, "missing_operand\n");
    return 1;
  }
  if(argv[1][0] != '/') {
    say(errfd, "relative_path\n");
    return 1;
  }

  if((rc=open_target("sfoinfo", argv[1], errfd, &fd))) {
    return rc;
  }
  if(fstat(fd, &st)) {
    say_failure(errfd, "sfoinfo", argv[1], errno);
    close(fd);
    return 1;
  }
  if(st.st_size < SFO_HEADER || st.st_size > SFO_MAX_SIZE) {
    close(fd);
    say(errfd, "not_sfo\n");
    return 1;
  }

  size = (uint64_t)st.st_size;
  if(!(buf = malloc(size))) {
    close(fd);
    say(errfd, "operation_failed\n");
    return 1;
  }
  while(got < size) {
    n = read(fd, buf + got, size - got);
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      break;
    }
    got += (size_t)n;
  }
  close(fd);

  if(got != size || le32(buf) != SFO_MAGIC) {
    free(buf);
    say(errfd, "not_sfo\n");
    return 1;
  }

  keys = le32(buf + 8);
  data = le32(buf + 12);
  count = le32(buf + 16);

  for(i=0; i<count; i++) {
    uint64_t offset = SFO_HEADER + (uint64_t)i * SFO_ENTRY;
    const unsigned char *entry;
    uint64_t key_start;
    uint64_t val_start;
    uint32_t val_len;
    uint32_t type;
    const unsigned char *nul;

    if(offset + SFO_ENTRY > size) {
      free(buf);
      say(errfd, "not_sfo\n");
      return 1;
    }
    entry = buf + offset;

    key_start = (uint64_t)keys + le16(entry);
    val_len = le32(entry + 4);
    type = entry[3];
    val_start = (uint64_t)data + le32(entry + 12);

    if(key_start >= size || val_start + val_len > size) {
      free(buf);
      say(errfd, "not_sfo\n");
      return 1;
    }
    nul = memchr(buf + key_start, 0, (size_t)(size - key_start));
    if(!nul) {
      free(buf);
      say(errfd, "not_sfo\n");
      return 1;
    }

    say_bytes(outfd, buf + key_start, (size_t)(nul - (buf + key_start)));
    say(outfd, "(");
    say_sfo_value(outfd, buf + val_start, val_len, type);
    say(outfd, ")\n");
  }

  free(buf);
  return 0;
}


typedef int (*file_command_fn)(int argc, char *const argv[], int outfd,
                               int errfd);

static const struct {
  const char *name;
  file_command_fn run;
} file_commands[] = {
  {"file", run_file},
  {"cat", run_cat},
  {"grep", run_grep},
  {"cmp", run_cmp},
  {"hexdump", run_hexdump},
  {"sha256sum", run_sha256sum},
  {"read", run_read},
};


static int
table_command(const char *name) {
  return !strcmp(name, "ls") || !strcmp(name, "stat") || !strcmp(name, "df") ||
         !strcmp(name, "find");
}


static int
json_command(const char *name) {
  return !strcmp(name, "ps") || table_command(name);
}


static int
json_requested(int argc, char *const argv[]) {
  int i;

  for(i=1; i<argc; i++) {
    if(!strncmp(argv[i], "--json", 6)) {
      return 1;
    }
  }
  return 0;
}


static int
refuse_option(int errfd, int *status) {
  say(errfd, "bad_option\n");
  *status = 1;
  return 0;
}


static int
run_table(int json, int argc, char *const argv[], int outfd, int errfd) {
  if(!strcmp(argv[0], "ls")) {
    return run_ls(json, argc, argv, outfd, errfd);
  }
  if(!strcmp(argv[0], "stat")) {
    return run_stat(json, argc, argv, outfd, errfd);
  }
  if(!strcmp(argv[0], "df")) {
    return run_df(json, argc, argv, outfd, errfd);
  }
  return run_find(json, argc, argv, outfd, errfd);
}


/* A refused option is found before anything runs, so nothing else is printed. */
static int
run_json(int argc, char *const argv[], int outfd, int errfd, int *status) {
  char **plain;
  int count = 0;
  int refused = 0;
  int rc = 0;
  int i;

  plain = calloc((size_t)argc, sizeof(*plain));
  if(!plain) {
    say(errfd, "operation_failed\n");
    *status = 1;
    return 0;
  }
  plain[count++] = argv[0];
  for(i=1; i<argc; i++) {
    if(!strcmp(argv[i], "--json")) {
      continue;
    }
    if(argv[i][0] == '-') {
      refused = 1;
      break;
    }
    plain[count++] = argv[i];
  }

  if(refused || (!strcmp(argv[0], "ps") && count != 1)) {
    free(plain);
    return refuse_option(errfd, status);
  }
  if(!strcmp(argv[0], "ps")) {
    rc = readers_run(1, count, plain, outfd, errfd, status);
  } else {
    *status = run_table(1, count, plain, outfd, errfd);
  }
  free(plain);
  return rc;
}


int
runner_run(int argc, char *const argv[], int outfd, int errfd, int *status) {
  size_t i;

  if(argc < 1) {
    return -1;
  }

  if(json_command(argv[0]) && json_requested(argc, argv)) {
    return run_json(argc, argv, outfd, errfd, status);
  }

  if(argc == 1 && !strcmp(argv[0], "pwd")) {
    say(outfd, "/\n");
    *status = 0;
    return 0;
  }

  if(table_command(argv[0])) {
    *status = run_table(0, argc, argv, outfd, errfd);
    return 0;
  }

  if(argc >= 1 && !strcmp(argv[0], "cd")) {
    say(errfd, "no_working_directory\n");
    *status = 1;
    return 0;
  }

  if(!strcmp(argv[0], "echo")) {
    *status = run_echo(argc, argv, outfd);
    return 0;
  }

  if(argc == 1 && !strcmp(argv[0], "help")) {
    *status = run_help(outfd);
    return 0;
  }

  if(argc == 1 && !strcmp(argv[0], "id")) {
    *status = run_id(outfd);
    return 0;
  }

  if(argc == 1 && !strcmp(argv[0], "sync")) {
    sync();
    *status = 0;
    return 0;
  }

  if(!strcmp(argv[0], "sleep")) {
    *status = run_sleep(argc, argv, errfd);
    return 0;
  }

  if(!strcmp(argv[0], "sum")) {
    *status = run_sum(argc, argv, outfd, errfd);
    return 0;
  }

  if(!strcmp(argv[0], "sfoinfo")) {
    *status = run_sfoinfo(argc, argv, outfd, errfd);
    return 0;
  }

  for(i=0; argc >= 1 && i<sizeof(file_commands)/sizeof(file_commands[0]); i++) {
    if(!strcmp(argv[0], file_commands[i].name)) {
      *status = file_commands[i].run(argc, argv, outfd, errfd);
      return 0;
    }
  }

  return readers_run(0, argc, argv, outfd, errfd, status);
}
