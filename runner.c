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
#include <fnmatch.h>
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

#include "answer.h"
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
  {"date", "print the current time in UTC"},
  {"df", "print the free space of an absolute path"},
  {"dmesg", "print the kernel log"},
  {"du", "print the bytes under an absolute path, one line per directory"},
  {"echo", "print the operands"},
  {"file", "print the kind of an absolute path"},
  {"find", "list an absolute tree"},
  {"grep", "print the lines of an absolute file that match"},
  {"head", "print the first lines of an absolute file"},
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
  {"sysinfo", "print the sysname, release, machine, uptime and memory"},
  {"tail", "print the last lines of an absolute file"},
  {"wc", "count the lines, words and bytes of an absolute file"},
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
parse_count(const char *text, size_t *value) {
  size_t n = 0;

  if(!*text) {
    return -1;
  }
  for(; *text; text++) {
    size_t digit;

    if(*text < '0' || *text > '9') {
      return -1;
    }
    digit = (size_t)(*text - '0');
    if(n > (SIZE_MAX - digit) / 10) {
      return -1;
    }
    n = n * 10 + digit;
  }
  *value = n;
  return 0;
}


// --limit N is the only option a reader takes, and it comes first.
static int
parse_limit(int argc, char *const argv[], int errfd, size_t *limit, int *skip) {
  *limit = SIZE_MAX;
  *skip = 0;

  // Any dash-led word in the place an option goes is an option, and `--limit`
  // is the only one these commands take: anything else answers bad_option
  // rather than being read as a path.
  if(argc < 2 || argv[1][0] != '-') {
    return 0;
  }
  if(!strcmp(argv[1], "--limit") && argc >= 3 && !parse_count(argv[2], limit)) {
    *skip = 2;
    return 0;
  }
  say(errfd, "bad_option\n");
  return 1;
}


static int
name_cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}


static char *join_path(const char *dir, const char *name);


static void
mode_text(mode_t mode, char *text) {
  static const char bits[] = "rwxrwxrwx";
  size_t i;

  if(S_ISDIR(mode)) {
    text[0] = 'd';
  } else if(S_ISLNK(mode)) {
    text[0] = 'l';
  } else if(S_ISREG(mode)) {
    text[0] = '-';
  } else {
    text[0] = '?';
  }
  for(i=0; i<9; i++) {
    text[i + 1] = (mode & (0400 >> i)) ? bits[i] : '-';
  }
  text[10] = '\0';
}


static int
ls_detail(const char *dir, const char *name, int json, answer_t *answer,
          int errfd) {
  char text[11];
  char line[2048];
  struct stat st;
  char *child;
  size_t n;

  if(!(child = join_path(dir, name))) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  if(lstat(child, &st)) {
    report("ls", child, errfd, errno);
    free(child);
    return 1;
  }
  free(child);

  mode_text(st.st_mode, text);
  if(json) {
    n = (size_t)snprintf(line, sizeof(line), "{\"mode\":\"%s\",\"size\":%llu,\"name\":",
                         text, (unsigned long long)st.st_size);
    if(n < sizeof(line)) {
      n += json_format_string(line + n, sizeof(line) - n, name);
    }
    if(n < sizeof(line)) {
      line[n++] = '}';
    }
  } else {
    n = (size_t)snprintf(line, sizeof(line), "%s %llu %s", text,
                         (unsigned long long)st.st_size, name);
  }
  // A row too long for the buffer is counted as cut, never streamed.
  if(n >= sizeof(line)) {
    answer_admit(answer, n);
    return 0;
  }
  answer_line(answer, line, n);
  return 0;
}


static int
run_ls(int json, int argc, char *const argv[], int outfd, int errfd) {
  char **names = NULL;
  size_t count = 0;
  size_t cap = 0;
  struct dirent *ent;
  answer_t answer;
  size_t limit = SIZE_MAX;
  DIR *dir;
  const char *path;
  int longform = 0;
  int all = 0;
  int first = 1;
  size_t i;
  int rc = 0;

  while(first < argc && argv[first][0] == '-') {
    if(!strcmp(argv[first], "--")) {
      first++;
      break;
    } else if(!strcmp(argv[first], "-l")) {
      longform = 1;
    } else if(!strcmp(argv[first], "-a")) {
      all = 1;
    } else if(!strcmp(argv[first], "--limit")) {
      if(first + 1 >= argc || parse_count(argv[first + 1], &limit)) {
        say(errfd, "bad_option\n");
        return 1;
      }
      first++;
    } else {
      say(errfd, "bad_option\n");
      return 1;
    }
    first++;
  }
  if(argc - first != 1 || argv[first][0] != '/') {
    say(errfd, "relative_path\n");
    return 1;
  }
  path = argv[first];

  if(!(dir = opendir(path))) {
    int err = errno;

    report("ls", path, errfd, err);
    return 1;
  }

  while((ent = readdir(dir))) {
    if(!all && (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))) {
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
    answer_init(&answer, outfd, limit);
    for(i=0; i<count; i++) {
      if(longform) {
        if(ls_detail(path, names[i], json, &answer, errfd)) {
          rc = 1;
        }
      } else if(json) {
        answer_json(&answer, "name", names[i]);
      } else {
        answer_line(&answer, names[i], strlen(names[i]));
      }
    }
    answer_done(&answer);
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
open_regular(const char *cmd, const char *path, int errfd, int *fd) {
  struct stat st;
  int rc;
  int err;

  if((rc=open_target(cmd, path, errfd, fd))) {
    return rc;
  }
  if(fstat(*fd, &st)) {
    err = errno;
    close(*fd);
    report(cmd, path, errfd, err);
    return 1;
  }
  if(!S_ISREG(st.st_mode)) {
    close(*fd);
    say(errfd, "not_a_file\n");
    return 1;
  }
  return 0;
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
  size_t shown = 0;
  size_t total = 0;
  size_t cap;
  size_t limit;
  ssize_t n;
  int skip;
  int fd;
  int rc;

  if(parse_limit(argc, argv, errfd, &limit, &skip)) {
    return 1;
  }
  argc -= skip;
  argv += skip;

  if(argc != 2) {
    return bad_arguments("cat", errfd);
  }
  if((rc=open_target("cat", argv[1], errfd, &fd))) {
    return rc;
  }

  cap = limit < CONTENT_CAP ? limit : CONTENT_CAP;
  for(;;) {
    n = read(fd, buf, sizeof(buf));
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      break;
    }
    total += (size_t)n;
    if(shown < cap) {
      size_t take = cap - shown;

      if((size_t)n < take) {
        take = (size_t)n;
      }
      put(outfd, buf, take);
      shown += take;
      last = buf[take - 1];
    }
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
  if(shown < total) {
    say_cut(outfd, shown, total);
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


#define GREP_LINES 0
#define GREP_COUNT 1
#define GREP_LIST  2
#define TREE_DEPTH_MAX 64


/** One answer line, prefixed by its path when the search spans files. **/
static void
grep_line(answer_t *answer, const char *path, int named, const char *text,
          size_t len) {
  size_t plen = named ? strlen(path) + 1 : 0;
  char *line;

  if(!named) {
    answer_line(answer, text, len);
    return;
  }
  if(!(line = malloc(plen + len))) {
    answer_admit(answer, plen + len);
    return;
  }
  memcpy(line, path, plen - 1);
  line[plen - 1] = ':';
  memcpy(line + plen, text, len);
  answer_line(answer, line, plen + len);
  free(line);
}


/** Search one open regular file. named prefixes each line or count with its path. **/
static int
grep_file(const regex_t *re, const char *path, int fd, int mode, int named,
          answer_t *answer, int errfd, int *matched) {
  char *line = NULL;
  size_t cap = 0;
  size_t hits = 0;
  ssize_t len;
  int failed;
  FILE *file;

  if(!(file=fdopen(fd, "r"))) {
    close(fd);
    say(errfd, "operation_failed\n");
    return 1;
  }

  while((len=next_line(file, &line, &cap)) >= 0) {
    size_t text = (size_t)len;

    if(line[text - 1] == '\n') {
      line[--text] = '\0';
    }
    if(regexec(re, line, 0, NULL, 0) == 0) {
      hits++;
      if(mode == GREP_LINES) {
        grep_line(answer, path, named, line, text);
      }
    }
  }

  failed = len == -2 || ferror(file);
  fclose(file);
  free(line);

  if(failed) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  if(hits) {
    *matched = 1;
  }
  if(mode == GREP_COUNT) {
    char count[32];
    size_t n = (size_t)snprintf(count, sizeof(count), "%zu", hits);

    grep_line(answer, path, named, count, n);
  } else if(mode == GREP_LIST && hits) {
    answer_line(answer, path, strlen(path));
  }
  return 0;
}


/**
 * Search the directory at path and everything below it. Links are not
 * followed: a link to a protected object answers protected, any other link is
 * skipped. Returns 0, 1 for a failure, or STATUS_PROTECTED.
 **/
static int
grep_walk(const regex_t *re, const char *path, int mode, answer_t *answer,
          int errfd, int *matched, int depth) {
  struct dirent *ent;
  DIR *dir;
  int failed = 0;

  if(depth >= TREE_DEPTH_MAX) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  if(!(dir=opendir(path))) {
    report("grep", path, errfd, errno);
    return 1;
  }

  while((ent = readdir(dir))) {
    char *child;
    struct stat st;
    struct stat target;
    int rc = 0;

    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(!(child=join_path(path, ent->d_name))) {
      failed = 1;
      break;
    }
    if(lstat(child, &st)) {
      report("grep", child, errfd, errno);
      rc = 1;
    } else if(S_ISLNK(st.st_mode)) {
      if(!stat(child, &target) && protected_stat(&target)) {
        say(errfd, "protected\n");
        rc = STATUS_PROTECTED;
      }
    } else if(protected_stat(&st)) {
      say(errfd, "protected\n");
      rc = STATUS_PROTECTED;
    } else if(S_ISDIR(st.st_mode)) {
      rc = grep_walk(re, child, mode, answer, errfd, matched, depth + 1);
    } else if(S_ISREG(st.st_mode)) {
      int fd;

      if(!(rc=open_target("grep", child, errfd, &fd))) {
        rc = grep_file(re, child, fd, mode, 1, answer, errfd, matched);
      }
    }
    free(child);

    if(rc == STATUS_PROTECTED) {
      closedir(dir);
      return rc;
    }
    if(rc) {
      failed = 1;
    }
  }
  closedir(dir);
  return failed;
}


static int
run_grep(int argc, char *const argv[], int outfd, int errfd) {
  answer_t answer;
  int recursive = 0;
  int list = 0;
  int count = 0;
  size_t limit = SIZE_MAX;
  int first = 1;
  int matched = 0;
  const char *pattern = NULL;
  const char *path;
  regex_t re;
  struct stat st;
  int mode;
  int fd;
  int rc;

  // `--` ends the options, so a pattern may begin with a dash; `-e PATTERN`
  // names the pattern outright. Any other dash-led word is not an option.
  while(first < argc && argv[first][0] == '-') {
    if(!strcmp(argv[first], "--")) {
      first++;
      break;
    } else if(!strcmp(argv[first], "-r")) {
      recursive = 1;
    } else if(!strcmp(argv[first], "-l")) {
      list = 1;
    } else if(!strcmp(argv[first], "-c")) {
      count = 1;
    } else if(!strcmp(argv[first], "--limit")) {
      if(first + 1 >= argc || parse_count(argv[first + 1], &limit)) {
        say(errfd, "bad_option\n");
        return 1;
      }
      first++;
    } else if(!strcmp(argv[first], "-e")) {
      if(first + 1 >= argc) {
        return bad_arguments("grep", errfd);
      }
      pattern = argv[++first];
    } else {
      say(errfd, "bad_option\n");
      return 1;
    }
    first++;
  }
  if(pattern) {
    if(argc - first != 1) {
      return bad_arguments("grep", errfd);
    }
    path = argv[first];
  } else {
    if(argc - first != 2) {
      return bad_arguments("grep", errfd);
    }
    pattern = argv[first];
    path = argv[first + 1];
  }
  if(regcomp(&re, pattern, REG_NOSUB)) {
    say(errfd, "bad_argument\n");
    return 1;
  }
  mode = list ? GREP_LIST : count ? GREP_COUNT : GREP_LINES;

  answer_init(&answer, outfd, limit);
  if(!recursive) {
    if((rc=open_target("grep", path, errfd, &fd))) {
      regfree(&re);
      return rc;
    }
    rc = grep_file(&re, path, fd, mode, 0, &answer, errfd, &matched);
  } else if((rc=open_target("grep", path, errfd, &fd))) {
    regfree(&re);
    return rc;
  } else if(fstat(fd, &st)) {
    close(fd);
    report("grep", path, errfd, errno);
    rc = 1;
  } else if(S_ISDIR(st.st_mode)) {
    close(fd);
    rc = grep_walk(&re, path, mode, &answer, errfd, &matched, 0);
  } else {
    rc = grep_file(&re, path, fd, mode, 1, &answer, errfd, &matched);
  }
  regfree(&re);

  if(rc) {
    return rc;
  }
  answer_done(&answer);
  return matched ? 0 : 1;
}


static int
run_head(int argc, char *const argv[], int outfd, int errfd) {
  char *line = NULL;
  size_t cap = 0;
  answer_t answer;
  size_t count = 10;
  ssize_t len;
  int failed;
  int fd;
  int rc;
  FILE *file;

  if(argc == 3) {
    if(parse_count(argv[1], &count)) {
      return bad_arguments("head", errfd);
    }
    argc--;
    argv++;
  }
  if(argc != 2) {
    return bad_arguments("head", errfd);
  }
  if((rc=open_regular("head", argv[1], errfd, &fd))) {
    return rc;
  }
  if(!(file=fdopen(fd, "r"))) {
    close(fd);
    say(errfd, "operation_failed\n");
    return 1;
  }

  answer_init(&answer, outfd, count);
  while((len=next_line(file, &line, &cap)) >= 0) {
    size_t text = (size_t)len;

    if(line[text - 1] == '\n') {
      line[--text] = '\0';
    }
    answer_line(&answer, line, text);
  }

  failed = len == -2 || ferror(file);
  fclose(file);
  free(line);

  if(failed) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  answer_done(&answer);
  return 0;
}


typedef struct tail_line {
  struct tail_line *next;
  size_t len;
  char text[];
} tail_line_t;


static void
tail_drop(tail_line_t **first, tail_line_t **last, size_t *count,
          size_t *bytes) {
  tail_line_t *old = *first;

  *first = old->next;
  if(!*first) {
    *last = NULL;
  }
  *bytes -= old->len + 1;
  (*count)--;
  free(old);
}


static void
tail_free(tail_line_t *first) {
  while(first) {
    tail_line_t *next = first->next;

    free(first);
    first = next;
  }
}


static int
run_tail(int argc, char *const argv[], int outfd, int errfd) {
  tail_line_t *first = NULL;
  tail_line_t *last = NULL;
  tail_line_t *node;
  char *line = NULL;
  size_t cap = 0;
  size_t count = 0;
  size_t bytes = 0;
  size_t total = 0;
  size_t limit = 10;
  ssize_t len;
  int failed;
  int oom = 0;
  int fd;
  int rc;
  FILE *file;

  if(argc == 3) {
    if(parse_count(argv[1], &limit)) {
      return bad_arguments("tail", errfd);
    }
    argc--;
    argv++;
  }
  if(argc != 2) {
    return bad_arguments("tail", errfd);
  }
  if((rc=open_regular("tail", argv[1], errfd, &fd))) {
    return rc;
  }
  if(!(file=fdopen(fd, "r"))) {
    close(fd);
    say(errfd, "operation_failed\n");
    return 1;
  }

  while((len=next_line(file, &line, &cap)) >= 0) {
    size_t text = (size_t)len;

    if(line[text - 1] == '\n') {
      text--;
    }
    total++;
    if(!(node=malloc(sizeof(*node) + text + 1))) {
      oom = 1;
      break;
    }
    node->next = NULL;
    node->len = text;
    memcpy(node->text, line, text);
    node->text[text] = '\0';
    if(last) {
      last->next = node;
    } else {
      first = node;
    }
    last = node;
    count++;
    bytes += text + 1;
    while(first && (count > limit || bytes > CONTENT_CAP)) {
      tail_drop(&first, &last, &count, &bytes);
    }
  }

  failed = oom || len == -2 || ferror(file);
  fclose(file);
  free(line);

  if(failed) {
    tail_free(first);
    say(errfd, "operation_failed\n");
    return 1;
  }

  for(node=first; node; node=node->next) {
    put(outfd, node->text, node->len);
    say(outfd, "\n");
  }
  if(count < total) {
    say_cut(outfd, count, total);
  }
  tail_free(first);
  return 0;
}


static int
run_wc(int argc, char *const argv[], int outfd, int errfd) {
  unsigned long long lines = 0;
  unsigned long long words = 0;
  unsigned long long bytes = 0;
  char buf[IO_CHUNK];
  char line[OUT_LINE_CAP];
  int inword = 0;
  ssize_t n;
  size_t i;
  int fd;
  int rc;

  if(argc != 2) {
    return bad_arguments("wc", errfd);
  }
  if((rc=open_regular("wc", argv[1], errfd, &fd))) {
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
    for(i=0; i<(size_t)n; i++) {
      bytes++;
      if(buf[i] == '\n') {
        lines++;
      }
      if(isspace((unsigned char)buf[i])) {
        inword = 0;
      } else if(!inword) {
        inword = 1;
        words++;
      }
    }
  }

  if(n < 0) {
    int err = errno;

    close(fd);
    report("wc", argv[1], errfd, err);
    return 1;
  }
  close(fd);

  snprintf(line, sizeof(line), "%llu %llu %llu ", lines, words, bytes);
  say(outfd, line);
  say(outfd, argv[1]);
  say(outfd, "\n");
  return 0;
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
run_date(int argc, char *const argv[], int outfd, int errfd) {
  char line[64];
  struct tm tm;
  time_t now;

  if(argc > 1) {
    if(argv[1][0] == '-') {
      say(errfd, "bad_option\n");
      return 1;
    }
    return bad_arguments("date", errfd);
  }

  if((now=time(NULL)) == (time_t)-1 || !gmtime_r(&now, &tm)) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d UTC\n",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec);
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


static int
find_wanted(const char *path, const struct stat *st, const char *name, char type) {
  const char *base;
  char kind;

  if(name) {
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    // A glob is expanded here, as bash's find does: `-name '*.log'` matches
    // by name, and a value with no metacharacter matches exactly.
    if(fnmatch(name, base, 0)) {
      return 0;
    }
  }
  if(type) {
    kind = S_ISREG(st->st_mode) ? 'f' : S_ISDIR(st->st_mode) ? 'd' :
           S_ISLNK(st->st_mode) ? 'l' : '?';
    if(kind != type) {
      return 0;
    }
  }
  return 1;
}


static int
run_find(int json, int argc, char *const argv[], int outfd, int errfd) {
  char **todo = NULL;
  size_t count = 0;
  size_t cap = 0;
  struct stat st;
  struct dirent *ent;
  answer_t answer;
  size_t limit;
  DIR *dir;
  char *root;
  const char *name = NULL;
  char type = 0;
  int failed = 0;
  int oom = 0;
  int skip;
  size_t i;
  int next;

  if(parse_limit(argc, argv, errfd, &limit, &skip)) {
    return 1;
  }
  argc -= skip;
  argv += skip;

  if(argc < 2) {
    return bad_arguments("find", errfd);
  }
  for(next=2; next<argc; next+=2) {
    if(!strcmp(argv[next], "-name") || !strcmp(argv[next], "-type")) {
      if(next + 1 >= argc) {
        say(errfd, "missing_operand\n");
        return 1;
      }
    }
    if(!strcmp(argv[next], "-name")) {
      name = argv[next + 1];
    } else if(!strcmp(argv[next], "-type")) {
      const char *value = argv[next + 1];

      if(strcmp(value, "f") && strcmp(value, "d") && strcmp(value, "l")) {
        say(errfd, "bad_argument\n");
        return 1;
      }
      type = value[0];
    } else if(argv[next][0] == '-') {
      say(errfd, "bad_option\n");
      return 1;
    } else {
      return bad_arguments("find", errfd);
    }
  }
  if(refuse_relative(argv[1], errfd)) {
    return 1;
  }
  if(lstat(argv[1], &st)) {
    report("find", argv[1], errfd, errno);
    return 1;
  }

  answer_init(&answer, outfd, limit);
  if(find_wanted(argv[1], &st, name, type)) {
    answer_path(&answer, json, argv[1]);
  }
  if(!S_ISDIR(st.st_mode)) {
    answer_done(&answer);
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
      if(find_wanted(child, &child_st, name, type)) {
        answer_path(&answer, json, child);
      }

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
  answer_done(&answer);
  return failed;
}


typedef struct {
  answer_t *answer;
  int errfd;
  int failed;
  int oom;
} du_walk_t;


// One directory's line, after the totals of everything below it.
static void
du_say(du_walk_t *walk, const char *path, uint64_t bytes) {
  int need = snprintf(NULL, 0, "%llu %s", (unsigned long long)bytes, path);
  char *line;

  if(need < 0) {
    walk->failed = 1;
    return;
  }
  if(!(line = malloc((size_t)need + 1))) {
    walk->oom = 1;
    return;
  }
  snprintf(line, (size_t)need + 1, "%llu %s", (unsigned long long)bytes, path);
  answer_line(walk->answer, line, (size_t)need);
  free(line);
}


// Sums the regular files under path and writes one line for each directory,
// children first. A link is never followed, and a file that is not regular
// counts as no bytes.
static uint64_t
du_walk(du_walk_t *walk, const char *path) {
  char **names = NULL;
  size_t count = 0;
  size_t cap = 0;
  struct stat st;
  struct dirent *ent;
  uint64_t total = 0;
  size_t i;
  DIR *dir;

  if(lstat(path, &st)) {
    report("du", path, walk->errfd, errno);
    walk->failed = 1;
    return 0;
  }
  if(!S_ISDIR(st.st_mode)) {
    return S_ISREG(st.st_mode) ? (uint64_t)st.st_size : 0;
  }

  if(!(dir=opendir(path))) {
    report("du", path, walk->errfd, errno);
    walk->failed = 1;
    du_say(walk, path, 0);
    return 0;
  }
  while((ent = readdir(dir))) {
    char **grown;

    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(count == cap) {
      grown = realloc(names, (cap ? cap * 2 : 16) * sizeof(*names));
      if(!grown) {
        walk->oom = 1;
        break;
      }
      names = grown;
      cap = cap ? cap * 2 : 16;
    }
    if(!(names[count] = strdup(ent->d_name))) {
      walk->oom = 1;
      break;
    }
    count++;
  }
  closedir(dir);

  if(!walk->oom) {
    qsort(names, count, sizeof(*names), name_cmp);
    for(i=0; i<count; i++) {
      char *child = join_path(path, names[i]);

      if(!child) {
        walk->oom = 1;
        break;
      }
      total += du_walk(walk, child);
      free(child);
    }
  }

  for(i=0; i<count; i++) {
    free(names[i]);
  }
  free(names);

  du_say(walk, path, total);
  return total;
}


static int
run_du(int argc, char *const argv[], int outfd, int errfd) {
  answer_t answer;
  du_walk_t walk;
  struct stat st;
  uint64_t total;

  if(argc != 2) {
    if(argc > 1 && argv[1][0] == '-') {
      say(errfd, "bad_option\n");
      return 1;
    }
    return bad_arguments("du", errfd);
  }
  if(refuse_relative(argv[1], errfd)) {
    return 1;
  }
  if(lstat(argv[1], &st)) {
    report("du", argv[1], errfd, errno);
    return 1;
  }

  answer_init(&answer, outfd, SIZE_MAX);
  walk.answer = &answer;
  walk.errfd = errfd;
  walk.failed = 0;
  walk.oom = 0;
  total = du_walk(&walk, argv[1]);
  if(!S_ISDIR(st.st_mode)) {
    du_say(&walk, argv[1], total);
  }

  if(walk.oom) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  answer_done(&answer);
  return walk.failed;
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

  // Decision 5's one frame: the size is the number of bytes that follow,
  // which is the file's size for a whole read and the range's for a cut one.
  snprintf(header, sizeof(header), "bytes %llu %s\n",
           (unsigned long long)shown, hex);
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
  int options;
} file_commands[] = {
  {"file", run_file, 0},
  {"cat", run_cat, 1},
  {"grep", run_grep, 1},
  {"cmp", run_cmp, 0},
  {"hexdump", run_hexdump, 0},
  {"sha256sum", run_sha256sum, 0},
  {"read", run_read, 1},
  {"head", run_head, 0},
  {"tail", run_tail, 0},
  {"wc", run_wc, 0},
  {"date", run_date, 0},
  {"du", run_du, 0},
};


static int
table_command(const char *name) {
  return !strcmp(name, "ls") || !strcmp(name, "stat") || !strcmp(name, "df") ||
         !strcmp(name, "find");
}


static int
json_command(const char *name) {
  return !strcmp(name, "ps") || !strcmp(name, "sysinfo") || table_command(name);
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
  int i;

  if(!strcmp(argv[0], "ls")) {
    return run_ls(json, argc, argv, outfd, errfd);
  }
  if(!strcmp(argv[0], "stat")) {
    for(i=1; i<argc; i++) {
      if(argv[i][0] == '-') {
        say(errfd, "bad_option\n");
        return 1;
      }
    }
    return run_stat(json, argc, argv, outfd, errfd);
  }
  if(!strcmp(argv[0], "df")) {
    for(i=1; i<argc; i++) {
      if(argv[i][0] == '-') {
        say(errfd, "bad_option\n");
        return 1;
      }
    }
    return run_df(json, argc, argv, outfd, errfd);
  }
  return run_find(json, argc, argv, outfd, errfd);
}


static int
limit_command(const char *name) {
  return !strcmp(name, "ls") || !strcmp(name, "find");
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
    if(!strcmp(argv[i], "--limit") && limit_command(argv[0])) {
      plain[count++] = argv[i];
      if(i+1 < argc) {
        plain[count++] = argv[++i];
      }
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
  if(!strcmp(argv[0], "ps") || !strcmp(argv[0], "sysinfo")) {
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
      size_t j;

      if(!file_commands[i].options) {
        for(j=1; j<(size_t)argc; j++) {
          if(argv[j][0] == '-') {
            say(errfd, "bad_option\n");
            *status = 1;
            return 0;
          }
        }
      }
      *status = file_commands[i].run(argc, argv, outfd, errfd);
      return 0;
    }
  }

  return readers_run(0, argc, argv, outfd, errfd, status);
}
