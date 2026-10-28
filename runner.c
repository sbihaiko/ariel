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

#if defined(__APPLE__)
// macOS hides O_NOFOLLOW behind _DARWIN_C_SOURCE once _POSIX_C_SOURCE is
// defined, and cd opens its directory without following a symbolic link.
#define _DARWIN_C_SOURCE 1
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
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
#include "runs.h"
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
#define VERIFY_CEILING (256ULL * 1024 * 1024)
#define VERIFY_LINES 10
/* One file name from a directory entry: 255 bytes plus the terminator. */
#define VERIFY_NAME_CAP 256


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
  {"ifconfig", "print the interfaces with their state, IPv4 address and mask"},
  {"ls", "list the entries of an absolute directory"},
  {"ping", "say whether an IPv4 address answers, with its round trips"},
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
  {"verify", "say whether one installed title is whole, with --size and --sha256 to compare; --all sweeps the console, with --floor N for free space"},
  {"trace", "record the console's state under NAME, kept in the state directory; --replace overwrites a record of that name; --list names the records kept; --diff NAME answers what changed since NAME"},
  {"wc","count the lines, words and bytes of an absolute file"},
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


/**
 * The session of the command this thread is running, or NULL. One
 * connection thread runs one command at a time, and every path-taking
 * command reaches the two helpers below, so the working directory travels
 * here instead of as an argument repeated at fourteen call sites. It is
 * thread-local, so two connections never share one; runner_run sets it for
 * the length of its dispatch and puts back what it found.
 **/
static _Thread_local runner_session_t *session_current;

static int resolve_path(const char *cwd, const char *path, char *out,
                        size_t size, int errfd);
static int refuse_protected(const char *path, int errfd);


int
runner_resolve(const runner_session_t *session, const char *path, char *out,
               size_t size, int errfd) {
  return resolve_path(session ? session->cwd : NULL, path, out, size, errfd);
}


/** The path a command will act on, resolved against the session's directory
    when it is relative. Returns 0 when out holds it. **/
static int
resolve_operand(const char *path, char *out, size_t size, int errfd) {
  return resolve_path(session_current ? session_current->cwd : NULL,
                      path, out, size, errfd);
}


/**
 * Resolve one path against the session's directory: an absolute path is
 * normalised as it stands and a relative one is joined to cwd, so a command
 * names the same entry however it was written. The join is lexical, so no
 * symbolic link is followed here and the checks after it still see one, and
 * a ".." that would leave the root answers bad_path. A relative path with
 * no working directory answers relative_path, as it always has. Returns 0
 * when out holds the path.
 **/
static int
resolve_path(const char *cwd, const char *path, char *out, size_t size,
             int errfd) {
  char joined[PATH_MAX * 2];
  const char *part;
  size_t used = 0;

  if(!path[0]) {
    say(errfd, "bad_path\n");
    return 1;
  }

  if(path[0] == '/') {
    if(snprintf(joined, sizeof(joined), "%s", path) >= (int)sizeof(joined)) {
      say(errfd, "bad_path\n");
      return 1;
    }
  } else {
    if(!cwd) {
      say(errfd, "relative_path\n");
      return 1;
    }
    if(snprintf(joined, sizeof(joined), "%s/%s", cwd, path)
       >= (int)sizeof(joined)) {
      say(errfd, "bad_path\n");
      return 1;
    }
  }

  // Rebuild the path one segment at a time, so "." disappears, ".." pops a
  // segment and no other segment is touched.
  out[0] = '\0';
  part = joined;
  while(*part) {
    const char *slash;
    size_t len;

    while(*part == '/') {
      part++;
    }
    if(!*part) {
      break;
    }

    slash = strchr(part, '/');
    len = slash ? (size_t)(slash - part) : strlen(part);

    if(len == 1 && part[0] == '.') {
      // The current directory names itself.
    } else if(len == 2 && part[0] == '.' && part[1] == '.') {
      if(used == 0) {
        say(errfd, "bad_path\n");
        return 1;
      }
      while(used > 0 && out[used - 1] != '/') {
        used--;
      }
      if(used > 0) {
        used--;
      }
      out[used] = '\0';
    } else {
      if(used + 1 + len + 1 > size) {
        say(errfd, "bad_path\n");
        return 1;
      }
      out[used++] = '/';
      memcpy(out + used, part, len);
      used += len;
      out[used] = '\0';
    }

    part = slash ? slash + 1 : part + len;
  }

  if(used == 0) {
    out[0] = '/';
    out[1] = '\0';
  }

  return 0;
}


/**
 * cd PATH: take the session into a directory, judged as ls judges a path.
 * A symbolic link answers for itself and is never followed, so the session
 * only ever holds a path it named. The chosen directory comes back through
 * the session for the caller that stores it.
 **/
static int
run_cd(runner_session_t *session, int argc, char *const argv[], int errfd,
       int *status) {
  char resolved[PATH_MAX];
  struct stat st;
  int fd;

  *status = 1;

  // A connection with no session cannot change directory at all, so it
  // answers that whatever it was asked; the argument count matters only
  // where there is a directory to change to.
  if(!session || !session->cwd) {
    say(errfd, "no_working_directory\n");
    return 0;
  }
  if(argc != 2) {
    say(errfd, "bad_argument\n");
    return 0;
  }

  if(resolve_path(session->cwd, argv[1], resolved, sizeof(resolved), errfd)) {
    return 0;
  }
  if(refuse_protected(resolved, errfd)) {
    *status = STATUS_PROTECTED;
    return 0;
  }

  // lstat first, so a symbolic link answers for itself whether or not the
  // platform's open would have followed it.
  if(lstat(resolved, &st)) {
    report("cd", resolved, errfd, errno);
    return 0;
  }
  if(S_ISLNK(st.st_mode)) {
    say(errfd, "symbolic_link\n");
    return 0;
  }
  if(!S_ISDIR(st.st_mode)) {
    say(errfd, "not_a_directory\n");
    return 0;
  }

  if((fd=open(resolved, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) {
    report("cd", resolved, errfd, errno);
    return 0;
  }
  close(fd);

  if(!session->new_cwd ||
     snprintf(session->new_cwd, session->new_cwd_size, "%s", resolved)
     >= (int)session->new_cwd_size) {
    say(errfd, "bad_path\n");
    return 0;
  }

  *status = 0;
  return 0;
}


static int
refuse_protected(const char *path, int errfd) {
  if(protected_path(path)) {
    say(errfd, "protected\n");
    return 1;
  }
  return 0;
}


static int
protected_entry(const char *path) {
  struct stat st;

  return !lstat(path, &st) && protected_stat(&st);
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
  char resolved[PATH_MAX];
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
  if(argc - first != 1) {
    say(errfd, "relative_path\n");
    return 1;
  }
  if(resolve_operand(argv[first], resolved, sizeof(resolved), errfd)) {
    return 1;
  }
  path = resolved;
  if(refuse_protected(path, errfd)) {
    return STATUS_PROTECTED;
  }

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
  char resolved[PATH_MAX];
  int state;
  int err;

  if(resolve_operand(path, resolved, sizeof(resolved), errfd)) {
    return 1;
  }
  path = resolved;

  if(refuse_protected(path, errfd)) {
    return STATUS_PROTECTED;
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
  char resolved[PATH_MAX];
  char line[OUT_LINE_CAP];
  struct statvfs vfs;

  if(argc != 2) {
    return bad_arguments("df", errfd);
  }
  if(resolve_operand(argv[1], resolved, sizeof(resolved), errfd)) {
    return 1;
  }
  if(refuse_protected(resolved, errfd)) {
    return STATUS_PROTECTED;
  }
  if(statvfs(resolved, &vfs)) {
    report("df", resolved, errfd, errno);
    return 1;
  }

  if(json) {
    say(outfd, "{\"path\":");
    json_say_string(outfd, resolved);
    snprintf(line, sizeof(line),
             ",\"total_bytes\":%llu,\"free_bytes\":%llu,\"available_bytes\":%llu}\n",
             (unsigned long long)vfs.f_blocks * vfs.f_frsize,
             (unsigned long long)vfs.f_bfree * vfs.f_frsize,
             (unsigned long long)vfs.f_bavail * vfs.f_frsize);
    say(outfd, line);
    return 0;
  }

  // The path is written on its own: it can be longer than a line buffer, and a
  // line cut to fit would name a path the owner never asked about.
  say(outfd, resolved);
  snprintf(line, sizeof(line),
           ": %llu bytes total, %llu bytes free, %llu bytes available\n",
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
  char resolved[PATH_MAX];
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
  if(resolve_operand(argv[1], resolved, sizeof(resolved), errfd)) {
    return 1;
  }
  if(refuse_protected(resolved, errfd)) {
    return STATUS_PROTECTED;
  }
  if(lstat(resolved, &st)) {
    report("find", resolved, errfd, errno);
    return 1;
  }

  answer_init(&answer, outfd, limit);
  if(find_wanted(resolved, &st, name, type)) {
    answer_path(&answer, json, resolved);
  }
  if(!S_ISDIR(st.st_mode)) {
    answer_done(&answer);
    return 0;
  }

  root = strdup(resolved);
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
      if(protected_stat(&child_st)) {
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
      if(!protected_entry(child)) {
        total += du_walk(walk, child);
      }
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
  char resolved[PATH_MAX];
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
  if(resolve_operand(argv[1], resolved, sizeof(resolved), errfd)) {
    return 1;
  }
  if(refuse_protected(resolved, errfd)) {
    return STATUS_PROTECTED;
  }
  if(lstat(resolved, &st)) {
    report("du", resolved, errfd, errno);
    return 1;
  }

  answer_init(&answer, outfd, SIZE_MAX);
  walk.answer = &answer;
  walk.errfd = errfd;
  walk.failed = 0;
  walk.oom = 0;
  total = du_walk(&walk, resolved);
  if(!S_ISDIR(st.st_mode)) {
    du_say(&walk, resolved, total);
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
run_sleep(platform_t *platform, int argc, char *const argv[], int errfd) {
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

  // A sleep ends on the platform's clock, so a build whose clock moves only
  // when something moves it does not sleep on real time: the host build's
  // test clock ends this sleep, and no scenario waits for the machine.
  if(platform && platform->sleep_ms) {
    platform->sleep_ms(platform, (long)seconds * 1000L);
  } else {
    struct timespec want;
    struct timespec rest;

    want.tv_sec = (time_t)seconds;
    want.tv_nsec = 0;
    while(nanosleep(&want, &rest) < 0 && errno == EINTR) {
      want = rest;
    }
  }
  return 0;
}


static int
run_sum(int argc, char *const argv[], int outfd, int errfd) {
  char resolved[PATH_MAX];
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
  if(resolve_operand(argv[1], resolved, sizeof(resolved), errfd)) {
    return 1;
  }

  if((rc=open_target("sum", resolved, errfd, &fd))) {
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
  char resolved[PATH_MAX];
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
  if(resolve_operand(argv[1], resolved, sizeof(resolved), errfd)) {
    return 1;
  }

  if((rc=open_target("sfoinfo", resolved, errfd, &fd))) {
    return rc;
  }
  if(fstat(fd, &st)) {
    say_failure(errfd, "sfoinfo", resolved, errno);
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


static const char *const verify_entries[] = {
  "app.pkg", "app.pbm", "app.json", "app.xml", "sce_sys/param.sfo",
};


static int
verify_title_ok(const char *title) {
  return title[0] && strcmp(title, ".") && strcmp(title, "..") &&
         !strchr(title, '/');
}


static int
verify_hex_digest(const char *text) {
  size_t i;

  if(strlen(text) != SHA256_HEX_LEN) {
    return 0;
  }
  for(i=0; i<SHA256_HEX_LEN; i++) {
    if(!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) {
      return 0;
    }
  }
  return 1;
}


typedef struct {
  const char *title;
  const char *sha256;
  int has_size;
  size_t size;
  int all;
  int has_floor;
  size_t floor;
} verify_args_t;


static int
verify_parse(int argc, char *const argv[], verify_args_t *args, int errfd) {
  int i;

  memset(args, 0, sizeof(*args));
  if(argc < 2) {
    say(errfd, "missing_operand\n");
    return 1;
  }
  if(!strcmp(argv[1], "--all")) {
    args->all = 1;
  } else if(argv[1][0] == '-') {
    say(errfd, "bad_option\n");
    return 1;
  } else {
    args->title = argv[1];
  }

  for(i=2; i<argc; i++) {
    if(args->all && !strcmp(argv[i], "--floor") && !args->has_floor && i+1 < argc &&
       !parse_count(argv[i+1], &args->floor)) {
      args->has_floor = 1;
      i++;
    } else if(!args->all && !strcmp(argv[i], "--size") && !args->has_size && i+1 < argc &&
              !parse_count(argv[i+1], &args->size)) {
      args->has_size = 1;
      i++;
    } else if(!args->all && !strcmp(argv[i], "--sha256") && !args->sha256 && i+1 < argc &&
              verify_hex_digest(argv[i+1])) {
      args->sha256 = argv[++i];
    } else if(argv[i][0] == '-') {
      say(errfd, "bad_option\n");
      return 1;
    } else {
      say(errfd, "bad_argument\n");
      return 1;
    }
  }

  if(!args->all && !verify_title_ok(args->title)) {
    say(errfd, "bad_argument\n");
    return 1;
  }
  return 0;
}


static void
verify_entry(const char *app, const char *entry, char *line) {
  char path[PATH_MAX];
  struct stat st;

  if(snprintf(path, sizeof(path), "%s/%s", app, entry) >= (int)sizeof(path) ||
     lstat(path, &st) || !S_ISREG(st.st_mode)) {
    snprintf(line, OUT_LINE_CAP, "finding missing %s", entry);
  } else if(st.st_size == 0) {
    snprintf(line, OUT_LINE_CAP, "finding empty %s", entry);
  } else {
    snprintf(line, OUT_LINE_CAP, "ok %s", entry);
  }
}


// The smallest licence file name in user/license that names the title.
static int
verify_find_licence(const char *root, const char *title, char *name, size_t size) {
  char dir[PATH_MAX];
  char needle[PATH_MAX];
  struct dirent *entry;
  DIR *handle;
  int found = 0;

  if(snprintf(dir, sizeof(dir), "%s/user/license", root) >= (int)sizeof(dir) ||
     snprintf(needle, sizeof(needle), "-%s_", title) >= (int)sizeof(needle) ||
     !(handle=opendir(dir))) {
    return 0;
  }
  while((entry=readdir(handle))) {
    size_t len = strlen(entry->d_name);

    if(strncmp(entry->d_name, "fake", 4) ||
       strcmp(entry->d_name + len - 4, ".rif") ||
       !strstr(entry->d_name, needle)) {
      continue;
    }
    if(!found || strcmp(entry->d_name, name) < 0) {
      snprintf(name, size, "%s", entry->d_name);
      found = 1;
    }
  }
  closedir(handle);
  return found;
}


static int
verify_licence_is(const char *licence, const char *content) {
  size_t len = strlen(licence);

  return strlen(content) == len - 8 && !strncmp(content, licence + 4, len - 8);
}


static int
sfo_find(const unsigned char *buf, uint64_t size, const char *key, char *value,
         size_t cap) {
  uint32_t keys = le32(buf + 8);
  uint32_t data = le32(buf + 12);
  uint32_t count = le32(buf + 16);
  uint32_t i;

  for(i=0; i<count; i++) {
    uint64_t offset = SFO_HEADER + (uint64_t)i * SFO_ENTRY;
    const unsigned char *entry;
    const unsigned char *nul;
    const unsigned char *text;
    uint64_t key_start;
    uint64_t val_start;
    uint32_t val_len;
    size_t len;

    if(offset + SFO_ENTRY > size) {
      return 1;
    }
    entry = buf + offset;
    key_start = (uint64_t)keys + le16(entry);
    val_len = le32(entry + 4);
    val_start = (uint64_t)data + le32(entry + 12);
    if(key_start >= size || val_start + val_len > size) {
      return 1;
    }
    nul = memchr(buf + key_start, 0, (size_t)(size - key_start));
    if(!nul) {
      return 1;
    }
    if(strcmp((const char *)buf + key_start, key)) {
      continue;
    }
    if(entry[3] != SFO_TYPE_STR) {
      return 1;
    }
    text = buf + val_start;
    nul = memchr(text, 0, val_len);
    len = nul ? (size_t)(nul - text) : val_len;
    if(len >= cap) {
      return 1;
    }
    memcpy(value, text, len);
    value[len] = '\0';
    return 0;
  }
  return 1;
}


static int
sfo_string(const char *path, const char *key, char *value, size_t cap) {
  unsigned char *buf;
  struct stat st;
  ssize_t n;
  int rc = 1;
  int fd;

  if((fd=open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0) {
    return 1;
  }
  if(fstat(fd, &st) || st.st_size < SFO_HEADER || st.st_size > SFO_MAX_SIZE ||
     !(buf=malloc((size_t)st.st_size))) {
    close(fd);
    return 1;
  }
  n = fill(fd, (char *)buf, (size_t)st.st_size);
  close(fd);
  if(n == st.st_size && le32(buf) == SFO_MAGIC) {
    rc = sfo_find(buf, (uint64_t)st.st_size, key, value, cap);
  }
  free(buf);
  return rc;
}


static int
verify_sha256(const char *path, char hex[SHA256_HEX_LEN + 1], uint64_t *bytes) {
  unsigned char digest[SHA256_DIGEST_LEN];
  char buf[IO_CHUNK];
  sha256_t hash;
  uint64_t total = 0;
  ssize_t n;
  int err;
  int fd;

  if((fd=open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0) {
    return errno;
  }
  sha256_init(&hash);
  for(;;) {
    n = fill(fd, buf, sizeof(buf));
    if(n < 0) {
      err = errno;
      close(fd);
      return err;
    }
    if(n == 0) {
      break;
    }
    sha256_update(&hash, buf, (size_t)n);
    total += (uint64_t)n;
  }
  close(fd);

  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
  *bytes = total;
  return 0;
}


/**
 * The checks of the title at app, one line each in lines, counted in total.
 * A size or hash is compared only when the caller names one, and a file over
 * VERIFY_CEILING is never read for its hash. A hash that cannot be read is
 * reported and answers 1.
 **/
static int
verify_title_checks(const char *root, const char *app, const verify_args_t *args,
                    char lines[VERIFY_LINES][OUT_LINE_CAP], size_t *total, int errfd) {
  /* A licence is one directory entry, so its name and not a path bounds it. */
  char licence[VERIFY_NAME_CAP];
  char content[PATH_MAX];
  char path[PATH_MAX];
  char hex[SHA256_HEX_LEN + 1];
  struct stat st;
  uint64_t hashed;
  size_t count = 0;
  size_t i;
  char *line;
  int rc;

  for(i=0; i<sizeof(verify_entries)/sizeof(verify_entries[0]); i++) {
    verify_entry(app, verify_entries[i], lines[count++]);
  }

  line = lines[count++];
  if(snprintf(path, sizeof(path), "%s/user/appmeta/%s", root, args->title) >= (int)sizeof(path) ||
     lstat(path, &st)) {
    snprintf(line, OUT_LINE_CAP, "finding missing appmeta");
  } else {
    snprintf(line, OUT_LINE_CAP, "ok appmeta");
  }

  line = lines[count++];
  if(!verify_find_licence(root, args->title, licence, sizeof(licence))) {
    snprintf(line, OUT_LINE_CAP, "finding licence_missing %s", args->title);
  } else {
    snprintf(line, OUT_LINE_CAP, "ok licence");
    line = lines[count++];
    if(snprintf(path, sizeof(path), "%s/sce_sys/param.sfo", app) >= (int)sizeof(path) ||
       sfo_string(path, "CONTENT_ID", content, sizeof(content))) {
      snprintf(line, OUT_LINE_CAP, "finding missing content_id");
    } else if(!verify_licence_is(licence, content)) {
      snprintf(line, OUT_LINE_CAP, "finding licence_mismatch %s", licence);
    } else {
      snprintf(line, OUT_LINE_CAP, "ok content_id");
    }
  }

  if(args->has_size || args->sha256) {
    if(snprintf(path, sizeof(path), "%s/app.pkg", app) >= (int)sizeof(path)) {
      say(errfd, "bad_path\n");
      return 1;
    }
    if(!lstat(path, &st) && S_ISREG(st.st_mode)) {
      if(args->has_size) {
        line = lines[count++];
        if((unsigned long long)st.st_size == (unsigned long long)args->size) {
          snprintf(line, OUT_LINE_CAP, "ok app.pkg size");
        } else {
          snprintf(line, OUT_LINE_CAP, "finding size_mismatch app.pkg %lld",
                   (long long)st.st_size);
        }
      }
      if(args->sha256) {
        line = lines[count++];
        if((unsigned long long)st.st_size > VERIFY_CEILING) {
          snprintf(line, OUT_LINE_CAP, "too_large_to_verify app.pkg");
        } else if((rc=verify_sha256(path, hex, &hashed))) {
          report("verify", path, errfd, rc);
          return 1;
        } else if(strcmp(hex, args->sha256)) {
          snprintf(line, OUT_LINE_CAP, "finding hash_mismatch app.pkg");
        } else {
          snprintf(line, OUT_LINE_CAP, "ok app.pkg sha256");
        }
      }
    }
  }

  *total = count;
  return 0;
}


/** The part of a title that a finding of its checks names. **/
static const char *
title_part(const char *finding) {
  static const struct {
    const char *kind;
    const char *part;
  } parts[] = {
    {"missing app.", "package"},
    {"empty app.", "package"},
    {"missing sce_sys/param.sfo", "sfo"},
    {"empty sce_sys/param.sfo", "sfo"},
    {"missing content_id", "sfo"},
    {"missing appmeta", "appmeta"},
    {"licence_missing", "licence"},
    {"licence_mismatch", "licence"},
  };
  size_t i;

  for(i=0; i<sizeof(parts)/sizeof(parts[0]); i++) {
    if(!strncmp(finding, parts[i].kind, strlen(parts[i].kind))) {
      return parts[i].part;
    }
  }
  return "package";
}


int
runner_title_missing(const char *root, const char *title, const char **part) {
  char lines[VERIFY_LINES][OUT_LINE_CAP];
  char app[PATH_MAX];
  verify_args_t args;
  size_t count = 0;
  size_t i;

  memset(&args, 0, sizeof(args));
  args.title = title;
  if(snprintf(app, sizeof(app), "%s/user/app/%s", root, title) >= (int)sizeof(app) ||
     verify_title_checks(root, app, &args, lines, &count, -1)) {
    *part = "package";
    return 1;
  }
  for(i=0; i<count; i++) {
    if(!strncmp(lines[i], "finding ", sizeof("finding ") - 1)) {
      *part = title_part(lines[i] + sizeof("finding ") - 1);
      return 1;
    }
  }
  return 0;
}


int
runner_package_fact(const char *path, uint64_t *bytes, char hex[SHA256_HEX_LEN + 1]) {
  struct stat st;

  if(lstat(path, &st) || !S_ISREG(st.st_mode)) {
    return 1;
  }
  *bytes = (uint64_t)st.st_size;
  if((unsigned long long)st.st_size > VERIFY_CEILING) {
    return 2;
  }
  return verify_sha256(path, hex, bytes) ? 1 : 0;
}


static void
verify_finding(int outfd, const char *kind, const char *detail) {
  say(outfd, "finding ");
  say(outfd, kind);
  say(outfd, " ");
  say(outfd, detail);
  say(outfd, "\n");
}


// A finding of one title names the title after its kind. licence_missing
// already names its title as its detail, so it keeps that one name.
static void
verify_title_finding(int outfd, const char *title, const char *line) {
  const char *kind = line + sizeof("finding ") - 1;
  size_t kind_len = strcspn(kind, " ");

  if(kind_len == sizeof("licence_missing") - 1 &&
     !strncmp(kind, "licence_missing", kind_len)) {
    say(outfd, line);
    say(outfd, "\n");
    return;
  }
  say(outfd, "finding ");
  put(outfd, kind, kind_len);
  say(outfd, " ");
  say(outfd, title);
  say(outfd, " ");
  say(outfd, kind + kind_len + 1);
  say(outfd, "\n");
}


// Whether an installed title, a directory under user/app, is named by licence.
static int
verify_licence_named(const char *root, const char *licence) {
  char dir[PATH_MAX];
  char app[PATH_MAX];
  char needle[PATH_MAX];
  struct dirent *entry;
  struct stat st;
  DIR *apps;
  int found = 0;

  if(snprintf(dir, sizeof(dir), "%s/user/app", root) >= (int)sizeof(dir) ||
     !(apps=opendir(dir))) {
    return 0;
  }
  while(!found && (entry=readdir(apps))) {
    if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
       snprintf(needle, sizeof(needle), "-%s_", entry->d_name) >= (int)sizeof(needle) ||
       !strstr(licence, needle)) {
      continue;
    }
    found = snprintf(app, sizeof(app), "%s/%s", dir, entry->d_name) < (int)sizeof(app) &&
            !lstat(app, &st) && S_ISDIR(st.st_mode);
  }
  closedir(apps);
  return found;
}


static size_t
verify_orphan_licences(const char *root, int titles_listed, int outfd) {
  char dir[PATH_MAX];
  struct dirent *entry;
  DIR *licences;
  size_t findings = 0;
  size_t len;

  if(snprintf(dir, sizeof(dir), "%s/user/license", root) >= (int)sizeof(dir)) {
    return 0;
  }
  if(!(licences=opendir(dir))) {
    if(errno == ENOENT) {
      return 0;
    }
    verify_finding(outfd, "unsupported", "licences");
    return 1;
  }
  if(!titles_listed) {
    closedir(licences);
    return 0;
  }
  while((entry=readdir(licences))) {
    len = strlen(entry->d_name);
    if(strncmp(entry->d_name, "fake", 4) || strcmp(entry->d_name + len - 4, ".rif") ||
       verify_licence_named(root, entry->d_name)) {
      continue;
    }
    verify_finding(outfd, "licence_orphan", entry->d_name);
    findings++;
  }
  closedir(licences);
  return findings;
}


static size_t
verify_orphan_staging(const char *root, int outfd) {
  char dir[PATH_MAX];
  char stage[PATH_MAX];
  char app[PATH_MAX];
  struct dirent *entry;
  struct stat st;
  DIR *staging;
  size_t findings = 0;

  if(snprintf(dir, sizeof(dir), "%s/user/staging", root) >= (int)sizeof(dir)) {
    return 0;
  }
  if(!(staging=opendir(dir))) {
    if(errno == ENOENT) {
      return 0;
    }
    verify_finding(outfd, "unsupported", "staging");
    return 1;
  }
  while((entry=readdir(staging))) {
    if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
       snprintf(stage, sizeof(stage), "%s/%s", dir, entry->d_name) >= (int)sizeof(stage) ||
       lstat(stage, &st) || !S_ISDIR(st.st_mode)) {
      continue;
    }
    if(snprintf(app, sizeof(app), "%s/user/app/%s", root, entry->d_name) < (int)sizeof(app) &&
       !lstat(app, &st) && S_ISDIR(st.st_mode)) {
      continue;
    }
    verify_finding(outfd, "staging_orphan", entry->d_name);
    findings++;
  }
  closedir(staging);
  return findings;
}


static size_t
verify_space(const char *root, size_t floor, int outfd) {
  char path[PATH_MAX];
  char bytes[32];
  struct statvfs vfs;
  unsigned long long available;

  if(snprintf(path, sizeof(path), "%s/user", root) >= (int)sizeof(path) ||
     statvfs(path, &vfs)) {
    verify_finding(outfd, "unsupported", "space");
    return 1;
  }
  available = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
  if(available >= (unsigned long long)floor) {
    return 0;
  }
  snprintf(bytes, sizeof(bytes), "%llu", available);
  verify_finding(outfd, "space_below", bytes);
  return 1;
}


/**
 * verify --all [--floor N]: the checks of every installed title, then the
 * console-wide findings. A clean console answers one line. Findings are
 * answered in the order the console lists its titles.
 **/
static int
run_verify_all(const char *root, const verify_args_t *args, int outfd, int errfd) {
  char lines[VERIFY_LINES][OUT_LINE_CAP];
  char dir[PATH_MAX];
  char app[PATH_MAX];
  verify_args_t title;
  struct dirent *entry;
  struct stat st;
  size_t findings = 0;
  size_t count;
  size_t i;
  int titles_listed = 1;
  DIR *apps;

  if(snprintf(dir, sizeof(dir), "%s/user/app", root) >= (int)sizeof(dir)) {
    say(errfd, "bad_path\n");
    return 1;
  }
  if(!(apps=opendir(dir))) {
    if(errno != ENOENT) {
      titles_listed = 0;
      verify_finding(outfd, "unsupported", "titles");
      findings++;
    }
  } else {
    while((entry=readdir(apps))) {
      if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
         snprintf(app, sizeof(app), "%s/%s", dir, entry->d_name) >= (int)sizeof(app) ||
         lstat(app, &st) || !S_ISDIR(st.st_mode)) {
        continue;
      }
      memset(&title, 0, sizeof(title));
      title.title = entry->d_name;
      if(verify_title_checks(root, app, &title, lines, &count, errfd)) {
        closedir(apps);
        return 1;
      }
      for(i=0; i<count; i++) {
        if(!strncmp(lines[i], "finding ", 8)) {
          verify_title_finding(outfd, entry->d_name, lines[i]);
          findings++;
        }
      }
    }
    closedir(apps);
  }

  findings += verify_orphan_licences(root, titles_listed, outfd);
  findings += verify_orphan_staging(root, outfd);
  if(args->has_floor) {
    findings += verify_space(root, args->floor, outfd);
  }

  say(outfd, findings ? "not_whole console\n" : "whole console\n");
  return findings ? 1 : 0;
}


/**
 * verify TITLE [--size N] [--sha256 HEX] or verify --all [--floor N]: answer
 * one line per check, then whole or not_whole.
 **/
static int
run_verify(const char *root, int argc, char *const argv[], int outfd, int errfd) {
  char lines[VERIFY_LINES][OUT_LINE_CAP];
  verify_args_t args;
  char app[PATH_MAX];
  struct stat st;
  size_t count = 0;
  size_t i;
  int whole = 1;

  if(verify_parse(argc, argv, &args, errfd)) {
    return 1;
  }
  if(args.all) {
    return run_verify_all(root, &args, outfd, errfd);
  }
  if(snprintf(app, sizeof(app), "%s/user/app/%s", root, args.title) >= (int)sizeof(app)) {
    say(errfd, "bad_path\n");
    return 1;
  }
  if(lstat(app, &st) || !S_ISDIR(st.st_mode)) {
    say(outfd, "not_installed ");
    say(outfd, args.title);
    say(outfd, "\n");
    return 1;
  }
  if(refuse_protected(app, errfd)) {
    return STATUS_PROTECTED;
  }
  if(verify_title_checks(root, app, &args, lines, &count, errfd)) {
    return 1;
  }

  for(i=0; i<count; i++) {
    if(strncmp(lines[i], "ok ", 3)) {
      whole = 0;
    }
    say(outfd, lines[i]);
    say(outfd, "\n");
  }
  say(outfd, whole ? "whole " : "not_whole ");
  say(outfd, args.title);
  say(outfd, "\n");
  return whole ? 0 : 1;
}


#define TRACE_KEEP 8
#define TRACE_LIST_MAX 16
#define TRACE_NAME_MAX 32
#define TRACE_FIELD_RAW 256
#define TRACE_FIELD_OUT 128
#define TRACE_LINE_CAP 512
#define TRACE_RECORD_CAP (32UL * 1024)
#define TRACE_FIELDS_MAX 96
#define TRACE_KEY_MAX (TRACE_FIELD_OUT + 16)
#define TRACE_SECTIONS 5
#define TRACE_FREE_SLACK (16ULL * 1024ULL * 1024ULL)
#define TRACE_BOOT_SLACK 1ULL

#define TRACE_ANY 0
#define TRACE_DIRS 1
#define TRACE_FILES 2

struct trace_names {
  size_t total;
  size_t count;
  char names[TRACE_LIST_MAX][TRACE_FIELD_RAW];
};

struct trace_mounts {
  size_t total;
  size_t count;
  char targets[TRACE_LIST_MAX][TRACE_FIELD_RAW];
  char sources[TRACE_LIST_MAX][TRACE_FIELD_RAW];
};

struct trace_scan {
  struct trace_mounts mounts;
  struct trace_names titles;
  struct trace_names metadata;
  struct trace_names licences;
  char running[TRACE_LIST_MAX][PAYLOAD_NAME_MAX + 1];
};

struct trace_record {
  char *text;
  size_t len;
  int failed;
};

struct trace_field {
  char key[TRACE_KEY_MAX];
  char value[TRACE_FIELD_OUT + 1];
};

struct trace_fields {
  size_t count;
  struct trace_field items[TRACE_FIELDS_MAX];
};

static const char *const trace_counts[TRACE_SECTIONS] = {
  "mounts", "titles", "metadata", "licences", "running"
};
static const char *const trace_entries[TRACE_SECTIONS] = {
  "mount", "title", "metadata", "licence", "running"
};


static int
trace_name_ok(const char *name) {
  size_t i;
  size_t len = strlen(name);

  if(len == 0 || len > TRACE_NAME_MAX || !strcmp(name, ".") || !strcmp(name, "..")) {
    return 0;
  }
  for(i=0; i<len; i++) {
    unsigned char c = (unsigned char)name[i];

    if(c < 0x21 || c > 0x7e || c == '/' || c == '\\') {
      return 0;
    }
  }
  return 1;
}


// Keeps the smallest TRACE_LIST_MAX names in order and counts every name.
static void
trace_names_add(struct trace_names *list, const char *name) {
  size_t at = list->count;

  list->total++;
  if(list->count == TRACE_LIST_MAX) {
    if(strcmp(name, list->names[TRACE_LIST_MAX - 1]) >= 0) {
      return;
    }
    at = TRACE_LIST_MAX - 1;
  } else {
    list->count++;
  }
  while(at > 0 && strcmp(name, list->names[at - 1]) < 0) {
    snprintf(list->names[at], TRACE_FIELD_RAW, "%s", list->names[at - 1]);
    at--;
  }
  snprintf(list->names[at], TRACE_FIELD_RAW, "%s", name);
}


static void
trace_scan(struct trace_names *list, const char *dir, int want) {
  char path[PATH_MAX];
  struct dirent *ent;
  struct stat st;
  DIR *handle;

  if(!(handle=opendir(dir))) {
    return;
  }
  while((ent = readdir(handle))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >= (int)sizeof(path)) {
      continue;
    }
    if(want != TRACE_ANY) {
      if(lstat(path, &st)) {
        continue;
      }
      if(want == TRACE_DIRS && !S_ISDIR(st.st_mode)) {
        continue;
      }
      if(want == TRACE_FILES && !S_ISREG(st.st_mode)) {
        continue;
      }
    }
    trace_names_add(list, ent->d_name);
  }
  closedir(handle);
}


// Sums the regular files under path; a link is never followed.
static unsigned long long
trace_tree_bytes(const char *path) {
  char child[PATH_MAX];
  unsigned long long total = 0;
  struct dirent *ent;
  struct stat st;
  DIR *handle;

  if(lstat(path, &st)) {
    return 0;
  }
  if(S_ISREG(st.st_mode)) {
    return (unsigned long long)st.st_size;
  }
  if(!S_ISDIR(st.st_mode) || !(handle=opendir(path))) {
    return 0;
  }
  while((ent = readdir(handle))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >= (int)sizeof(child)) {
      continue;
    }
    total += trace_tree_bytes(child);
  }
  closedir(handle);
  return total;
}


static void
trace_mount_add(void *ctx, const char *target, const char *source) {
  struct trace_mounts *mounts = ctx;

  mounts->total++;
  if(mounts->count < TRACE_LIST_MAX) {
    snprintf(mounts->targets[mounts->count], TRACE_FIELD_RAW, "%s", target);
    snprintf(mounts->sources[mounts->count], TRACE_FIELD_RAW, "%s", source);
    mounts->count++;
  }
}


// Escapes what a record line cannot carry raw: spaces, controls, non-ASCII and %.
static void
trace_escape(char out[TRACE_FIELD_OUT + 1], const char *src) {
  size_t used = 0;
  size_t i;

  for(i=0; src[i]; i++) {
    unsigned char c = (unsigned char)src[i];
    char piece[4];
    size_t n = 1;

    if(c > 0x20 && c < 0x7f && c != '%') {
      piece[0] = (char)c;
    } else {
      snprintf(piece, sizeof(piece), "%%%02X", (unsigned)c);
      n = 3;
    }
    if(used + n >= TRACE_FIELD_OUT) {
      break;
    }
    memcpy(out + used, piece, n);
    used += n;
  }
  out[used] = '\0';
}


static void
trace_put(struct trace_record *record, const char *text) {
  size_t len = strlen(text);

  if(record->failed || len > TRACE_RECORD_CAP - record->len) {
    record->failed = 1;
    return;
  }
  memcpy(record->text + record->len, text, len);
  record->len += len;
  record->text[record->len] = '\0';
}


static int
trace_build(const char *root, struct trace_scan *scan, struct trace_record *record) {
  char line[TRACE_LINE_CAP];
  char path[PATH_MAX];
  char first[TRACE_FIELD_OUT + 1];
  char second[TRACE_FIELD_OUT + 1];
  unsigned long long uptime;
  unsigned long long bytes;
  struct statvfs vfs;
  size_t running;
  size_t i;
  time_t now;

  if((now=time(NULL)) == (time_t)-1 || readers_uptime(&uptime) ||
     statvfs(root, &vfs) || readers_mounts(trace_mount_add, &scan->mounts)) {
    return -1;
  }
  snprintf(path, sizeof(path), "%s/user/app", root);
  trace_scan(&scan->titles, path, TRACE_DIRS);
  snprintf(path, sizeof(path), "%s/user/appmeta", root);
  trace_scan(&scan->metadata, path, TRACE_ANY);
  snprintf(path, sizeof(path), "%s/user/license", root);
  trace_scan(&scan->licences, path, TRACE_FILES);
  running = runs_names(scan->running, TRACE_LIST_MAX);

  snprintf(line, sizeof(line), "clock %lld\n", (long long)now);
  trace_put(record, line);
  snprintf(line, sizeof(line), "uptime %llu\n", uptime);
  trace_put(record, line);
  snprintf(line, sizeof(line), "free %llu\n",
           (unsigned long long)vfs.f_bavail * vfs.f_frsize);
  trace_put(record, line);

  snprintf(line, sizeof(line), "mounts %zu\n", scan->mounts.total);
  trace_put(record, line);
  for(i=0; i<scan->mounts.count; i++) {
    trace_escape(first, scan->mounts.targets[i]);
    trace_escape(second, scan->mounts.sources[i]);
    snprintf(line, sizeof(line), "mount %s %s\n", first, second);
    trace_put(record, line);
  }

  snprintf(line, sizeof(line), "titles %zu\n", scan->titles.total);
  trace_put(record, line);
  for(i=0; i<scan->titles.count; i++) {
    snprintf(path, sizeof(path), "%s/user/app/%s", root, scan->titles.names[i]);
    bytes = trace_tree_bytes(path);
    trace_escape(first, scan->titles.names[i]);
    snprintf(line, sizeof(line), "title %s %llu\n", first, bytes);
    trace_put(record, line);
  }

  snprintf(line, sizeof(line), "metadata %zu\n", scan->metadata.total);
  trace_put(record, line);
  for(i=0; i<scan->metadata.count; i++) {
    trace_escape(first, scan->metadata.names[i]);
    snprintf(line, sizeof(line), "metadata %s\n", first);
    trace_put(record, line);
  }

  snprintf(line, sizeof(line), "licences %zu\n", scan->licences.total);
  trace_put(record, line);
  for(i=0; i<scan->licences.count; i++) {
    trace_escape(first, scan->licences.names[i]);
    snprintf(line, sizeof(line), "licence %s\n", first);
    trace_put(record, line);
  }

  snprintf(line, sizeof(line), "running %zu\n", running);
  trace_put(record, line);
  for(i=0; i<running && i<TRACE_LIST_MAX; i++) {
    snprintf(line, sizeof(line), "running %s\n", scan->running[i]);
    trace_put(record, line);
  }

  snprintf(line, sizeof(line), "boot %lld\n", (long long)now - (long long)uptime);
  trace_put(record, line);
  return record->failed ? -1 : 0;
}


static int
trace_write_file(const char *path, const char *data, size_t len) {
  size_t done = 0;
  int fd;

  if((fd=open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644)) < 0) {
    return -1;
  }
  while(done < len) {
    ssize_t put = write(fd, data + done, len - done);

    if(put < 0 && errno == EINTR) {
      continue;
    }
    if(put <= 0) {
      close(fd);
      unlink(path);
      return -1;
    }
    done += (size_t)put;
  }
  if(fsync(fd) || close(fd)) {
    unlink(path);
    return -1;
  }
  return 0;
}


// A name copied whole or not at all: a truncated name is not that name.
static int
trace_name_set(char *out, const char *name) {
  size_t len = strlen(name);

  if(len > TRACE_NAME_MAX) {
    return -1;
  }
  memcpy(out, name, len + 1);
  return 0;
}


// The order file, not file times, says which record is oldest: times can tie.
static int
trace_remember(const char *base, const char *records, const char *name) {
  char text[(TRACE_KEEP + 1) * (TRACE_NAME_MAX + 2)];
  char path[PATH_MAX];
  char tmp[PATH_MAX];
  char line[TRACE_NAME_MAX + 2];
  struct {
    size_t count;
    char names[TRACE_KEEP + 1][TRACE_NAME_MAX + 1];
  } order;
  size_t used = 0;
  FILE *file;
  size_t i;

  memset(&order, 0, sizeof(order));
  if(snprintf(path, sizeof(path), "%s/order", base) >= (int)sizeof(path)) {
    return -1;
  }
  if((file=fopen(path, "r"))) {
    while(order.count < TRACE_KEEP && fgets(line, sizeof(line), file)) {
      line[strcspn(line, "\n")] = '\0';
      if(line[0] && strcmp(line, name) && !trace_name_set(order.names[order.count], line)) {
        order.count++;
      }
    }
    fclose(file);
  }
  if(trace_name_set(order.names[order.count], name)) {
    return -1;
  }
  order.count++;

  while(order.count > TRACE_KEEP) {
    if(snprintf(path, sizeof(path), "%s/%s", records, order.names[0]) >= (int)sizeof(path)) {
      return -1;
    }
    if(unlink(path) && errno != ENOENT) {
      return -1;
    }
    memmove(order.names[0], order.names[1], (order.count - 1) * sizeof(order.names[0]));
    order.count--;
  }

  for(i=0; i<order.count; i++) {
    used += (size_t)snprintf(text + used, sizeof(text) - used, "%s\n", order.names[i]);
  }
  if(snprintf(tmp, sizeof(tmp), "%s/order.tmp", base) >= (int)sizeof(tmp)) {
    return -1;
  }
  if(trace_write_file(tmp, text, used)) {
    return -1;
  }
  if(snprintf(path, sizeof(path), "%s/order", base) >= (int)sizeof(path)) {
    unlink(tmp);
    return -1;
  }
  if(rename(tmp, path)) {
    unlink(tmp);
    return -1;
  }
  return 0;
}


// Returns 0 when stored, 1 when the name is kept and replace is not set, -1 on failure.
static int
trace_store(const char *root, const char *name, const char *text, size_t len, int replace) {
  char base[PATH_MAX];
  char records[PATH_MAX];
  char tmp[PATH_MAX];
  char final[PATH_MAX];
  struct stat st;

  if(snprintf(base, sizeof(base), "%s/data/ariel/traces", root) >= (int)sizeof(base) ||
     snprintf(records, sizeof(records), "%s/records", base) >= (int)sizeof(records) ||
     snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", base, name) >= (int)sizeof(tmp) ||
     snprintf(final, sizeof(final), "%s/%s", records, name) >= (int)sizeof(final)) {
    return -1;
  }
  if((mkdir(base, 0755) && errno != EEXIST) || (mkdir(records, 0755) && errno != EEXIST)) {
    return -1;
  }
  if(!lstat(final, &st) && !replace) {
    return 1;
  }
  if(trace_write_file(tmp, text, len) || rename(tmp, final)) {
    unlink(tmp);
    return -1;
  }
  return trace_remember(base, records, name);
}


static int
trace_capture(const char *root, struct trace_record *record) {
  struct trace_scan *scan;
  int rc;

  record->text = malloc(TRACE_RECORD_CAP + 1);
  scan = calloc(1, sizeof(*scan));
  if(!record->text || !scan) {
    free(record->text);
    free(scan);
    record->text = NULL;
    return -1;
  }
  record->len = 0;
  record->failed = 0;
  record->text[0] = '\0';
  rc = trace_build(root, scan, record);
  free(scan);
  if(rc) {
    free(record->text);
    record->text = NULL;
  }
  return rc;
}


// Returns 0 and the text, 1 when no record is kept under the path, -1 on failure.
static int
trace_read_record(const char *path, char **text) {
  struct stat st;
  size_t done = 0;
  ssize_t got;
  int fd;

  if((fd=open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0) {
    return errno == ENOENT ? 1 : -1;
  }
  if(fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > (off_t)TRACE_RECORD_CAP) {
    close(fd);
    return -1;
  }
  *text = malloc((size_t)st.st_size + 1);
  if(!*text) {
    close(fd);
    return -1;
  }
  while(done < (size_t)st.st_size) {
    got = read(fd, *text + done, (size_t)st.st_size - done);
    if(got < 0 && errno == EINTR) {
      continue;
    }
    if(got <= 0) {
      break;
    }
    done += (size_t)got;
  }
  close(fd);
  if(done < (size_t)st.st_size) {
    free(*text);
    *text = NULL;
    return -1;
  }
  (*text)[done] = '\0';
  return 0;
}


static int
trace_section(const char *word, const char *const names[]) {
  int i;

  for(i=0; i<TRACE_SECTIONS; i++) {
    if(!strcmp(word, names[i])) {
      return i;
    }
  }
  return -1;
}


static int
trace_fields_add(struct trace_fields *fields, const char *key, const char *value) {
  struct trace_field *field;

  if(fields->count == TRACE_FIELDS_MAX) {
    return -1;
  }
  field = &fields->items[fields->count++];
  snprintf(field->key, sizeof(field->key), "%s", key);
  snprintf(field->value, sizeof(field->value), "%s", value);
  return 0;
}


// Each list opens with its count; the lines after it are its entries. Clock and uptime are never compared.
static int
trace_fields_parse(const char *text, struct trace_fields *fields) {
  char line[TRACE_LINE_CAP];
  char key[TRACE_KEY_MAX];
  int counted[TRACE_SECTIONS];
  const char *cursor = text;
  const char *end;
  char *word;
  char *rest;
  char *value;
  int section;
  size_t len;

  memset(counted, 0, sizeof(counted));
  while(*cursor) {
    end = strchr(cursor, '\n');
    len = end ? (size_t)(end - cursor) : strlen(cursor);
    if(len >= sizeof(line)) {
      return -1;
    }
    memcpy(line, cursor, len);
    line[len] = '\0';
    cursor += end ? len + 1 : len;

    word = line;
    rest = strchr(line, ' ');
    if(rest) {
      *rest++ = '\0';
    } else {
      rest = line + len;
    }
    if(!strcmp(word, "clock") || !strcmp(word, "uptime")) {
      continue;
    }
    if(!strcmp(word, "free") || !strcmp(word, "boot")) {
      if(trace_fields_add(fields, word, rest)) {
        return -1;
      }
      continue;
    }
    section = trace_section(word, trace_counts);
    if(section >= 0 && !counted[section]) {
      counted[section] = 1;
      if(trace_fields_add(fields, word, rest)) {
        return -1;
      }
      continue;
    }
    section = trace_section(word, trace_entries);
    if(section < 0) {
      continue;
    }
    if(section <= 1) {
      value = strchr(rest, ' ');
      if(!value) {
        continue;
      }
      *value++ = '\0';
    } else {
      value = "present";
    }
    if(snprintf(key, sizeof(key), "%s %s", word, rest) >= (int)sizeof(key)) {
      return -1;
    }
    if(trace_fields_add(fields, key, value)) {
      return -1;
    }
  }
  return 0;
}


static const struct trace_field *
trace_field_find(const struct trace_fields *fields, const char *key) {
  size_t i;

  for(i=0; i<fields->count; i++) {
    if(!strcmp(fields->items[i].key, key)) {
      return &fields->items[i];
    }
  }
  return NULL;
}


// Free space moves with the record's own writes, and boot is derived from two whole-second readings.
static int
trace_moved(const char *key, const char *before, const char *after) {
  unsigned long long a = strtoull(before, NULL, 10);
  unsigned long long b = strtoull(after, NULL, 10);
  unsigned long long slack;

  if(!strcmp(key, "free")) {
    slack = TRACE_FREE_SLACK;
  } else if(!strcmp(key, "boot")) {
    slack = TRACE_BOOT_SLACK;
  } else {
    return strcmp(before, after) != 0;
  }
  return (a > b ? a - b : b - a) > slack;
}


static void
trace_say_change(int outfd, const char *key, const char *before, const char *after) {
  say(outfd, key);
  say(outfd, " ");
  say(outfd, before);
  say(outfd, " ");
  say(outfd, after);
  say(outfd, "\n");
}


static size_t
trace_fields_diff(const struct trace_fields *before, const struct trace_fields *after, int outfd) {
  const struct trace_field *old;
  const struct trace_field *now;
  size_t changed = 0;
  size_t i;

  for(i=0; i<before->count; i++) {
    old = &before->items[i];
    now = trace_field_find(after, old->key);
    if(!now) {
      trace_say_change(outfd, old->key, old->value, "absent");
      changed++;
    } else if(trace_moved(old->key, old->value, now->value)) {
      trace_say_change(outfd, old->key, old->value, now->value);
      changed++;
    }
  }
  for(i=0; i<after->count; i++) {
    if(!trace_field_find(before, after->items[i].key)) {
      trace_say_change(outfd, after->items[i].key, "absent", after->items[i].value);
      changed++;
    }
  }
  return changed;
}


static int
run_trace_list(const char *root, int argc, char *const argv[], int outfd, int errfd) {
  char dir[PATH_MAX];
  struct trace_names *names;
  size_t i;

  if(argc > 2) {
    say(errfd, argv[2][0] == '-' ? "bad_option\n" : "bad_argument\n");
    return 1;
  }
  names = calloc(1, sizeof(*names));
  if(!names) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  snprintf(dir, sizeof(dir), "%s/data/ariel/traces/records", root);
  trace_scan(names, dir, TRACE_FILES);
  for(i=0; i<names->count; i++) {
    say(outfd, "record ");
    say(outfd, names->names[i]);
    say(outfd, "\n");
  }
  free(names);
  return 0;
}


static int
run_trace_diff(const char *root, int argc, char *const argv[], int outfd, int errfd) {
  char path[PATH_MAX];
  struct trace_record now;
  struct trace_fields *before = NULL;
  struct trace_fields *after = NULL;
  char *kept = NULL;
  size_t changed = 0;
  char count[32];
  int rc = 0;

  if(argc < 3) {
    say(errfd, "missing_operand\n");
    return 1;
  }
  if(argv[2][0] == '-') {
    say(errfd, "bad_option\n");
    return 1;
  }
  if(!trace_name_ok(argv[2])) {
    say(errfd, "bad_path\n");
    return 1;
  }
  if(argc > 3) {
    say(errfd, argv[3][0] == '-' ? "bad_option\n" : "bad_argument\n");
    return 1;
  }

  snprintf(path, sizeof(path), "%s/data/ariel/traces/records/%s", root, argv[2]);
  rc = trace_read_record(path, &kept);
  if(rc == 1) {
    say(errfd, "trace_missing ");
    say(errfd, argv[2]);
    say(errfd, "\n");
    return 95;
  }
  if(rc || trace_capture(root, &now)) {
    free(kept);
    say(errfd, "operation_failed\n");
    return 1;
  }

  before = calloc(1, sizeof(*before));
  after = calloc(1, sizeof(*after));
  if(!before || !after || trace_fields_parse(kept, before) ||
     trace_fields_parse(now.text, after)) {
    rc = 1;
  } else {
    changed = trace_fields_diff(before, after, outfd);
    if(changed == 0) {
      say(outfd, "trace_unchanged\n");
    } else {
      snprintf(count, sizeof(count), "changed %zu\n", changed);
      say(outfd, count);
    }
  }
  free(kept);
  free(now.text);
  free(before);
  free(after);
  if(rc) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  return 0;
}


static int
run_trace(platform_t *platform, int argc, char *const argv[], int outfd, int errfd) {
  struct trace_record record;
  int replace = 0;
  int rc;
  int i;

  if(argc >= 2 && !strcmp(argv[1], "--list")) {
    return run_trace_list(platform->fs_root, argc, argv, outfd, errfd);
  }
  if(argc >= 2 && !strcmp(argv[1], "--diff")) {
    return run_trace_diff(platform->fs_root, argc, argv, outfd, errfd);
  }
  if(argc < 2) {
    say(errfd, "missing_operand\n");
    return 1;
  }
  if(argv[1][0] == '-') {
    say(errfd, "bad_option\n");
    return 1;
  }
  for(i=2; i<argc; i++) {
    if(!strcmp(argv[i], "--replace") && !replace) {
      replace = 1;
    } else if(argv[i][0] == '-') {
      say(errfd, "bad_option\n");
      return 1;
    } else {
      say(errfd, "bad_argument\n");
      return 1;
    }
  }
  if(!trace_name_ok(argv[1])) {
    say(errfd, "bad_path\n");
    return 1;
  }

  if(trace_capture(platform->fs_root, &record)) {
    say(errfd, "operation_failed\n");
    return 1;
  }

  rc = trace_store(platform->fs_root, argv[1], record.text, record.len, replace);
  if(rc == 1) {
    free(record.text);
    say(errfd, "trace_exists ");
    say(errfd, argv[1]);
    say(errfd, "\n");
    return 96;
  }
  if(rc) {
    free(record.text);
    say(errfd, "operation_failed\n");
    return 1;
  }

  say_bytes(outfd, record.text, record.len);
  free(record.text);
  say(outfd, "recorded ");
  say(outfd, argv[1]);
  say(outfd, "\n");
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
  return !strcmp(name, "ps") || !strcmp(name, "sysinfo") ||
         !strcmp(name, "ifconfig") || table_command(name);
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
  if(!strcmp(argv[0], "ps") || !strcmp(argv[0], "sysinfo") ||
     !strcmp(argv[0], "ifconfig")) {
    rc = readers_run(1, count, plain, outfd, errfd, status);
  } else {
    *status = run_table(1, count, plain, outfd, errfd);
  }
  free(plain);
  return rc;
}


static int
runner_dispatch(platform_t *platform, int argc, char *const argv[], int outfd,
                int errfd, runner_session_t *session, int *status) {
  size_t i;

  if(argc < 1) {
    return -1;
  }

  if(json_command(argv[0]) && json_requested(argc, argv)) {
    return run_json(argc, argv, outfd, errfd, status);
  }

  if(argc == 1 && !strcmp(argv[0], "pwd")) {
    char line[PATH_MAX + 2];

    snprintf(line, sizeof(line), "%s\n",
             (session && session->cwd) ? session->cwd : "/");
    say(outfd, line);
    *status = 0;
    return 0;
  }

  if(table_command(argv[0])) {
    *status = run_table(0, argc, argv, outfd, errfd);
    return 0;
  }

  if(argc >= 1 && !strcmp(argv[0], "cd")) {
    return run_cd(session, argc, argv, errfd, status);
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
    *status = run_sleep(platform, argc, argv, errfd);
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

  if(!strcmp(argv[0], "verify")) {
    *status = run_verify(platform->fs_root, argc, argv, outfd, errfd);
    return 0;
  }

  if(!strcmp(argv[0], "trace")) {
    *status = run_trace(platform, argc, argv, outfd, errfd);
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


int
runner_run(platform_t *platform, int argc, char *const argv[], int outfd,
           int errfd, runner_session_t *session, int *status) {
  runner_session_t *previous = session_current;
  int rc;

  session_current = session;
  rc = runner_dispatch(platform, argc, argv, outfd, errfd, session, status);
  session_current = previous;
  return rc;
}
