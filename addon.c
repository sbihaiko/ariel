/* Ariel: the addon directory and the refusal of an addon by name.

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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "addon.h"
#include "answer.h"
#include "fileops.h"
#include "sha256.h"
#include "store.h"

#define ADDON_ABI 1
#define ADDON_ARGS_MAX 8
#define ADDON_TIMEOUT_MS 10000
#define ADDON_OUTPUT_MAX (64UL * 1024)
#define ADDON_ELF_MAX (4UL * 1024 * 1024)
#define MANIFEST_MAX 512
#define MANIFEST_FILE "manifest"
#define ADDON_ELF_FILE "elf"
#define ADDON_RESULT_PREFIX "/data/addon-"

#ifdef ARIEL_HOST_BUILD
#define PLATFORM_TAG "host"
#else
#define PLATFORM_TAG "ps5"
#endif

#define KEY_NAME     1
#define KEY_ARGS     2
#define KEY_ABI      4
#define KEY_PLATFORM 8
#define KEY_ALL      (KEY_NAME | KEY_ARGS | KEY_ABI | KEY_PLATFORM)

typedef enum {
  ADDON_OK,
  ADDON_REFUSED,
  ADDON_MISSING,
  ADDON_MALFORMED,
  ADDON_UNREADABLE
} addon_verdict_t;

typedef struct {
  long least;
  long most;
  char sha256[SHA256_HEX_LEN + 1];
} addon_manifest_t;

static char addons_dir[PATH_MAX];


void
addon_init(const char *state_dir) {
  snprintf(addons_dir, sizeof(addons_dir), "%s/addons", state_dir);
}


static int
same(const char *text, size_t len, const char *word) {
  return len == strlen(word) && !memcmp(text, word, len);
}


/** Decimal digits only, at most digits of them, into out. **/
static int
number(const char *text, size_t len, size_t digits, long *out) {
  long value = 0;
  size_t i;

  if(len == 0 || len > digits) {
    return 0;
  }
  for(i=0; i<len; i++) {
    if(text[i] < '0' || text[i] > '9') {
      return 0;
    }
    value = value * 10 + (text[i] - '0');
  }
  *out = value;
  return 1;
}


/**
 * Judge the text of a manifest for the addon named addon. It holds four
 * `key value` lines, each key once and nothing else. The ABI is checked
 * before the platform, and the first mismatch names its field.
 **/
static addon_verdict_t
parse_manifest(const char *addon, const char *text, size_t len,
               const char **field, addon_manifest_t *manifest) {
  const char *end = text + len;
  const char *line = text;
  const char *eol;
  const char *space;
  const char *value;
  size_t keylen;
  size_t vlen;
  int seen = 0;
  int bit;
  int platform_match = 0;
  long abi = 0;
  long least = 0;
  long most = 0;

  if(len == 0 || text[len - 1] != '\n') {
    return ADDON_MALFORMED;
  }
  while(line < end) {
    eol = memchr(line, '\n', (size_t)(end - line));
    space = memchr(line, ' ', (size_t)(eol - line));
    if(!space) {
      return ADDON_MALFORMED;
    }
    keylen = (size_t)(space - line);
    value = space + 1;
    vlen = (size_t)(eol - value);
    if(vlen == 0) {
      return ADDON_MALFORMED;
    }

    if(same(line, keylen, "name")) {
      bit = KEY_NAME;
      if(!same(value, vlen, addon)) {
        return ADDON_MALFORMED;
      }
    } else if(same(line, keylen, "args")) {
      const char *dash = memchr(value, '-', vlen);

      bit = KEY_ARGS;
      if(!dash ||
         !number(value, (size_t)(dash - value), 2, &least) ||
         !number(dash + 1, (size_t)(eol - dash - 1), 2, &most) ||
         most > ADDON_ARGS_MAX || least > most) {
        return ADDON_MALFORMED;
      }
    } else if(same(line, keylen, "abi")) {
      bit = KEY_ABI;
      if(!number(value, vlen, 6, &abi)) {
        return ADDON_MALFORMED;
      }
    } else if(same(line, keylen, "platform")) {
      bit = KEY_PLATFORM;
      if(same(value, vlen, "ps5") || same(value, vlen, "host")) {
        platform_match = same(value, vlen, PLATFORM_TAG);
      } else {
        return ADDON_MALFORMED;
      }
    } else {
      return ADDON_MALFORMED;
    }

    if(seen & bit) {
      return ADDON_MALFORMED;
    }
    seen |= bit;
    line = eol + 1;
  }

  if(seen != KEY_ALL) {
    return ADDON_MALFORMED;
  }
  if(abi != ADDON_ABI) {
    *field = "abi";
    return ADDON_REFUSED;
  }
  if(!platform_match) {
    *field = "platform";
    return ADDON_REFUSED;
  }
  manifest->least = least;
  manifest->most = most;
  return ADDON_OK;
}


/** Read and judge the manifest of the addon named addon under addons. **/
static addon_verdict_t
judge(int addons, const char *addon, const char **field,
      addon_manifest_t *manifest) {
  struct stat st;
  char text[MANIFEST_MAX + 1];
  unsigned char digest[SHA256_DIGEST_LEN];
  size_t len = 0;
  ssize_t n = 0;
  sha256_t hash;
  int adir;
  int mfd;

  adir = openat(addons, addon, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(adir < 0) {
    return ADDON_MISSING;
  }
  mfd = openat(adir, MANIFEST_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  close(adir);
  if(mfd < 0) {
    return errno == ENOENT ? ADDON_MISSING : ADDON_MALFORMED;
  }
  if(fstat(mfd, &st) || !S_ISREG(st.st_mode)) {
    close(mfd);
    return ADDON_MALFORMED;
  }

  while(len <= MANIFEST_MAX &&
        (n = read(mfd, text + len, MANIFEST_MAX + 1 - len)) > 0) {
    len += (size_t)n;
  }
  close(mfd);
  if(n < 0 || len > MANIFEST_MAX) {
    return ADDON_MALFORMED;
  }

  sha256_init(&hash);
  sha256_update(&hash, text, len);
  sha256_final(&hash, digest);
  sha256_hex(digest, manifest->sha256);
  return parse_manifest(addon, text, len, field, manifest);
}


static addon_verdict_t
judge_named(const char *addon, const char **field, addon_manifest_t *manifest) {
  addon_verdict_t verdict;
  int addons;

  addons = open(addons_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(addons < 0) {
    return errno == ENOENT ? ADDON_MISSING : ADDON_UNREADABLE;
  }
  verdict = judge(addons, addon, field, manifest);
  close(addons);
  return verdict;
}


static int
status_of(addon_verdict_t verdict) {
  switch(verdict) {
  case ADDON_OK:
    return 0;
  case ADDON_MISSING:
    return 91;
  case ADDON_MALFORMED:
    return 92;
  default:
    return 1;
  }
}


static void
say_verdict(answer_t *answer, const char *addon, addon_verdict_t verdict,
            const char *field) {
  char line[128];

  switch(verdict) {
  case ADDON_OK:
    snprintf(line, sizeof(line), "addon %s ok", addon);
    break;
  case ADDON_REFUSED:
    snprintf(line, sizeof(line), "addon_refused %s %s", addon, field);
    break;
  case ADDON_MISSING:
    snprintf(line, sizeof(line), "manifest_missing %s", addon);
    break;
  case ADDON_MALFORMED:
    snprintf(line, sizeof(line), "manifest_malformed %s", addon);
    break;
  case ADDON_UNREADABLE:
    snprintf(line, sizeof(line), "operation_failed");
    break;
  }
  answer_line(answer, line, strlen(line));
}


void
addon_check(int fd, const char *name) {
  answer_t answer;
  addon_verdict_t verdict;
  addon_manifest_t manifest;
  const char *field = "";
  char exit_line[16];

  answer_init(&answer, fd, SIZE_MAX);
  if(!store_name_valid(name)) {
    answer_line(&answer, "bad_name", strlen("bad_name"));
    answer_line(&answer, "exit 1", strlen("exit 1"));
    return;
  }

  verdict = judge_named(name, &field, &manifest);
  say_verdict(&answer, name, verdict, field);
  snprintf(exit_line, sizeof(exit_line), "exit %d", status_of(verdict));
  answer_line(&answer, exit_line, strlen(exit_line));
}


void
addon_list(int fd) {
  answer_t answer;
  addon_verdict_t verdict;
  addon_manifest_t manifest;
  const char *field;
  struct dirent *ent;
  DIR *dir;
  int addons;

  answer_init(&answer, fd, SIZE_MAX);
  addons = open(addons_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(addons < 0 && errno == ENOENT) {
    answer_line(&answer, "exit 0", strlen("exit 0"));
    return;
  }
  if(addons < 0 || !(dir = fdopendir(addons))) {
    if(addons >= 0) {
      close(addons);
    }
    say_verdict(&answer, "", ADDON_UNREADABLE, "");
    answer_line(&answer, "exit 1", strlen("exit 1"));
    return;
  }

  while((ent = readdir(dir))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(!store_name_valid(ent->d_name)) {
      answer_line(&answer, "bad_name", strlen("bad_name"));
      continue;
    }
    field = "";
    verdict = judge(dirfd(dir), ent->d_name, &field, &manifest);
    say_verdict(&answer, ent->d_name, verdict, field);
  }
  closedir(dir);

  answer_done(&answer);
  answer_line(&answer, "exit 0", strlen("exit 0"));
}


static int
elf_open(const char *addon, size_t *size) {
  struct stat st;
  int addons;
  int adir;
  int fd;

  addons = open(addons_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(addons < 0) {
    return -1;
  }
  adir = openat(addons, addon, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  close(addons);
  if(adir < 0) {
    return -1;
  }
  fd = openat(adir, ADDON_ELF_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  close(adir);
  if(fd < 0) {
    return -1;
  }
  if(fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
     (uint64_t)st.st_size > ADDON_ELF_MAX) {
    close(fd);
    return -1;
  }
  *size = (size_t)st.st_size;
  return fd;
}


static int
read_elf(const char *addon, unsigned char **bytes, size_t *size) {
  size_t done = 0;
  ssize_t n;
  int fd;

  fd = elf_open(addon, size);
  if(fd < 0) {
    return -1;
  }
  *bytes = malloc(*size);
  if(!*bytes) {
    close(fd);
    return -1;
  }
  while(done < *size) {
    n = read(fd, *bytes + done, *size - done);
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      free(*bytes);
      *bytes = NULL;
      close(fd);
      return -1;
    }
    done += (size_t)n;
  }
  close(fd);
  return 0;
}


static uint64_t
platform_ms(platform_t *platform) {
  struct timespec now;

  platform->clock(platform, &now);
  return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}


static void
pause_briefly(void) {
  struct timespec pause = {0, 20 * 1000 * 1000};

  (void)nanosleep(&pause, NULL);
}


static void
stop_and_reap(platform_t *platform, pid_t pid) {
  int status;

  (void)platform->spawn_kill(platform, pid);
  while(platform->spawn_poll(platform, pid, &status) == 0) {
    pause_briefly();
  }
}


enum {
  PUMP_IDLE,
  PUMP_CLOSED,
  PUMP_BIG,
  PUMP_FAILED
};

/** Copy what the addon has written so far into to, counting it in total. **/
static int
pump(int from, int to, size_t *total) {
  char buf[4096];
  ssize_t n;
  ssize_t w;
  size_t done;

  for(;;) {
    n = read(from, buf, sizeof(buf));
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n < 0) {
      return errno == EAGAIN ? PUMP_IDLE : PUMP_FAILED;
    }
    if(n == 0) {
      return PUMP_CLOSED;
    }
    *total += (size_t)n;
    if(*total > ADDON_OUTPUT_MAX) {
      return PUMP_BIG;
    }
    done = 0;
    while(done < (size_t)n) {
      w = write(to, buf + done, (size_t)n - done);
      if(w < 0 && errno == EINTR) {
        continue;
      }
      if(w <= 0) {
        return PUMP_FAILED;
      }
      done += (size_t)w;
    }
  }
}


/** Watch one run to its end, cutting it at deadline. Returns its outcome. **/
static addon_run_t
watch(platform_t *platform, pid_t pid, uint64_t deadline, int from, int to) {
  size_t total = 0;
  int status = 0;
  int got = 0;
  int pumped;

  for(;;) {
    pumped = pump(from, to, &total);
    if(pumped == PUMP_BIG) {
      stop_and_reap(platform, pid);
      return ADDON_TOO_LARGE;
    }
    if(pumped == PUMP_FAILED) {
      stop_and_reap(platform, pid);
      return ADDON_FAILED;
    }
    got = platform->spawn_poll(platform, pid, &status);
    if(got < 0) {
      stop_and_reap(platform, pid);
      return ADDON_FAILED;
    }
    if(got) {
      break;
    }
    if(platform_ms(platform) >= deadline) {
      stop_and_reap(platform, pid);
      return ADDON_TIMED_OUT;
    }
    pause_briefly();
  }

  pumped = pump(from, to, &total);
  if(pumped == PUMP_BIG) {
    return ADDON_TOO_LARGE;
  }
  if(pumped == PUMP_FAILED || status != 0) {
    return ADDON_FAILED;
  }
  return ADDON_RAN;
}


int
addon_accept(int fd, const char *name, int argc, char hex[65]) {
  addon_manifest_t manifest;
  addon_verdict_t verdict;
  answer_t answer;
  const char *field = "";
  char exit_line[16];
  size_t size;
  int elf;

  answer_init(&answer, fd, SIZE_MAX);
  if(!store_name_valid(name)) {
    answer_line(&answer, "bad_name", strlen("bad_name"));
    answer_line(&answer, "exit 1", strlen("exit 1"));
    return 0;
  }

  verdict = judge_named(name, &field, &manifest);
  if(verdict == ADDON_OK && (argc < manifest.least || argc > manifest.most)) {
    verdict = ADDON_REFUSED;
    field = "args";
  }
  if(verdict == ADDON_OK) {
    elf = elf_open(name, &size);
    if(elf < 0) {
      verdict = ADDON_UNREADABLE;
    } else {
      close(elf);
      memcpy(hex, manifest.sha256, sizeof(manifest.sha256));
      return 1;
    }
  }

  say_verdict(&answer, name, verdict, field);
  snprintf(exit_line, sizeof(exit_line), "exit %d", status_of(verdict));
  answer_line(&answer, exit_line, strlen(exit_line));
  return 0;
}


addon_run_t
addon_run(platform_t *platform, const char *name, int argc,
          char *const args[], char *result, size_t size) {
  char *argv[ADDON_ARGS_MAX + 2];
  approval_facts_t facts;
  char file[PATH_MAX];
  addon_run_t outcome = ADDON_FAILED;
  unsigned char *elf = NULL;
  size_t elf_size = 0;
  uint64_t deadline;
  int pipefd[2] = {-1, -1};
  int opened = -1;
  int created = 0;
  pid_t pid = 0;
  int i;

  if(read_elf(name, &elf, &elf_size)) {
    return ADDON_FAILED;
  }
  if(snprintf(result, size, "%s%s-%llu", ADDON_RESULT_PREFIX, name,
              (unsigned long long)platform_ms(platform)) >= (int)size) {
    goto done;
  }
  if(snprintf(file, sizeof(file), "%s%s", platform->fs_root, result) >=
     (int)sizeof(file)) {
    goto done;
  }

  memset(&facts, 0, sizeof(facts));
  if(fileops_write_check(platform->fs_root, file, &facts) != FILEOPS_OK ||
     strcmp(facts.kind, "absent") ||
     fileops_write_open(platform->fs_root, file, &facts, &opened)) {
    goto done;
  }
  created = 1;
  if(fcntl(opened, F_SETFD, FD_CLOEXEC) || pipe(pipefd) ||
     fcntl(pipefd[0], F_SETFL, O_NONBLOCK) ||
     fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) ||
     fcntl(pipefd[1], F_SETFD, FD_CLOEXEC)) {
    goto done;
  }

  argv[0] = (char*)name;
  for(i=0; i<argc; i++) {
    argv[i + 1] = args[i];
  }
  argv[argc + 1] = NULL;

  deadline = platform_ms(platform) + ADDON_TIMEOUT_MS;
  if(platform->spawn_start_isolated(platform, elf, elf_size, argv, pipefd[1],
                                    &pid)) {
    outcome = ADDON_SPAWN_FAILED;
    goto done;
  }
  close(pipefd[1]);
  pipefd[1] = -1;

  outcome = watch(platform, pid, deadline, pipefd[0], opened);

done:
  if(opened >= 0) {
    close(opened);
  }
  if(created && outcome != ADDON_RAN) {
    (void)fileops_discard(platform->fs_root, file);
  }
  if(pipefd[0] >= 0) {
    close(pipefd[0]);
  }
  if(pipefd[1] >= 0) {
    close(pipefd[1]);
  }
  free(elf);
  return outcome;
}
