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
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "addon.h"
#include "answer.h"
#include "store.h"

#define ADDON_ABI 1
#define ADDON_ARGS_MAX 8
#define MANIFEST_MAX 512
#define MANIFEST_FILE "manifest"

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
               const char **field) {
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
      long least;
      long most;

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
  return ADDON_OK;
}


/** Read and judge the manifest of the addon named addon under addons. **/
static addon_verdict_t
judge(int addons, const char *addon, const char **field) {
  struct stat st;
  char text[MANIFEST_MAX + 1];
  size_t len = 0;
  ssize_t n = 0;
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
  return parse_manifest(addon, text, len, field);
}


static addon_verdict_t
judge_named(const char *addon, const char **field) {
  addon_verdict_t verdict;
  int addons;

  addons = open(addons_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(addons < 0) {
    return errno == ENOENT ? ADDON_MISSING : ADDON_UNREADABLE;
  }
  verdict = judge(addons, addon, field);
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
  const char *field = "";
  char exit_line[16];

  answer_init(&answer, fd, SIZE_MAX);
  if(!store_name_valid(name)) {
    answer_line(&answer, "bad_name", strlen("bad_name"));
    answer_line(&answer, "exit 1", strlen("exit 1"));
    return;
  }

  verdict = judge_named(name, &field);
  say_verdict(&answer, name, verdict, field);
  snprintf(exit_line, sizeof(exit_line), "exit %d", status_of(verdict));
  answer_line(&answer, exit_line, strlen(exit_line));
}


void
addon_list(int fd) {
  answer_t answer;
  addon_verdict_t verdict;
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
    verdict = judge(dirfd(dir), ent->d_name, &field);
    say_verdict(&answer, ent->d_name, verdict, field);
  }
  closedir(dir);

  answer_done(&answer);
  answer_line(&answer, "exit 0", strlen("exit 0"));
}
