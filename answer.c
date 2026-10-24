/* Ariel: one bounded answer of the agent port.

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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "answer.h"
#include "json.h"


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


void
say_cut(int fd, size_t shown, size_t total) {
  char line[64];

  snprintf(line, sizeof(line), "truncated %zu of %zu\n", shown, total);
  say(fd, line);
}


void
answer_init(answer_t *answer, int fd, size_t limit) {
  answer->fd = fd;
  answer->limit = limit;
  answer->shown = 0;
  answer->total = 0;
  answer->bytes = 0;
  answer->full = 0;
}


// A line that does not fit stops the content, so the lines shown are a prefix.
int
answer_admit(answer_t *answer, size_t len) {
  answer->total++;
  if(answer->full) {
    return 0;
  }
  if(answer->shown >= answer->limit || len + 1 > CONTENT_CAP - answer->bytes) {
    answer->full = 1;
    return 0;
  }
  answer->shown++;
  answer->bytes += len + 1;
  return 1;
}


void
answer_line(answer_t *answer, const char *text, size_t len) {
  if(answer_admit(answer, len)) {
    put(answer->fd, text, len);
    say(answer->fd, "\n");
  }
}


void
answer_json(answer_t *answer, const char *key, const char *value) {
  size_t klen = strlen(key);
  size_t len = klen + 5 + json_format_string(NULL, 0, value);

  if(answer_admit(answer, len)) {
    put(answer->fd, "{\"", 2);
    put(answer->fd, key, klen);
    put(answer->fd, "\":", 2);
    json_say_string(answer->fd, value);
    say(answer->fd, "}\n");
  }
}


void
answer_path(answer_t *answer, int json, const char *path) {
  if(json) {
    answer_json(answer, "path", path);
  } else {
    answer_line(answer, path, strlen(path));
  }
}


void
answer_done(answer_t *answer) {
  if(answer->shown < answer->total) {
    say_cut(answer->fd, answer->shown, answer->total);
  }
}
