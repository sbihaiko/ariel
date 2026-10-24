/* Ariel: the answers of the diagnostic commands that both builds share.

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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "answer.h"
#include "diagnostics.h"
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
diagnostics_say_sysinfo(int json, int fd, const char *sysname,
                        const char *release, const char *machine,
                        unsigned long long uptime_seconds,
                        unsigned long long memory_total,
                        unsigned long long memory_free) {
  char line[192];

  if(json) {
    say(fd, "{\"sysname\":");
    json_say_string(fd, sysname);
    say(fd, ",\"release\":");
    json_say_string(fd, release);
    say(fd, ",\"machine\":");
    json_say_string(fd, machine);
    snprintf(line, sizeof(line),
             ",\"uptime_seconds\":%llu,\"memory_total_bytes\":%llu,"
             "\"memory_free_bytes\":%llu}\n",
             uptime_seconds, memory_total, memory_free);
    say(fd, line);
    return;
  }

  say(fd, "uname ");
  say(fd, sysname);
  say(fd, " ");
  say(fd, release);
  say(fd, " ");
  say(fd, machine);
  say(fd, "\n");

  snprintf(line, sizeof(line), "uptime %llu\n", uptime_seconds);
  say(fd, line);
  snprintf(line, sizeof(line), "memory %llu %llu\n", memory_total, memory_free);
  say(fd, line);
}


void
diagnostics_say_log(int fd, const char *data, size_t len) {
  answer_t answer;
  const char *end = data + len;
  const char *nul = memchr(data, '\0', len);
  const char *line = data;

  // A kernel log may arrive NUL padded; the text ends at the first NUL.
  if(nul) {
    end = nul;
  }

  answer_init(&answer, fd, SIZE_MAX);
  while(line < end) {
    const char *newline = memchr(line, '\n', (size_t)(end - line));
    const char *stop = newline ? newline : end;

    // The kernel ends its lines with a carriage return on some consoles.
    while(stop > line && stop[-1] == '\r') {
      stop--;
    }
    answer_line(&answer, line, (size_t)(stop - line));
    line = newline ? newline + 1 : end;
  }
  answer_done(&answer);
}
