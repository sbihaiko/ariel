/* Ariel host build: the agent protocol.

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
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "token.h"

/**
 * The agent port bounds: a line is at most 1 KiB, and auth and the command
 * each have a deadline. A line over the limit and a missed deadline are the
 * same failure here: no line was read.
 **/
#define LINE_LIMIT          1024
#define AUTH_DEADLINE_MS    5000L
#define COMMAND_DEADLINE_MS 5000L


static void
write_all(int fd, const char *buf, size_t len) {
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


static long
millis_left(platform_t *platform, const struct timespec *start, long budget) {
  struct timespec now;
  long elapsed;

  platform->clock(platform, &now);
  elapsed  = (now.tv_sec - start->tv_sec) * 1000L;
  elapsed += (now.tv_nsec - start->tv_nsec) / 1000000L;

  return budget - elapsed;
}


/**
 * Read one line of at most LINE_LIMIT bytes, without the line ending.
 * Returns the length, -1 when the connection ended or the deadline passed,
 * or -2 when the line is too long.
 **/
static int
read_line(platform_t *platform, int fd, char *buf, size_t size,
          long budget_ms) {
  struct timespec start;
  size_t len = 0;

  platform->clock(platform, &start);

  while(1) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    long left = millis_left(platform, &start, budget_ms);
    char c;
    ssize_t n;
    int rc;

    if(left <= 0) {
      return -1;
    }

    rc = poll(&pfd, 1, (int)left);
    if(rc < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(rc == 0) {
      return -1;
    }

    n = read(fd, &c, 1);
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(n == 0) {
      return -1;
    }

    if(c == '\n') {
      if(len > 0 && buf[len - 1] == '\r') {
        len--;
      }
      buf[len] = '\0';
      return (int)len;
    }

    if(len + 1 >= size) {
      return -2;
    }
    buf[len++] = c;
  }
}


static int
authenticate(platform_t *platform, int fd, const char *token) {
  char candidate[TOKEN_LEN];
  char line[LINE_LIMIT + 1];
  int len;

  len = read_line(platform, fd, line, sizeof(line), AUTH_DEADLINE_MS);
  if(len != 5 + TOKEN_HEX_LEN || strncmp(line, "auth ", 5)) {
    return 0;
  }

  memcpy(candidate, line + 5, TOKEN_HEX_LEN);
  candidate[TOKEN_HEX_LEN] = '\0';

  return token_equal(candidate, token);
}


void
agent_serve(platform_t *platform, int fd, const char *token) {
  static const char auth_failed[] = "exit 70\n";
  static const char unknown[] = "unknown_command\nexit 1\n";
  char line[LINE_LIMIT + 1];

  if(!authenticate(platform, fd, token)) {
    write_all(fd, auth_failed, sizeof(auth_failed) - 1);
    return;
  }

  // Exactly one command per connection. This tracer knows no commands, so
  // every one of them answers unknown_command.
  (void)read_line(platform, fd, line, sizeof(line), COMMAND_DEADLINE_MS);
  write_all(fd, unknown, sizeof(unknown) - 1);
}
