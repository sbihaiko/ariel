/* Ariel host build: the MCP server's check of a console, one line each way.

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
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "mcp_check.h"

#define REPLY_MAX 65536

static int
connect_within(int fd, const struct sockaddr *addr, socklen_t len, int timeout) {
  struct pollfd pfd;
  socklen_t errlen = sizeof(int);
  int flags = fcntl(fd, F_GETFL, 0);
  int err = 0;

  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if(connect(fd, addr, len) && errno != EINPROGRESS) {
    return -1;
  }

  pfd.fd = fd;
  pfd.events = POLLOUT;
  if(poll(&pfd, 1, timeout * 1000) != 1) {
    errno = ETIMEDOUT;
    return -1;
  }
  if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen)) {
    return -1;
  }
  if(err) {
    errno = err;
    return -1;
  }

  fcntl(fd, F_SETFL, flags);
  return 0;
}


static int
connect_to(const char *host, const char *port, int timeout, FILE *err) {
  struct addrinfo hints;
  struct addrinfo *found;
  struct addrinfo *ai;
  struct timeval tv;
  int status;
  int last = 0;
  int fd = -1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  status = getaddrinfo(host, port, &hints, &found);
  if(status) {
    fprintf(err, "ariel-mcp: cannot reach %s:%s: %s\n", host, port,
            gai_strerror(status));
    return -1;
  }

  tv.tv_sec = timeout;
  tv.tv_usec = 0;
  for(ai = found; ai && fd < 0; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if(fd < 0) {
      last = errno;
      continue;
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if(connect_within(fd, ai->ai_addr, ai->ai_addrlen, timeout)) {
      last = errno;
      close(fd);
      fd = -1;
    }
  }
  freeaddrinfo(found);

  if(fd < 0) {
    fprintf(err, "ariel-mcp: cannot reach %s:%s: %s\n", host, port,
            strerror(last));
  }
  return fd;
}


int
mcp_check(const char *host, const char *port, const char *token, int timeout,
          FILE *out, FILE *err) {
  char request[128];
  char reply[REPLY_MAX];
  char *exit_line = NULL;
  char *uname_line = NULL;
  char *line;
  char *next;
  size_t got = 0;
  size_t eol;
  size_t ulen;
  ssize_t n;
  int fd;

  signal(SIGPIPE, SIG_IGN);
  fd = connect_to(host, port, timeout, err);
  if(fd < 0) {
    return 1;
  }

  snprintf(request, sizeof(request), "auth %s\nsysinfo\n", token);
  if(send(fd, request, strlen(request), 0) != (ssize_t)strlen(request)) {
    fprintf(err, "ariel-mcp: cannot send to %s:%s: %s\n", host, port,
            strerror(errno));
    close(fd);
    return 1;
  }
  shutdown(fd, SHUT_WR);

  for(;;) {
    n = recv(fd, reply + got, REPLY_MAX - 1 - got, 0);
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n < 0) {
      fprintf(err, "ariel-mcp: no reply from %s:%s: %s\n", host, port,
              strerror(errno));
      close(fd);
      return 1;
    }
    if(n == 0) {
      break;
    }
    got += (size_t)n;
    if(got == REPLY_MAX - 1) {
      break;
    }
  }
  close(fd);
  reply[got] = '\0';

  for(line=reply; *line; line=next) {
    next = strchr(line, '\n');
    next = next ? next + 1 : line + strlen(line);
    if(!strncmp(line, "exit ", 5)) {
      exit_line = line;
    } else if(!strncmp(line, "uname ", 6)) {
      uname_line = line;
    }
  }

  if(!exit_line) {
    fprintf(err, "ariel-mcp: check failed: %s:%s closed without an exit line\n",
            host, port);
    return 1;
  }

  eol = strcspn(exit_line, "\r\n");
  if(eol == 6 && !strncmp(exit_line, "exit 0", 6)) {
    if(uname_line) {
      ulen = strcspn(uname_line + 6, "\r\n");
      fprintf(out, "console %s:%s (%.*s)\n", host, port, (int)ulen,
              uname_line + 6);
    } else {
      fprintf(out, "console %s:%s\n", host, port);
    }
    return 0;
  }
  if(eol == 7 && !strncmp(exit_line, "exit 70", 7)) {
    fprintf(err, "ariel-mcp: check failed: %s:%s refused the token: exit 70\n",
            host, port);
    return 1;
  }
  fprintf(err, "ariel-mcp: check failed: %s:%s answered %.*s\n", host, port,
          (int)eol, exit_line);
  return 1;
}
