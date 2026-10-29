/* Ariel host build: the MCP server's link to the console's agent port.

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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "mcp_link.h"

#define REPLY_MAX 4096
#define REFUSED_STATUS 70

static int
connect_to(const char *host, int port, int timeout_s, char *why, size_t why_len) {
  struct addrinfo hints;
  struct addrinfo *found;
  struct addrinfo *ai;
  struct timeval limit;
  char service[8];
  int err = 0;
  int fd = -1;
  int rc;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  snprintf(service, sizeof(service), "%d", port);
  rc = getaddrinfo(host, service, &hints, &found);
  if(rc) {
    snprintf(why, why_len, "resolve %s: %s", host, gai_strerror(rc));
    return -1;
  }

  for(ai = found; ai && fd < 0; ai = ai->ai_next) {
    int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

    if(s < 0) {
      err = errno;
      continue;
    }
    if(connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
      fd = s;
    } else {
      err = errno;
      close(s);
    }
  }
  freeaddrinfo(found);

  if(fd < 0) {
    snprintf(why, why_len, "connect %s:%d: %s", host, port, strerror(err));
    return -1;
  }

  limit.tv_sec = timeout_s;
  limit.tv_usec = 0;
  if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) ||
     setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit))) {
    snprintf(why, why_len, "set the timeout on %s:%d: %s", host, port,
             strerror(errno));
    close(fd);
    return -1;
  }
  return fd;
}


static int
send_all(int fd, const char *text, size_t len) {
  while(len) {
    ssize_t n = send(fd, text, len, 0);

    if(n <= 0) {
      return -1;
    }
    text += n;
    len -= (size_t)n;
  }
  return 0;
}


static const char *
last_line(const char *reply, size_t used) {
  size_t start = used - 1;

  while(start > 0 && reply[start - 1] != '\n') {
    start--;
  }
  return reply + start;
}


static int
reply_complete(const char *reply, size_t used) {
  return used > 0 && reply[used - 1] == '\n' &&
         !strncmp(last_line(reply, used), "exit ", 5);
}


static void
first_word(const char *reply, size_t used, char *word, size_t len) {
  size_t n = 0;

  while(n < used && reply[n] != '\n' && n + 1 < len) {
    word[n] = reply[n];
    n++;
  }
  word[n] = '\0';
}


int
mcp_probe(const char *host, int port, const char *token, int timeout_s,
          char *why, size_t why_len) {
  char request[64];
  char reply[REPLY_MAX];
  char word[64];
  size_t used = 0;
  int fd;
  int status;

  fd = connect_to(host, port, timeout_s, why, why_len);
  if(fd < 0) {
    return -1;
  }

  snprintf(request, sizeof(request), "auth %s\npwd\n", token);
  if(send_all(fd, request, strlen(request))) {
    snprintf(why, why_len, "console %s:%d closed the connection", host, port);
    close(fd);
    return -1;
  }

  for(;;) {
    ssize_t n = recv(fd, reply + used, sizeof(reply) - 1 - used, 0);

    if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      snprintf(why, why_len, "console %s:%d did not answer within %d s",
               host, port, timeout_s);
      close(fd);
      return -1;
    }
    if(n <= 0) {
      break;
    }
    used += (size_t)n;
    if(reply_complete(reply, used) || used == sizeof(reply) - 1) {
      break;
    }
  }
  close(fd);

  if(!reply_complete(reply, used)) {
    if(used == 0) {
      snprintf(why, why_len, "console %s:%d closed the connection without answering",
               host, port);
    } else {
      snprintf(why, why_len, "console %s:%d answered without an exit status",
               host, port);
    }
    return -1;
  }

  status = atoi(last_line(reply, used) + 5);
  if(status == 0) {
    return 0;
  }
  if(status == REFUSED_STATUS) {
    snprintf(why, why_len, "console %s:%d refused the token: exit %d",
             host, port, status);
    return -1;
  }
  first_word(reply, used, word, sizeof(word));
  snprintf(why, why_len, "console %s:%d answered \"%s\" with exit %d",
           host, port, word, status);
  return -1;
}
