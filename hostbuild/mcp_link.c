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

#define REPLY_STEP 8192
#define REPLY_LIMIT (256UL * 1024)
#define REFUSED_STATUS 70

static int
connect_to(const struct mcp_console *console, char *why, size_t why_len) {
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
  snprintf(service, sizeof(service), "%d", console->port);
  rc = getaddrinfo(console->host, service, &hints, &found);
  if(rc) {
    snprintf(why, why_len, "resolve %s: %s", console->host, gai_strerror(rc));
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
    snprintf(why, why_len, "connect %s:%d: %s", console->host, console->port,
             strerror(err));
    return -1;
  }

  limit.tv_sec = console->timeout_s;
  limit.tv_usec = 0;
  if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) ||
     setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit))) {
    snprintf(why, why_len, "set the timeout on %s:%d: %s", console->host,
             console->port, strerror(errno));
    close(fd);
    return -1;
  }
  return fd;
}


static int
send_text(int fd, const char *text) {
  size_t len = strlen(text);

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


static void
first_word(const char *text, size_t len, char *word, size_t cap) {
  size_t n = 0;

  while(n < len && text[n] != '\n' && n + 1 < cap) {
    word[n] = text[n];
    n++;
  }
  word[n] = '\0';
}


int
mcp_exchange(const struct mcp_console *console, const char *command,
             struct mcp_answer *answer, char *why, size_t why_len) {
  char *reply;
  size_t cap = REPLY_STEP;
  size_t used = 0;
  size_t start;
  int fd;

  fd = connect_to(console, why, why_len);
  if(fd < 0) {
    return -1;
  }
  reply = malloc(cap);
  if(!reply) {
    snprintf(why, why_len, "out of memory for the console's answer");
    close(fd);
    return -1;
  }

  if(send_text(fd, "auth ") || send_text(fd, console->token) ||
     send_text(fd, "\n") || send_text(fd, command) || send_text(fd, "\n")) {
    snprintf(why, why_len, "console %s:%d closed the connection",
             console->host, console->port);
    goto failed;
  }

  for(;;) {
    ssize_t n;

    if(cap - used < 2) {
      char *grown;

      if(cap >= REPLY_LIMIT) {
        snprintf(why, why_len, "console %s:%d answered more than %lu bytes",
                 console->host, console->port, REPLY_LIMIT);
        goto failed;
      }
      grown = realloc(reply, cap + REPLY_STEP);
      if(!grown) {
        snprintf(why, why_len, "out of memory for the console's answer");
        goto failed;
      }
      reply = grown;
      cap += REPLY_STEP;
    }
    n = recv(fd, reply + used, cap - used - 1, 0);
    if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      snprintf(why, why_len, "console %s:%d did not answer within %d s",
               console->host, console->port, console->timeout_s);
      goto failed;
    }
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      break;
    }
    used += (size_t)n;
  }
  close(fd);
  reply[used] = '\0';

  if(used == 0) {
    snprintf(why, why_len, "console %s:%d closed the connection without answering",
             console->host, console->port);
    free(reply);
    return -1;
  }
  start = used - 1;
  if(reply[start] != '\n') {
    snprintf(why, why_len, "console %s:%d answered without an exit status",
             console->host, console->port);
    free(reply);
    return -1;
  }
  while(start > 0 && reply[start - 1] != '\n') {
    start--;
  }
  if(strncmp(reply + start, "exit ", 5)) {
    snprintf(why, why_len, "console %s:%d answered without an exit status",
             console->host, console->port);
    free(reply);
    return -1;
  }

  reply[start] = '\0';
  answer->text = reply;
  answer->len = start;
  answer->status = atoi(reply + start + 5);
  return 0;

failed:
  close(fd);
  free(reply);
  return -1;
}


int
mcp_probe(const struct mcp_console *console, char *why, size_t why_len) {
  struct mcp_answer answer;
  char word[64];
  int status;

  if(mcp_exchange(console, "pwd", &answer, why, why_len)) {
    return -1;
  }
  status = answer.status;
  first_word(answer.text, answer.len, word, sizeof(word));
  free(answer.text);

  if(status == 0) {
    return 0;
  }
  if(status == REFUSED_STATUS) {
    snprintf(why, why_len, "console %s:%d refused the token: exit %d",
             console->host, console->port, status);
    return -1;
  }
  snprintf(why, why_len, "console %s:%d answered \"%s\" with exit %d",
           console->host, console->port, word, status);
  return -1;
}
