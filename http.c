/* Ariel: a plain HTTP GET that reports each reply instead of following it.

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
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "http.h"

#define HTTP_PREFIX "http://"
#define HTTP_HEAD_MAX 8192
#define HTTP_PATH_MAX 1024
#define HTTP_TIMEOUT_S 15

struct body {
  size_t total;
  size_t max;
  http_sink_t sink;
  void *ctx;
};

static int
authority_ok(const char *text, size_t len) {
  size_t i;
  size_t colon = len;

  if(!len) {
    return 0;
  }

  for(i=0; i<len; i++) {
    if(text[i] == ':') {
      colon = i;
      break;
    }
  }

  if(!colon || colon > HTTP_HOST_MAX) {
    return 0;
  }

  for(i=0; i<colon; i++) {
    char c = text[i];
    if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '.' || c == '-')) {
      return 0;
    }
  }

  if(colon == len) {
    return 1;
  }

  if(len - colon - 1 < 1 || len - colon - 1 > 5) {
    return 0;
  }

  for(i=colon+1; i<len; i++) {
    if(text[i] < '0' || text[i] > '9') {
      return 0;
    }
  }

  return 1;
}


int
http_url_host(const char *url, char *host, size_t size) {
  const char *start = url + strlen(HTTP_PREFIX);
  const char *end;
  size_t len;

  if(strncmp(url, HTTP_PREFIX, strlen(HTTP_PREFIX))) {
    return -1;
  }

  end = strchr(start, '/');
  len = end ? (size_t)(end - start) : strlen(start);

  if(!authority_ok(start, len) || len + 1 > size) {
    return -1;
  }

  memcpy(host, start, len);
  host[len] = '\0';
  return 0;
}


static int
path_of(const char *url, char *path, size_t size) {
  const char *slash = strchr(url + strlen(HTTP_PREFIX), '/');

  if(!slash) {
    slash = "/";
  }

  if(strlen(slash) + 1 > size || strlen(slash) >= HTTP_PATH_MAX) {
    return -1;
  }

  snprintf(path, size, "%s", slash);
  return 0;
}


static int
connect_to(const char *authority) {
  char host[HTTP_HOST_MAX + 1];
  char port[8] = "80";
  struct addrinfo hints;
  struct addrinfo *found;
  struct addrinfo *ai;
  struct timeval timeout;
  const char *colon;
  int fd = -1;

  colon = strchr(authority, ':');
  // A host or port that does not fit is refused, never truncated.
  if(colon) {
    if(snprintf(host, sizeof(host), "%.*s", (int)(colon - authority),
                authority) >= (int)sizeof(host) ||
       snprintf(port, sizeof(port), "%s", colon + 1) >= (int)sizeof(port)) {
      return -1;
    }
  } else if(snprintf(host, sizeof(host), "%s", authority) >= (int)sizeof(host)) {
    return -1;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if(getaddrinfo(host, port, &hints, &found)) {
    return -1;
  }

  for(ai=found; ai; ai=ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if(fd < 0) {
      continue;
    }

    timeout.tv_sec = HTTP_TIMEOUT_S;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if(!connect(fd, ai->ai_addr, ai->ai_addrlen)) {
      break;
    }

    close(fd);
    fd = -1;
  }

  freeaddrinfo(found);
  return fd;
}


static int
send_all(int fd, const char *text, size_t len) {
  size_t sent = 0;

  while(sent < len) {
    ssize_t n = send(fd, text + sent, len - sent, 0);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    sent += (size_t)n;
  }

  return 0;
}


static int
deliver(struct body *body, const unsigned char *data, size_t len) {
  if(len > body->max - body->total) {
    return -1;
  }

  body->total += len;
  if(!len) {
    return 0;
  }

  return body->sink(body->ctx, data, len);
}


static int
header_value(const char *head, size_t len, const char *name, char *out,
             size_t size) {
  size_t name_len = strlen(name);
  size_t start;
  size_t i;

  out[0] = '\0';

  for(i=0; i+1 < len; i++) {
    if(head[i] == '\r' && head[i+1] == '\n') {
      break;
    }
  }

  for(start=i+2; start < len; ) {
    size_t eol = start;
    size_t vlen;
    size_t vstart;

    while(eol < len && !(head[eol] == '\r' && eol + 1 < len &&
                         head[eol+1] == '\n')) {
      eol++;
    }

    if(eol - start > name_len + 1 && !strncasecmp(head + start, name, name_len) &&
       head[start + name_len] == ':') {
      vstart = start + name_len + 1;
      while(vstart < eol && (head[vstart] == ' ' || head[vstart] == '\t')) {
        vstart++;
      }
      vlen = eol - vstart;
      if(vlen + 1 > size) {
        return -1;
      }
      memcpy(out, head + vstart, vlen);
      out[vlen] = '\0';
      return 0;
    }

    start = eol + 2;
  }

  return 0;
}


static int
parse_head(const char *head, size_t len, int *status, char *location,
           size_t size) {
  const char *space;
  int code = 0;
  size_t i;

  if(len < 12 || memcmp(head, "HTTP/", 5)) {
    return -1;
  }

  space = memchr(head, ' ', len);
  if(!space || (size_t)(space - head) + 4 > len) {
    return -1;
  }

  for(i=1; i<=3; i++) {
    if(space[i] < '0' || space[i] > '9') {
      return -1;
    }
    code = code * 10 + (space[i] - '0');
  }

  if(code < 100 || code > 599) {
    return -1;
  }

  *status = code;
  return header_value(head, len, "Location", location, size);
}


int
http_fetch(const char *url, size_t max, http_sink_t sink, void *ctx,
           int *status, char *location, size_t size) {
  char authority[HTTP_HOST_MAX + 8];
  char path[HTTP_PATH_MAX];
  char request[HTTP_PATH_MAX + HTTP_HOST_MAX + 256];
  char head[HTTP_HEAD_MAX];
  unsigned char chunk[4096];
  struct body body;
  size_t head_len = 0;
  int headed = 0;
  int fd;
  int rc = -1;

  if(http_url_host(url, authority, sizeof(authority)) ||
     path_of(url, path, sizeof(path))) {
    return -1;
  }

  if((fd=connect_to(authority)) < 0) {
    return -1;
  }

  // HTTP/1.0 keeps the reply unchunked and closes it at the end of the body.
  snprintf(request, sizeof(request),
           "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
           path, authority);

  body.total = 0;
  body.max = max;
  body.sink = sink;
  body.ctx = ctx;

  if(send_all(fd, request, strlen(request))) {
    goto out;
  }

  for(;;) {
    ssize_t n = read(fd, chunk, sizeof(chunk));

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      goto out;
    }

    if(n == 0) {
      break;
    }

    if(headed) {
      if(deliver(&body, chunk, (size_t)n)) {
        goto out;
      }
      continue;
    }

    if((size_t)n > sizeof(head) - head_len) {
      goto out;
    }
    memcpy(head + head_len, chunk, (size_t)n);
    head_len += (size_t)n;

    {
      const char *end = NULL;
      size_t i;

      for(i=0; i + 4 <= head_len; i++) {
        if(!memcmp(head + i, "\r\n\r\n", 4)) {
          end = head + i;
          break;
        }
      }

      if(!end) {
        continue;
      }

      if(parse_head(head, (size_t)(end - head), status, location, size)) {
        goto out;
      }

      headed = 1;
      if(deliver(&body, (const unsigned char *)end + 4,
                 head_len - (size_t)(end + 4 - head))) {
        goto out;
      }
    }
  }

  rc = headed ? 0 : -1;

out:
  close(fd);
  return rc;
}
