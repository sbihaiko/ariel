/* Ariel host build: the platform port for the host operating system.

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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "platform.h"
#include "vcontroller.h"


static int
host_listen(platform_t *self, uint16_t port) {
  struct sockaddr_in addr;
  int optval = 1;
  int srvfd;

  (void)self;

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
    perror("setsockopt");
    close(srvfd);
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&addr, sizeof(addr))) {
    perror("bind");
    close(srvfd);
    return -1;
  }

  if(listen(srvfd, 5)) {
    perror("listen");
    close(srvfd);
    return -1;
  }

  return srvfd;
}


static int
host_accept(platform_t *self, int srvfd) {
  int connfd;

  (void)self;

  do {
    connfd = accept(srvfd, NULL, NULL);
  } while(connfd < 0 && errno == EINTR);

  return connfd;
}


static void
host_clock(platform_t *self, struct timespec *now) {
  (void)self;

  clock_gettime(CLOCK_MONOTONIC, now);
}


static int
host_approval_request(platform_t *self, const approval_facts_t *facts,
                      char *id, size_t idlen) {
  (void)self;

  return vcontroller_request(facts, id, idlen);
}


static platform_t host_platform = {
  .listen = host_listen,
  .accept = host_accept,
  .clock = host_clock,
  .approval_request = host_approval_request,
};


platform_t *
platform_host(void) {
  vcontroller_start();
  return &host_platform;
}
