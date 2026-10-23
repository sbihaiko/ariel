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

#if defined(__APPLE__)
// macOS hides mkdtemp behind _DARWIN_C_SOURCE once _POSIX_C_SOURCE is
// defined, and a run's bytes go in a fresh directory only Ariel can read.
#define _DARWIN_C_SOURCE 1
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "platform.h"
#include "vcontroller.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/** The directory a run's bytes are written to before they are executed. **/
static char run_dir[PATH_MAX];

/**
 * The payload loader uses process-wide state, so one run at a time. On the
 * host that state is simply the temporary file and the child process.
 **/
static pthread_mutex_t spawn_lock = PTHREAD_MUTEX_INITIALIZER;


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


static int
write_all(int fd, const unsigned char *buf, size_t len) {
  while(len > 0) {
    ssize_t n = write(fd, buf, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    buf += n;
    len -= (size_t)n;
  }
  return 0;
}


/**
 * The host has no exec from memory, so the verified bytes go to a fresh
 * file inside a directory only Ariel can read, run from there and the
 * file and directory go away after the payload exits.
 **/
static int
host_spawn(platform_t *self, const unsigned char *bytes, size_t size,
           char *const argv[], int outfd, int *status) {
  char dir[PATH_MAX];
  char path[PATH_MAX];
  int wait_status;
  int have_dir = 0;
  int filefd = -1;
  int nullfd = -1;
  int rc = -1;
  pid_t pid;

  (void)self;

  pthread_mutex_lock(&spawn_lock);

  path[0] = '\0';

  if(snprintf(dir, sizeof(dir), "%s/payload-XXXXXX", run_dir) >=
     (int)sizeof(dir) || !mkdtemp(dir)) {
    goto out;
  }
  have_dir = 1;

  if(snprintf(path, sizeof(path), "%s/payload", dir) >= (int)sizeof(path)) {
    goto out;
  }

  if((filefd=open(path, O_WRONLY | O_CREAT | O_EXCL, 0700)) < 0) {
    goto out;
  }

  if(write_all(filefd, bytes, size) || close(filefd)) {
    filefd = -1;
    goto out;
  }
  filefd = -1;

  if((nullfd=open("/dev/null", O_RDONLY)) < 0) {
    goto out;
  }

  pid = fork();
  if(pid < 0) {
    goto out;
  }

  if(pid == 0) {
    // Only async-signal-safe calls between fork and exec. The server
    // ignores SIGPIPE, and an ignored signal stays ignored across exec,
    // so the payload gets the default disposition back.
    signal(SIGPIPE, SIG_DFL);
    if(dup2(nullfd, STDIN_FILENO) < 0 ||
       dup2(outfd, STDOUT_FILENO) < 0 ||
       dup2(outfd, STDERR_FILENO) < 0) {
      _exit(127);
    }
    execv(path, argv);
    _exit(127);
  }

  while(waitpid(pid, &wait_status, 0) < 0) {
    if(errno != EINTR) {
      goto out;
    }
  }

  if(WIFEXITED(wait_status)) {
    *status = WEXITSTATUS(wait_status);
    rc = 0;
  } else if(WIFSIGNALED(wait_status)) {
    *status = 128 + WTERMSIG(wait_status);
    rc = 0;
  }

out:
  if(filefd >= 0) {
    close(filefd);
  }
  if(path[0]) {
    unlink(path);
  }
  if(have_dir) {
    rmdir(dir);
  }
  if(nullfd >= 0) {
    close(nullfd);
  }

  pthread_mutex_unlock(&spawn_lock);
  return rc;
}


static platform_t host_platform = {
  .listen = host_listen,
  .accept = host_accept,
  .clock = host_clock,
  .approval_request = host_approval_request,
  .spawn = host_spawn,
};


platform_t *
platform_host(const char *dir) {
  snprintf(run_dir, sizeof(run_dir), "%s", dir);
  vcontroller_start();
  return &host_platform;
}
