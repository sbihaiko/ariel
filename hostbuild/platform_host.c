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
#elif defined(__linux__)
// close_range(2) is reached through syscall(3), which glibc declares for
// the default feature set.
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#endif
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

/** One past the largest descriptor the child sweeps, read before any fork. **/
static long fd_limit = 1024;


/**
 * Mark a descriptor close-on-exec, so a payload never inherits the
 * listener, another client's connection or a file another thread holds.
 **/
static int
set_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD);

  if(flags < 0) {
    return -1;
  }

  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}


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

  if(set_cloexec(srvfd)) {
    perror("fcntl");
    close(srvfd);
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

  if(connfd >= 0 && set_cloexec(connfd)) {
    close(connfd);
    return -1;
  }

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
 * Close every descriptor above the standard ones except keep. This runs in
 * the child after fork, so it allocates nothing and takes no lock: close()
 * everywhere, or one close_range() syscall where the platform has it. It is
 * the second line of defence behind close-on-exec: another thread can accept
 * a connection between the fork and exec, so the child inherits that
 * descriptor before it is marked close-on-exec.
 *
 * The sweep covers every descriptor number the process can hold. A
 * descriptor above it would survive into the payload and keep another
 * client's connection open after Ariel finished it.
 **/
static void
close_extra_fds(int keep) {
#if defined(SYS_close_range)
  int covered = 1;

  if(keep > 3 &&
     syscall(SYS_close_range, 3u, (unsigned int)keep - 1u, 0u) != 0) {
    covered = 0;
  }
  if(syscall(SYS_close_range, (unsigned int)keep + 1u, ~0u, 0u) != 0) {
    covered = 0;
  }
  if(covered) {
    return;
  }

  // A kernel without close_range(2), or one that refused it: sweep every
  // descriptor number instead. fd_limit was read before any thread could
  // fork, so an accepted connection cannot hide above the sweep.
#endif

  {
    long fd;

    for(fd = 3; fd < fd_limit; fd++) {
      if(fd != keep) {
        close((int)fd);
      }
    }
  }
}


/**
 * The child never became the payload. Report errno to the parent through
 * the close-on-exec error pipe and leave with a status the parent ignores:
 * a payload that genuinely exits 127 writes nothing to that pipe.
 **/
static void
child_fail(int errfd, int err) {
  ssize_t n;

  do {
    n = write(errfd, &err, sizeof(err));
  } while(n < 0 && errno == EINTR);

  (void)n;
  _exit(127);
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
  int errpipe[2] = {-1, -1};
  int wait_status;
  int exec_failed = 0;
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

  if((filefd=open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700)) < 0) {
    goto out;
  }

  if(write_all(filefd, bytes, size)) {
    // Keep filefd for the cleanup below: a failed write must not leak the
    // descriptor or the unlinked temporary file's storage.
    goto out;
  }

  if(close(filefd)) {
    filefd = -1;
    goto out;
  }
  filefd = -1;

  if((nullfd=open("/dev/null", O_RDONLY | O_CLOEXEC)) < 0) {
    goto out;
  }

  // A successful exec closes the write end, so the parent reading the read
  // end distinguishes "never became the payload" from a payload that
  // exits 127 on its own.
  if(pipe(errpipe) < 0) {
    goto out;
  }
  if(set_cloexec(errpipe[0]) || set_cloexec(errpipe[1])) {
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
    struct sigaction dfl;

    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(SIGPIPE, &dfl, NULL);

    close(errpipe[0]);
    if(dup2(nullfd, STDIN_FILENO) < 0 ||
       dup2(outfd, STDOUT_FILENO) < 0 ||
       dup2(outfd, STDERR_FILENO) < 0) {
      child_fail(errpipe[1], errno);
    }

    // A payload inherits only its standard descriptors: a client whose
    // connection Ariel already finished reaches end of stream while a long
    // payload runs.
    close_extra_fds(errpipe[1]);

    execv(path, argv);
    child_fail(errpipe[1], errno);
  }

  close(errpipe[1]);
  errpipe[1] = -1;

  {
    int child_err = 0;
    ssize_t n;

    do {
      n = read(errpipe[0], &child_err, sizeof(child_err));
    } while(n < 0 && errno == EINTR);

    close(errpipe[0]);
    errpipe[0] = -1;

    exec_failed = n > 0;
  }

  while(waitpid(pid, &wait_status, 0) < 0) {
    if(errno != EINTR) {
      goto out;
    }
  }

  if(exec_failed) {
    goto out;
  }

  if(WIFEXITED(wait_status)) {
    *status = WEXITSTATUS(wait_status);
    rc = 0;
  } else if(WIFSIGNALED(wait_status)) {
    *status = 128 + WTERMSIG(wait_status);
    rc = 0;
  }

out:
  if(errpipe[0] >= 0) {
    close(errpipe[0]);
  }
  if(errpipe[1] >= 0) {
    close(errpipe[1]);
  }
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


/**
 * One past the highest descriptor number this process can hold. sysconf
 * reports RLIMIT_NOFILE; on macOS the kernel's per-process cap bounds the
 * numbers that are actually handed out, and the smaller of the two is the
 * bound the child has to sweep.
 **/
static long
open_max(void) {
  long limit = sysconf(_SC_OPEN_MAX);

#if defined(__APPLE__)
  int maxfiles = 0;
  size_t size = sizeof(maxfiles);

  if(sysctlbyname("kern.maxfilesperproc", &maxfiles, &size, NULL, 0) == 0 &&
     maxfiles > 2 && (limit < 0 || (long)maxfiles < limit)) {
    limit = maxfiles;
  }
#endif

  if(limit > (long)INT_MAX) {
    limit = (long)INT_MAX;
  }

  return limit;
}


platform_t *
platform_host(const char *dir) {
  long limit;

  snprintf(run_dir, sizeof(run_dir), "%s", dir);

  // Read the descriptor bound here, before any connection thread exists:
  // the child after fork sweeps descriptors up to it and may not call
  // anything that reads the process environment safely. Neither limit is
  // shortened further; a descriptor above the sweep would survive into the
  // payload.
  limit = open_max();
  if(limit > 2) {
    fd_limit = limit;
  }

  vcontroller_start();
  return &host_platform;
}
