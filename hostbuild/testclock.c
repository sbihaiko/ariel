/* Ariel host build: the test clock, a host-only test aid.

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
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "testclock.h"

/**
 * One wake pipe per connection is enough: at most four connections are
 * served at once, and each waiter owns its pipe alone.
 **/
#define WAKE_MAX 16

/**
 * A settle waits at most this long in real time. It only bounds a broken
 * scenario: a waiter that settles at all does so within microseconds.
 **/
#define SETTLE_REAL_MS 3000L

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t idle_changed = PTHREAD_COND_INITIALIZER;
static uint64_t clock_ms;
static int wake_reads[WAKE_MAX];
static int wake_writes[WAKE_MAX];
static int wake_idles[WAKE_MAX];


static void
wake_clear(void) {
  int i;

  for(i=0; i<WAKE_MAX; i++) {
    wake_reads[i] = -1;
    wake_writes[i] = -1;
    wake_idles[i] = 0;
  }
}


static int
nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);

  if(flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}


void
testclock_init(void) {
  pthread_mutex_lock(&lock);
  clock_ms = 0;
  wake_clear();
  pthread_mutex_unlock(&lock);
}


void
testclock_now(struct timespec *now) {
  uint64_t ms;

  pthread_mutex_lock(&lock);
  ms = clock_ms;
  pthread_mutex_unlock(&lock);

  now->tv_sec = (time_t)(ms / 1000);
  now->tv_nsec = (long)(ms % 1000) * 1000000L;
}


void
testclock_advance(long ms) {
  int i;

  if(ms <= 0) {
    return;
  }

  pthread_mutex_lock(&lock);
  clock_ms += (uint64_t)ms;

  // A full pipe is already readable, so a dropped byte loses nothing. No
  // waiter is idle until it has seen the new time.
  for(i=0; i<WAKE_MAX; i++) {
    if(wake_writes[i] >= 0) {
      ssize_t n = write(wake_writes[i], "w", 1);
      (void)n;
    }
    wake_idles[i] = 0;
  }
  pthread_cond_broadcast(&idle_changed);
  pthread_mutex_unlock(&lock);
}


int
testclock_wake_new(void) {
  int pipefd[2];
  int fd = -1;
  int i;

  if(pipe(pipefd)) {
    return -1;
  }

  if(nonblocking(pipefd[0]) || nonblocking(pipefd[1])) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }

  pthread_mutex_lock(&lock);
  for(i=0; i<WAKE_MAX; i++) {
    if(wake_reads[i] < 0) {
      wake_reads[i] = pipefd[0];
      wake_writes[i] = pipefd[1];
      fd = pipefd[0];
      break;
    }
  }
  pthread_mutex_unlock(&lock);

  if(fd < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
  }

  return fd;
}


void
testclock_wake_close(int fd) {
  int i;

  pthread_mutex_lock(&lock);
  for(i=0; i<WAKE_MAX; i++) {
    if(wake_reads[i] == fd) {
      close(wake_reads[i]);
      close(wake_writes[i]);
      wake_reads[i] = -1;
      wake_writes[i] = -1;
      wake_idles[i] = 0;
      break;
    }
  }
  pthread_cond_broadcast(&idle_changed);
  pthread_mutex_unlock(&lock);
}


void
testclock_wake_idle(int wake, int fd, int idle) {
  struct pollfd pfd[2];
  nfds_t nfds = 1;
  int i;

  pfd[0].fd = wake;
  pfd[0].events = POLLIN;
  pfd[0].revents = 0;

  if(fd >= 0) {
    pfd[1].fd = fd;
    pfd[1].events = POLLIN;
    pfd[1].revents = 0;
    nfds = 2;
  }

  pthread_mutex_lock(&lock);
  for(i=0; i<WAKE_MAX; i++) {
    if(wake_reads[i] == wake) {
      // Under the lock no advance can slip in between the check and the
      // mark, so an idle waiter has seen the current time.
      wake_idles[i] = idle && poll(pfd, nfds, 0) == 0;
      break;
    }
  }
  pthread_cond_broadcast(&idle_changed);
  pthread_mutex_unlock(&lock);
}


/** Count the wake pipes and the idle waiters. The caller holds the lock. **/
static void
wake_count(int *pipes, int *idle) {
  int i;

  *pipes = 0;
  *idle = 0;
  for(i=0; i<WAKE_MAX; i++) {
    if(wake_reads[i] >= 0) {
      (*pipes)++;
      *idle += wake_idles[i];
    }
  }
}


/** Wait until exactly n wake pipes exist and every waiter is idle. **/
static void
settle(int n, char *reply, size_t size) {
  struct timespec until;
  int pipes;
  int idle;

  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_sec += SETTLE_REAL_MS / 1000;

  pthread_mutex_lock(&lock);
  wake_count(&pipes, &idle);
  while(pipes != n || idle != n) {
    if(pthread_cond_timedwait(&idle_changed, &lock, &until) == ETIMEDOUT) {
      wake_count(&pipes, &idle);
      break;
    }
    wake_count(&pipes, &idle);
  }
  pthread_mutex_unlock(&lock);

  if(pipes == n && idle == n) {
    snprintf(reply, size, "settled %d", n);
  } else {
    snprintf(reply, size, "unsettled %d %d", pipes, idle);
  }
}


int
testclock_handle_line(const char *line, char *reply, size_t size) {
  static const char advance[] = "clock advance ";
  static const char settled[] = "clock settle ";
  unsigned long long now;
  char *end = NULL;
  long value;

  if(!strncmp(line, settled, sizeof(settled) - 1)) {
    errno = 0;
    value = strtol(line + sizeof(settled) - 1, &end, 10);
    if(errno || !end || *end || value < 0 || value > WAKE_MAX) {
      snprintf(reply, size, "unsettled bad count");
      return 1;
    }
    settle((int)value, reply, size);
    return 1;
  }

  if(strncmp(line, advance, sizeof(advance) - 1)) {
    return 0;
  }

  errno = 0;
  value = strtol(line + sizeof(advance) - 1, &end, 10);

  if(!errno && end && !*end && value >= 0) {
    testclock_advance(value);
  }

  pthread_mutex_lock(&lock);
  now = (unsigned long long)clock_ms;
  pthread_mutex_unlock(&lock);

  snprintf(reply, size, "clock %llu", now);
  return 1;
}
