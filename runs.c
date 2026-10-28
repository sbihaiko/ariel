/* Ariel: payloads that run in the background.

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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "runs.h"
#include "store.h"

struct run {
  int running;
  char name[PAYLOAD_NAME_MAX + 1];
  char sha256[65];
  platform_t *platform;
  pid_t pid;
  uint64_t deadline_ms;
};

// One mutex covers the table; a running slot belongs to its reaper.
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct run runs[RUNS_MAX];


static uint64_t
platform_ms(platform_t *platform) {
  struct timespec now;

  platform->clock(platform, &now);
  return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}


static void
pause_briefly(void) {
  struct timespec pause = {0, 20 * 1000 * 1000};

  (void)nanosleep(&pause, NULL);
}


static void
release(struct run *run) {
  pthread_mutex_lock(&lock);
  run->running = 0;
  pthread_mutex_unlock(&lock);
}


static void
stop_and_reap(platform_t *platform, pid_t pid) {
  int status;

  (void)platform->spawn_kill(platform, pid);
  while(platform->spawn_poll(platform, pid, &status) == 0) {
    pause_briefly();
  }
}


/** Watch one run until it exits, cutting it at its deadline. **/
static void *
reaper(void *arg) {
  struct run *run = arg;
  platform_t *platform = run->platform;
  const char *kind = "exit";
  char id[24];
  int status = 0;
  int got;
  int killed = 0;

  for(;;) {
    got = platform->spawn_poll(platform, run->pid, &status);
    if(got < 0) {
      status = -1;
      break;
    }
    if(got) {
      break;
    }

    if(!killed && platform_ms(platform) >= run->deadline_ms) {
      (void)platform->spawn_kill(platform, run->pid);
      killed = 1;
      kind = "cut";
    }

    pause_briefly();
  }

  if(killed) {
    snprintf(id, sizeof(id), "%ld", (long)run->pid);
  } else {
    snprintf(id, sizeof(id), "%d", status);
  }

  (void)store_audit_append(kind, run->name, id, run->sha256);
  release(run);
  return NULL;
}


int
runs_start(platform_t *platform, const char *name, const char *sha256,
           const unsigned char *bytes, size_t size, char *const envp[],
           pid_t *pid) {
  char id[24];
  char *argv[2];
  struct run *run = NULL;
  pthread_t thread;
  size_t i;
  int logfd;

  pthread_mutex_lock(&lock);
  for(i=0; i<RUNS_MAX; i++) {
    if(runs[i].running && !strcmp(runs[i].name, name)) {
      pthread_mutex_unlock(&lock);
      return RUNS_ALREADY;
    }
  }
  for(i=0; i<RUNS_MAX && !run; i++) {
    if(!runs[i].running) {
      run = &runs[i];
    }
  }
  if(!run) {
    pthread_mutex_unlock(&lock);
    return RUNS_FULL;
  }
  run->running = 1;
  snprintf(run->name, sizeof(run->name), "%s", name);
  snprintf(run->sha256, sizeof(run->sha256), "%s", sha256);
  run->platform = platform;
  pthread_mutex_unlock(&lock);

  if((logfd=store_log_open(name, 1)) < 0) {
    release(run);
    return RUNS_FAILED;
  }

  argv[0] = (char*)name;
  argv[1] = NULL;
  if(platform->spawn_start(platform, bytes, size, argv, envp, logfd, pid)) {
    close(logfd);
    release(run);
    return RUNS_FAILED;
  }
  close(logfd);

  // Audited before the reaper exists, so no exit line can come first.
  snprintf(id, sizeof(id), "%ld", (long)*pid);
  if(store_audit_append("run", name, id, sha256)) {
    stop_and_reap(platform, *pid);
    release(run);
    return RUNS_AUDIT;
  }

  run->pid = *pid;
  run->deadline_ms = platform_ms(platform) + RUN_TIMEOUT_MS;

  if(pthread_create(&thread, NULL, reaper, run)) {
    stop_and_reap(platform, *pid);
    (void)store_audit_append("cut", name, id, sha256);
    release(run);
    return RUNS_FAILED;
  }
  pthread_detach(thread);

  return RUNS_STARTED;
}


static int
health_failed_event(const char *name, const char *id, const char *sha256) {
  return store_audit_append("health.fail", name, id, sha256) ? RUNS_AUDIT
                                                            : RUNS_UNHEALTHY;
}


int
runs_health(platform_t *platform, const char *name, const char *sha256,
            const unsigned char *bytes, size_t size, uint64_t timeout_ms) {
  char id[24];
  char *argv[2];
  uint64_t deadline;
  pid_t pid = 0;
  int status = 0;
  int got = 0;
  int timed_out = 0;
  int logfd;

  if((logfd=store_log_open(name, 1)) < 0) {
    return health_failed_event(name, "-", sha256);
  }

  argv[0] = (char*)name;
  argv[1] = NULL;
  deadline = platform_ms(platform) + timeout_ms;
  if(platform->spawn_start(platform, bytes, size, argv, NULL, logfd,
                            &pid)) {
    close(logfd);
    return health_failed_event(name, "spawn", sha256);
  }
  close(logfd);

  snprintf(id, sizeof(id), "%ld", (long)pid);
  if(store_audit_append("health.start", name, id, sha256)) {
    stop_and_reap(platform, pid);
    return RUNS_AUDIT;
  }

  for(;;) {
    got = platform->spawn_poll(platform, pid, &status);
    if(got < 0) {
      status = -1;
      break;
    }
    if(got) {
      break;
    }
    if(platform_ms(platform) >= deadline) {
      stop_and_reap(platform, pid);
      timed_out = 1;
      break;
    }
    pause_briefly();
  }

  if(timed_out) {
    if(store_audit_append("health.timeout", name, id, sha256)) {
      return RUNS_AUDIT;
    }
    return RUNS_TIMED_OUT;
  }

  snprintf(id, sizeof(id), "%d", status);
  if(got > 0 && status == 0) {
    return store_audit_append("health.ok", name, id, sha256) ? RUNS_AUDIT
                                                          : RUNS_HEALTHY;
  }
  return health_failed_event(name, id, sha256);
}


int
runs_running(const char *name) {
  size_t i;
  int running = 0;

  pthread_mutex_lock(&lock);
  for(i=0; i<RUNS_MAX; i++) {
    if(runs[i].running && !strcmp(runs[i].name, name)) {
      running = 1;
    }
  }
  pthread_mutex_unlock(&lock);

  return running;
}


void
runs_visit_going(runs_visit_t visit, void *ctx) {
  size_t i;

  pthread_mutex_lock(&lock);
  for(i=0; i<RUNS_MAX; i++) {
    if(runs[i].running) {
      visit(ctx, runs[i].name);
    }
  }
  pthread_mutex_unlock(&lock);
}
