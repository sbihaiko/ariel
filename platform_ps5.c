/* Ariel: the platform port for the PS5.

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

/**
 * The PS5 implementation of the narrow platform port: sockets, the
 * monotonic clock, approvals from the controller, and spawning a payload
 * through the ELF loader. There is no test clock and no virtual
 * controller here, and nothing on the network can grant an approval.
 *
 * The controller is the approval source recorded in ADR-0006; the
 * controller spike (docs/controller-spike.md) is the console run that
 * validates reading it while another app is in the foreground.
 **/

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <ps5/klog.h>

#include "elfldr.h"
#include "notify.h"
#include "pad.h"
#include "platform.h"
#include "platform_ps5.h"
#include "store.h"

/** One prompt fits one notification. **/
#define PROMPT_MAX 256

/** How often the controller reader samples the pad. **/
#define PAD_POLL_MS 16

/** This many failed reads in a row mean the handle is stale. **/
#define PAD_FAILURES 30

/** How long to wait before opening the controller again. **/
#define PAD_RETRY_MS 2000

/** The agent access token, shown with every approval prompt. **/
static const char *agent_token;

/**
 * The ELF loader uses process-wide state, so only one spawn loads at a
 * time. The telnet shell's sh.elf is a spawn too, and it shares this lock;
 * a payload's wait is outside it, so a long run never delays a shell.
 **/
static pthread_mutex_t loader_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * The newest approval waiting for a decision on the controller. One press
 * answers it; no press answers an older one, which expires instead.
 **/
static pthread_mutex_t armed_lock = PTHREAD_MUTEX_INITIALIZER;
static char armed_id[APPROVAL_ID_MAX];
static uint64_t armed_ms;


static uint64_t
now_ms(void) {
  struct timespec now;

  clock_gettime(CLOCK_MONOTONIC, &now);

  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}


/** Report an error code once, not on every retry. **/
static void
log_error(const char *what, unsigned int code, unsigned int *last) {
  if(code == *last) {
    return;
  }

  *last = code;
  klog_printf("%s error 0x%08x\n", what, code);
}


static int
ps5_listen(platform_t *self, uint16_t port) {
  struct sockaddr_in addr;
  int optval = 1;
  int srvfd;

  (void)self;

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    klog_perror("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
    klog_perror("setsockopt");
    close(srvfd);
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&addr, sizeof(addr))) {
    klog_perror("bind");
    close(srvfd);
    return -1;
  }

  if(listen(srvfd, 5)) {
    klog_perror("listen");
    close(srvfd);
    return -1;
  }

  return srvfd;
}


static int
ps5_accept(platform_t *self, int srvfd) {
  int optval = 1;
  int connfd;

  (void)self;

  do {
    connfd = accept(srvfd, NULL, NULL);
  } while(connfd < 0 && errno == EINTR);

  // An agent connection carries small replies; do not let Nagle hold the
  // last line back.
  if(connfd >= 0) {
    setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
  }

  return connfd;
}


static void
ps5_clock(platform_t *self, struct timespec *now) {
  (void)self;

  clock_gettime(CLOCK_MONOTONIC, now);
}


/** Remember the approval the next controller press decides. **/
static void
approval_arm(const char *id) {
  pthread_mutex_lock(&armed_lock);
  snprintf(armed_id, sizeof(armed_id), "%s", id);
  armed_ms = now_ms();
  pthread_mutex_unlock(&armed_lock);
}


/**
 * Whether an approval still waits for the controller. The store refuses a
 * decision after the approval expires, so the reader stops asking for the
 * controller then and leaves it alone.
 **/
static int
approval_pending(void) {
  int pending;

  pthread_mutex_lock(&armed_lock);
  if(armed_id[0] && now_ms() - armed_ms >= APPROVAL_EXPIRY_MS) {
    armed_id[0] = '\0';
  }
  pending = armed_id[0] != '\0';
  pthread_mutex_unlock(&armed_lock);

  return pending;
}


/** Decide the armed approval. The store refuses an ID that is gone. **/
static void
approval_decide(int approved) {
  char id[APPROVAL_ID_MAX];

  pthread_mutex_lock(&armed_lock);
  snprintf(id, sizeof(id), "%s", armed_id);
  armed_id[0] = '\0';
  pthread_mutex_unlock(&armed_lock);

  if(!id[0] || store_approval_decide(id, approved)) {
    return;
  }

  notify("Ariel: approval %s %s", id, approved ? "granted" : "denied");
}


static int
ps5_approval_request(platform_t *self, const approval_facts_t *facts,
                     char *id, size_t idlen) {
  char prompt[PROMPT_MAX];

  (void)self;

  if(store_approval_request(facts, id, idlen, prompt, sizeof(prompt))) {
    return -1;
  }

  // The prompt names the payload, its size, its hash and that it will run;
  // the token always rides along, so the owner can hand it to the agent
  // whenever an approval comes up.
  approval_arm(id);
  notify("%s\nApprove with X, deny with O.\ntoken %s", prompt, agent_token);

  return 0;
}


/** Open the controller for the console's user. **/
static int
pad_open(int *user_id) {
  int id = -1;

  if(*user_id < 0) {
    if(sceUserServiceGetInitialUser(&id) || id < 0) {
      id = -1;
      if(sceUserServiceGetForegroundUser(&id) || id < 0) {
        return -1;
      }
    }
    *user_id = id;
  }

  return scePadOpen(*user_id, PAD_PORT_TYPE_STANDARD, 0, NULL);
}


/**
 * The approval source. The controller is only opened while a prompt waits
 * for an answer, so Ariel touches it at no other time. X approves, O
 * denies; a press is the moment a button goes down.
 **/
static void *
pad_reader(void *arg) {
  pad_data_t data;
  unsigned int buttons = 0;
  unsigned int init_error = 0;
  unsigned int open_error = 0;
  int baseline = 0;
  int failures = 0;
  int user_id = -1;
  int handle = -1;

  (void)arg;

  log_error("controller init", (unsigned int)scePadInit(), &init_error);
  sceUserServiceInitialize(NULL);

  while(1) {
    unsigned int pressed;

    if(!approval_pending()) {
      if(handle >= 0) {
        scePadClose(handle);
        handle = -1;
        buttons = 0;
      }
      usleep(PAD_POLL_MS * 1000);
      continue;
    }

    if(handle < 0) {
      handle = pad_open(&user_id);
      if(handle < 0) {
        log_error("controller open", (unsigned int)handle, &open_error);
        usleep(PAD_RETRY_MS * 1000);
        continue;
      }
      open_error = 0;
      buttons = 0;
      failures = 0;
      baseline = 1;
    }

    memset(&data, 0, sizeof(data));
    if(scePadReadState(handle, &data) < 0) {
      // A handle can go stale when the controller reconnects or another
      // app takes it: close it and let the retry open a fresh one.
      if(++failures >= PAD_FAILURES) {
        scePadClose(handle);
        handle = -1;
        failures = 0;
        usleep(PAD_RETRY_MS * 1000);
      } else {
        usleep(PAD_POLL_MS * 1000);
      }
      continue;
    }
    failures = 0;

    // The first read after opening only records which buttons are already
    // held: a button held down before the prompt appeared must not approve
    // it. Only a press after that counts.
    if(baseline) {
      baseline = 0;
      buttons = data.buttons;
      usleep(PAD_POLL_MS * 1000);
      continue;
    }

    pressed = data.buttons & ~buttons & ~PAD_BUTTON_INTERCEPTED;
    buttons = data.buttons;

    if(pressed & PAD_BUTTON_CROSS) {
      approval_decide(1);
    } else if(pressed & PAD_BUTTON_CIRCLE) {
      approval_decide(0);
    }

    usleep(PAD_POLL_MS * 1000);
  }

  return NULL;
}


void
platform_ps5_loader_lock(void) {
  pthread_mutex_lock(&loader_lock);
}


void
platform_ps5_loader_unlock(void) {
  pthread_mutex_unlock(&loader_lock);
}


static int
ps5_spawn(platform_t *self, const unsigned char *bytes, size_t size,
          char *const argv[], int outfd, int *status) {
  int wait_status;
  int rc = -1;
  pid_t pid;

  (void)self;
  (void)size;

  // The loader only reads the bytes; the store holds the verified object
  // in memory, so nothing is loaded from a path.
  platform_ps5_loader_lock();
  pid = elfldr_spawn(-1, outfd, outfd, (uint8_t*)bytes, (char**)argv);
  platform_ps5_loader_unlock();

  if(pid < 0) {
    klog_printf("elfldr_spawn failed\n");
    return -1;
  }

  // SIGCHLD has its default handling, so the payload's own exit status is
  // still there for this wait.
  while(waitpid(pid, &wait_status, 0) < 0) {
    if(errno != EINTR) {
      klog_perror("waitpid");
      return -1;
    }
  }

  if(WIFEXITED(wait_status)) {
    *status = WEXITSTATUS(wait_status);
    rc = 0;
  } else if(WIFSIGNALED(wait_status)) {
    *status = 128 + WTERMSIG(wait_status);
    rc = 0;
  }

  return rc;
}


static platform_t ps5_platform = {
  // A console has no test clock, so no wait has a wake pipe and every
  // deadline runs on real time.
  .listen = ps5_listen,
  .accept = ps5_accept,
  .clock = ps5_clock,
  .wake_new = NULL,
  .wake_close = NULL,
  .wake_idle = NULL,
  .approval_request = ps5_approval_request,
  .spawn = ps5_spawn,
};


platform_t *
platform_ps5(const char *token) {
  pthread_t thread;

  agent_token = token;

  if(pthread_create(&thread, NULL, pad_reader, NULL)) {
    // Without the reader the port still serves; an approval requested now
    // can only expire.
    klog_printf("pthread_create: controller reader not started\n");
  } else {
    pthread_detach(thread);
  }

  return &ps5_platform;
}
