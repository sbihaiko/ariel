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
 * monotonic clock, approvals by the owner's signature, and spawning a
 * payload through the ELF loader. There is no test clock and no virtual
 * controller here, and the console reads no controller. A grant is an
 * Ed25519 signature checked against the key pinned at build time, so an
 * agent that holds the connection can carry a signature but not make one.
 *
 * The owner's signature is the approval source recorded in ADR-0006.
 **/

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <ps5/klog.h>

#include "approval.h"
#include "elfldr.h"
#include "notify.h"
#include "platform.h"
#include "platform_ps5.h"
#include "runner.h"
#include "store.h"

/** One prompt fits one notification. **/
#define PROMPT_MAX 256

/**
 * The owner's public key and the console's identity come from the build
 * (ARIEL_PUBKEY_HEX and ARIEL_CONSOLE_ID in the Makefile). With no key
 * given nothing is pinned.
 **/
#ifndef ARIEL_PUBKEY_HEX
#define ARIEL_PUBKEY_HEX ""
#endif

#ifndef ARIEL_CONSOLE_ID
#define ARIEL_CONSOLE_ID "ps5"
#endif

/** The agent access token, shown with every approval prompt. **/
static const char *agent_token;

/** The pinned approval key, and whether the build accepted one. **/
static unsigned char pubkey[APPROVAL_PUBKEY_LEN];
static int pinned;

/**
 * The ELF loader uses process-wide state, so only one spawn loads at a
 * time. The telnet shell's sh.elf is a spawn too, and it shares this lock;
 * a payload's wait is outside it, so a long run never delays a shell.
 **/
static pthread_mutex_t loader_lock = PTHREAD_MUTEX_INITIALIZER;

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


static int
ps5_random(platform_t *self, unsigned char *buf, size_t len) {
  (void)self;

  arc4random_buf(buf, len);

  return 0;
}


static const char *
ps5_console_id(platform_t *self) {
  (void)self;

  return ARIEL_CONSOLE_ID;
}


static int
ps5_verify(platform_t *self, const unsigned char *msg, size_t len,
           const unsigned char *signature) {
  (void)self;

  // With no key pinned, or one the build refuses, no signature is valid.
  if(!pinned) {
    return -1;
  }

  return approval_verify(pubkey, msg, len, signature);
}


static int
ps5_approval_request(platform_t *self, const approval_facts_t *facts,
                     approval_challenge_t *challenge) {
  char prompt[PROMPT_MAX];

  (void)self;

  if(store_approval_request(facts, challenge, prompt, sizeof(prompt))) {
    return -1;
  }

  // The prompt names the payload, its size, its hash and that it will run.
  // The owner signs the challenge the agent returns, offline; the token
  // always rides along, so the owner can hand it to the agent whenever an
  // approval comes up.
  notify("%s\nApproval %s: sign its challenge with ariel-sign.\ntoken %s",
         prompt, challenge->id, agent_token);

  return 0;
}


static int
ps5_approval_grant(platform_t *self, const char *id,
                   const unsigned char *signature,
                   const char *console, const char *action_sha256) {
  (void)self;

  return store_approval_grant(id, signature, console, action_sha256);
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
ps5_spawn_start(platform_t *self, const unsigned char *bytes, size_t size,
                char *const argv[], int outfd, pid_t *pid) {
  (void)self;
  (void)size;

  // The loader only reads the bytes; the store holds the verified object
  // in memory, so nothing is loaded from a path.
  platform_ps5_loader_lock();
  *pid = elfldr_spawn(-1, outfd, outfd, (uint8_t*)bytes, (char**)argv);
  platform_ps5_loader_unlock();

  if(*pid < 0) {
    klog_printf("elfldr_spawn failed\n");
    return -1;
  }

  return 0;
}


static int
ps5_status(int wait_status, int *status) {
  if(WIFEXITED(wait_status)) {
    *status = WEXITSTATUS(wait_status);
    return 0;
  }
  if(WIFSIGNALED(wait_status)) {
    *status = 128 + WTERMSIG(wait_status);
    return 0;
  }
  return -1;
}


static int
ps5_spawn(platform_t *self, const unsigned char *bytes, size_t size,
          char *const argv[], int outfd, int *status) {
  int wait_status;
  pid_t pid;

  if(ps5_spawn_start(self, bytes, size, argv, outfd, &pid)) {
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

  return ps5_status(wait_status, status);
}


static int
ps5_spawn_poll(platform_t *self, pid_t pid, int *status) {
  int wait_status;
  pid_t got;

  (void)self;

  do {
    got = waitpid(pid, &wait_status, WNOHANG);
  } while(got < 0 && errno == EINTR);

  if(got < 0) {
    klog_perror("waitpid");
    return -1;
  }
  if(got == 0) {
    return 0;
  }

  return ps5_status(wait_status, status) ? -1 : 1;
}


static int
ps5_spawn_kill(platform_t *self, pid_t pid) {
  (void)self;

  return kill(pid, SIGKILL);
}


static int
ps5_run(platform_t *self, int argc, char *const argv[], int outfd, int errfd,
        int *status) {
  (void)self;

  return runner_run(argc, argv, outfd, errfd, status);
}


static platform_t ps5_platform = {
  // A console has no test clock, so no wait has a wake pipe and every
  // deadline runs on real time.
  .fs_root = "",
  .listen = ps5_listen,
  .accept = ps5_accept,
  .clock = ps5_clock,
  .wake_new = NULL,
  .wake_close = NULL,
  .wake_idle = NULL,
  .random = ps5_random,
  .console_id = ps5_console_id,
  .verify = ps5_verify,
  .approval_request = ps5_approval_request,
  .approval_grant = ps5_approval_grant,
  .spawn = ps5_spawn,
  .spawn_start = ps5_spawn_start,
  .spawn_poll = ps5_spawn_poll,
  .spawn_kill = ps5_spawn_kill,
  .run = ps5_run,
};


platform_t *
platform_ps5(const char *token) {
  agent_token = token;

  // The owner's public key is pinned at build time. A key that does not
  // parse, or one the build refuses such as the host test key, leaves
  // nothing pinned, and then every grant is refused.
  if(approval_pubkey_parse(ARIEL_PUBKEY_HEX, pubkey) ||
     approval_pin(pubkey)) {
    klog_printf("no approval key pinned: every grant will be refused\n");
  } else {
    pinned = 1;
  }

  return &ps5_platform;
}
