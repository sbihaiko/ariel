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
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <ps5/klog.h>
#include <ps5/kernel.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "approval.h"
#include "elfldr.h"
#include "http.h"
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

#ifndef ARIEL_RECOVERY_PUBKEY_HEX
#define ARIEL_RECOVERY_PUBKEY_HEX ""
#endif

#ifndef ARIEL_CONSOLE_ID
#define ARIEL_CONSOLE_ID "ps5"
#endif

/** The agent access token, shown with every approval prompt. **/
static const char *agent_token;

/** The pinned anchor: the primary and recovery keys, and whether the build accepted both. **/
static unsigned char pubkey[APPROVAL_PUBKEY_LEN];
static unsigned char recovery_pubkey[APPROVAL_PUBKEY_LEN];
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
ps5_verify(platform_t *self, const unsigned char key[APPROVAL_PUBKEY_LEN],
           const unsigned char *msg, size_t len,
           const unsigned char *signature) {
  (void)self;

  // With no anchor pinned, or one the build refuses, no signature is valid.
  if(!pinned) {
    return -1;
  }

  return approval_verify(key, msg, len, signature);
}


static int
ps5_anchor(platform_t *self, unsigned char primary[APPROVAL_PUBKEY_LEN],
           unsigned char recovery[APPROVAL_PUBKEY_LEN]) {
  (void)self;

  if(!pinned) {
    return -1;
  }

  memcpy(primary, pubkey, APPROVAL_PUBKEY_LEN);
  memcpy(recovery, recovery_pubkey, APPROVAL_PUBKEY_LEN);
  return 0;
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


/**
 * The kernel's list of processes, in a buffer the caller frees. Each record
 * is a kinfo_proc, and its own size says where the next one starts.
 **/
static int
procs_snapshot(char **buf, size_t *size) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  size_t need = 0;
  char *data;

  if(sysctl(mib, 4, NULL, &need, NULL, 0)) {
    return -1;
  }
  if(!(data = malloc(need ? need : 1))) {
    return -1;
  }
  if(sysctl(mib, 4, data, &need, NULL, 0)) {
    free(data);
    return -1;
  }

  *buf = data;
  *size = need;
  return 0;
}


static int
ps5_mount(const approval_facts_t *facts) {
  const char *names[3] = {"fstype", "fspath", "from"};
  const char *values[3] = {facts->fstype, facts->target, facts->from};
  struct iovec iov[6];
  int i;

  for(i=0; i<3; i++) {
    iov[2*i].iov_base = (void *)names[i];
    iov[2*i].iov_len = strlen(names[i]) + 1;
    iov[2*i+1].iov_base = (void *)values[i];
    iov[2*i+1].iov_len = strlen(values[i]) + 1;
  }
  return nmount(iov, 6, 0);
}


static int
ps5_unmount(const char *path) {
  return syscall(22, path, (uint64_t)0);
}


static int
ps5_mknod(const approval_facts_t *facts) {
  int mode = 0666 | (!strcmp(facts->type, "b") ? S_IFBLK : S_IFCHR);

  return syscall(SYS_mknod, facts->target, mode,
                 makedev((int)facts->major, (int)facts->minor));
}


/**
 * The root change is made in a child, so Ariel itself is never jailed. The
 * child ends at once, so the new root does not outlive this command.
 **/
static int
ps5_chroot(const char *path) {
  pid_t self = getpid();
  pid_t child;
  int status;

  child = fork();
  if(child < 0) {
    return -1;
  }
  if(child == 0) {
    kernel_set_ucred_authid(self, 0x4800000000000007l);
    _exit(chroot(path) ? 1 : 0);
  }
  if(waitpid(child, &status, 0) < 0 || !WIFEXITED(status) ||
     WEXITSTATUS(status)) {
    return -1;
  }
  return 0;
}


static int
proc_find(int32_t pid, struct kinfo_proc *out) {
  char *buf;
  char *p;
  char *end;
  size_t size;
  int found = -1;

  if(procs_snapshot(&buf, &size)) {
    return -1;
  }

  end = buf + size;
  for(p=buf; p<end; ) {
    struct kinfo_proc *ki = (struct kinfo_proc *)p;
    size_t step = (size_t)ki->ki_structsize;

    if(step == 0 || step > (size_t)(end - p)) {
      break;
    }
    if(ki->ki_pid == pid) {
      *out = *ki;
      found = 0;
      break;
    }
    p += step;
  }

  free(buf);
  return found;
}


static int
ps5_processes(platform_t *self, int32_t *pids, size_t max) {
  char *buf;
  char *p;
  char *end;
  size_t size;
  size_t count = 0;

  (void)self;

  if(procs_snapshot(&buf, &size)) {
    return -1;
  }

  end = buf + size;
  for(p=buf; p<end && count < max; ) {
    struct kinfo_proc *ki = (struct kinfo_proc *)p;
    size_t step = (size_t)ki->ki_structsize;

    if(step == 0 || step > (size_t)(end - p)) {
      break;
    }
    pids[count++] = ki->ki_pid;
    p += step;
  }

  free(buf);
  return (int)count;
}


static int
ps5_process_start(platform_t *self, int32_t pid, char *out, size_t size) {
  struct kinfo_proc ki;

  (void)self;

  if(proc_find(pid, &ki)) {
    return -1;
  }
  snprintf(out, size, "%lld.%06ld", (long long)ki.ki_start.tv_sec,
           (long)ki.ki_start.tv_usec);
  return 0;
}


static int
ps5_process_critical(platform_t *self, int32_t pid) {
  struct kinfo_proc ki;

  (void)self;

  if(pid == (int32_t)getpid()) {
    return 1;
  }
  if(proc_find(pid, &ki)) {
    return 0;
  }
  return !strcmp(ki.ki_comm, "SceShellCore");
}


static int
ps5_process_signal(platform_t *self, int32_t pid, int sig) {
  (void)self;

  return kill((pid_t)pid, sig) ? -1 : 0;
}


static int
ps5_reboot(platform_t *self) {
  (void)self;

  return reboot(RB_AUTOBOOT) ? -1 : 0;
}


static int
ps5_system_act(platform_t *self, const approval_facts_t *facts) {
  int rc;

  (void)self;

  if(!strcmp(facts->command, "mount")) {
    rc = ps5_mount(facts);
  } else if(!strcmp(facts->command, "umount")) {
    rc = ps5_unmount(facts->target);
  } else if(!strcmp(facts->command, "mknod")) {
    rc = ps5_mknod(facts);
  } else {
    rc = ps5_chroot(facts->target);
  }
  return rc ? -1 : 0;
}


static int
ps5_http_get(platform_t *self, const char *url, size_t max, http_sink_t sink,
             void *ctx, int *status, char *location, size_t size) {
  (void)self;
  return http_fetch(url, max, sink, ctx, status, location, size);
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
  .anchor = ps5_anchor,
  .approval_request = ps5_approval_request,
  .approval_grant = ps5_approval_grant,
  .spawn = ps5_spawn,
  .spawn_start = ps5_spawn_start,
  .spawn_start_isolated = ps5_spawn_start,
  .spawn_poll = ps5_spawn_poll,
  .spawn_kill = ps5_spawn_kill,
  .http_get = ps5_http_get,
  .run = ps5_run,
  .processes = ps5_processes,
  .process_start = ps5_process_start,
  .process_critical = ps5_process_critical,
  .process_signal = ps5_process_signal,
  .reboot = ps5_reboot,
  .system_act = ps5_system_act,
};


platform_t *
platform_ps5(const char *token) {
  agent_token = token;

  // The anchor is pinned at build time: the primary and the recovery key,
  // which must differ. A key that does not parse, or one the build refuses
  // such as the host test key, leaves nothing pinned, and then every grant
  // is refused.
  if(approval_pubkey_parse(ARIEL_PUBKEY_HEX, pubkey) ||
     approval_pin(pubkey) ||
     approval_pubkey_parse(ARIEL_RECOVERY_PUBKEY_HEX, recovery_pubkey) ||
     approval_pin(recovery_pubkey) ||
     !memcmp(pubkey, recovery_pubkey, APPROVAL_PUBKEY_LEN)) {
    klog_printf("no approval anchor pinned: every grant will be refused\n");
  } else {
    pinned = 1;
  }

  return &ps5_platform;
}
