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
#include <stdint.h>
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

#include "approval.h"
#include "http.h"
#include "platform.h"
#include "runner.h"
#include "sha256.h"
#include "store.h"
#include "testclock.h"
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


static char exe_path[PATH_MAX];

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

  testclock_now(now);
}


static void
host_sleep_ms(platform_t *self, long ms) {
  (void)self;

  testclock_sleep_ms(ms);
}


static int
host_wake_new(platform_t *self) {
  (void)self;

  return testclock_wake_new();
}


static void
host_wake_close(platform_t *self, int fd) {
  (void)self;

  testclock_wake_close(fd);
}


static void
host_wake_idle(platform_t *self, int wake, int fd, int idle) {
  (void)self;

  testclock_wake_idle(wake, fd, idle);
}


/** The identity every signature checked by the host build names. **/
#define HOST_CONSOLE_ID "ariel-host-test"

/**
 * The key the host build pins: the test key, whose private half is in the
 * repository. approval_pin refuses it in the PS5 build.
 **/
static unsigned char host_pubkey[APPROVAL_PUBKEY_LEN];

/** The host build's recovery test key; its private half is hostbuild/tests/host-recovery-testkey. **/
#define HOST_RECOVERY_PUBKEY_HEX \
  "b7ca23da46f215a71b7dde34148d594e973f82e874f6dc18d208a8a5d3a0c77a"
static unsigned char host_recovery_pubkey[APPROVAL_PUBKEY_LEN];

/**
 * The anchor this host build pins. ARIEL_HOST_ANCHOR_PRIMARY and
 * ARIEL_HOST_ANCHOR_RECOVERY, as hex, replace the test pair so a scenario can
 * start a build whose anchor differs from the keyring's. The host build only.
 **/
static unsigned char host_anchor_primary[APPROVAL_PUBKEY_LEN];
static unsigned char host_anchor_recovery[APPROVAL_PUBKEY_LEN];

/**
 * A scenario can make the nonce stream repeat from a restart by giving
 * ARIEL_HOST_NONCE_SEED. Without it the nonces come from the system's
 * random source. The seed exists only in the host build.
 **/
static char nonce_seed[64];
static int nonce_seeded;
static uint64_t nonce_counter;
static pthread_mutex_t random_lock = PTHREAD_MUTEX_INITIALIZER;


static int
host_random(platform_t *self, unsigned char *buf, size_t len) {
  size_t total = 0;
  int fd;

  (void)self;

  if(nonce_seeded) {
    // sha256(seed || counter), one block at a time.
    while(total < len) {
      unsigned char digest[SHA256_DIGEST_LEN];
      unsigned char counter[8];
      sha256_t hash;
      size_t n = len - total < sizeof(digest) ? len - total : sizeof(digest);
      uint64_t value;
      int i;

      pthread_mutex_lock(&random_lock);
      value = nonce_counter++;
      pthread_mutex_unlock(&random_lock);

      for(i=0; i<8; i++) {
        counter[i] = (unsigned char)(value >> (8 * i));
      }

      sha256_init(&hash);
      sha256_update(&hash, nonce_seed, strlen(nonce_seed));
      sha256_update(&hash, counter, sizeof(counter));
      sha256_final(&hash, digest);
      memcpy(buf + total, digest, n);
      total += n;
    }
    return 0;
  }

  if((fd=open("/dev/urandom", O_RDONLY | O_CLOEXEC)) < 0) {
    return -1;
  }

  while(total < len) {
    ssize_t n = read(fd, buf + total, len - total);

    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      close(fd);
      return -1;
    }
    total += (size_t)n;
  }

  return close(fd);
}


static const char *
host_console_id(platform_t *self) {
  (void)self;

  return HOST_CONSOLE_ID;
}


static int
host_verify(platform_t *self, const unsigned char key[APPROVAL_PUBKEY_LEN],
            const unsigned char *msg, size_t len,
            const unsigned char *signature) {
  (void)self;

  return approval_verify(key, msg, len, signature);
}


static void
host_anchor_override(const char *name, unsigned char key[APPROVAL_PUBKEY_LEN]) {
  const char *hex = getenv(name);

  if(hex && *hex && (approval_pubkey_parse(hex, key) || approval_pin(key))) {
    fprintf(stderr, "the host build cannot pin %s\n", name);
    exit(EXIT_FAILURE);
  }
}


static int
host_anchor(platform_t *self, unsigned char primary[APPROVAL_PUBKEY_LEN],
            unsigned char recovery[APPROVAL_PUBKEY_LEN]) {
  (void)self;

  memcpy(primary, host_anchor_primary, APPROVAL_PUBKEY_LEN);
  memcpy(recovery, host_anchor_recovery, APPROVAL_PUBKEY_LEN);
  return 0;
}


static int
host_approval_request(platform_t *self, const approval_facts_t *facts,
                      approval_challenge_t *challenge) {
  (void)self;

  return vcontroller_request(facts, challenge);
}


static int
host_approval_grant(platform_t *self, const char *id,
                    const unsigned char *signature,
                    const char *console, const char *action_sha256) {
  (void)self;

  return store_approval_grant(id, signature, console, action_sha256);
}


static int
host_processes(platform_t *self, int32_t *pids, size_t max) {
  FILE *ps;
  char line[64];
  size_t count = 0;

  (void)self;

  if(!(ps=popen("ps -axo pid=", "r"))) {
    return -1;
  }
  while(fgets(line, sizeof(line), ps)) {
    char *end;
    long pid = strtol(line, &end, 10);

    if(end == line || count == max) {
      continue;
    }
    pids[count++] = (int32_t)pid;
  }
  if(pclose(ps) == -1) {
    return -1;
  }
  return (int)count;
}


/** The process the harness marks critical, read from the environment. **/
static int32_t critical_pid;

static int
host_process_start(platform_t *self, int32_t pid, char *out, size_t size) {
  (void)self;

  if(pid <= 0 || (kill((pid_t)pid, 0) && errno != EPERM)) {
    return -1;
  }
  snprintf(out, size, "h.%u", vcontroller_epoch(pid));
  return 0;
}


static int
host_process_critical(platform_t *self, int32_t pid) {
  (void)self;

  return pid == (int32_t)getpid() || (critical_pid > 0 && pid == critical_pid);
}


static int
host_process_signal(platform_t *self, int32_t pid, int sig) {
  (void)self;

  return kill((pid_t)pid, sig) ? -1 : 0;
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


/** The file a run executes from, and the directory it lives in. **/
struct host_file {
  char dir[PATH_MAX];
  char path[PATH_MAX];
};

/**
 * Background payloads keep their file until they exit, so at most this many
 * can be running at once.
 **/
#define HOST_STARTED_MAX 16

struct host_started {
  int used;
  pid_t pid;
  struct host_file file;
};

static pthread_mutex_t started_lock = PTHREAD_MUTEX_INITIALIZER;
static struct host_started started[HOST_STARTED_MAX];


static void
host_file_remove(const struct host_file *file) {
  if(file->path[0]) {
    unlink(file->path);
  }
  if(file->dir[0]) {
    rmdir(file->dir);
  }
}


/**
 * The host has no exec from memory, so the verified bytes go to a fresh
 * file inside a directory only Ariel can read. The file stays until the
 * caller removes it; the spawn lock covers only the fork and exec window.
 **/
static int
host_start(const unsigned char *bytes, size_t size, char *const argv[],
           char *const envp[], int outfd, struct host_file *file, pid_t *child,
           int isolated) {
  char *const no_env[] = {NULL};
  int errpipe[2] = {-1, -1};
  int exec_failed = 0;
  int filefd = -1;
  int nullfd = -1;
  int rc = -1;
  pid_t pid;

  pthread_mutex_lock(&spawn_lock);

  file->dir[0] = '\0';
  file->path[0] = '\0';

  if(snprintf(file->dir, sizeof(file->dir), "%s/payload-XXXXXX", run_dir) >=
     (int)sizeof(file->dir) || !mkdtemp(file->dir)) {
    file->dir[0] = '\0';
    goto out;
  }

  if(snprintf(file->path, sizeof(file->path), "%s/payload", file->dir) >=
     (int)sizeof(file->path)) {
    file->path[0] = '\0';
    goto out;
  }

  if((filefd=open(file->path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  0700)) < 0) {
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

    if(isolated) {
      execve(file->path, argv, no_env);
    } else if(envp) {
      execve(file->path, argv, envp);
    } else {
      execv(file->path, argv);
    }
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

  if(exec_failed) {
    (void)waitpid(pid, NULL, 0);
    goto out;
  }

  *child = pid;
  rc = 0;

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
  if(rc) {
    host_file_remove(file);
  }
  if(nullfd >= 0) {
    close(nullfd);
  }

  pthread_mutex_unlock(&spawn_lock);
  return rc;
}


static int
host_status(int wait_status, int *status) {
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
host_spawn(platform_t *self, const unsigned char *bytes, size_t size,
           char *const argv[], char *const envp[], int outfd, int *status) {
  struct host_file file;
  int wait_status;
  pid_t pid;

  (void)self;

  if(host_start(bytes, size, argv, envp, outfd, &file, &pid, 0)) {
    return -1;
  }

  while(waitpid(pid, &wait_status, 0) < 0) {
    if(errno != EINTR) {
      host_file_remove(&file);
      return -1;
    }
  }
  host_file_remove(&file);

  return host_status(wait_status, status);
}


static int
host_spawn_start_mode(const unsigned char *bytes, size_t size,
                      char *const argv[], char *const envp[], int outfd,
                      pid_t *pid, int isolated) {
  struct host_started *slot = NULL;
  size_t i;
  int rc;

  pthread_mutex_lock(&started_lock);
  for(i=0; i<HOST_STARTED_MAX && !slot; i++) {
    if(!started[i].used) {
      slot = &started[i];
    }
  }
  if(slot) {
    slot->used = 1;
    slot->pid = 0;
  }
  pthread_mutex_unlock(&started_lock);

  if(!slot) {
    return -1;
  }

  rc = host_start(bytes, size, argv, envp, outfd, &slot->file, pid, isolated);

  pthread_mutex_lock(&started_lock);
  if(rc) {
    slot->used = 0;
  } else {
    slot->pid = *pid;
  }
  pthread_mutex_unlock(&started_lock);

  return rc;
}


static int
host_spawn_start(platform_t *self, const unsigned char *bytes, size_t size,
                 char *const argv[], char *const envp[], int outfd,
                 pid_t *pid) {
  (void)self;

  return host_spawn_start_mode(bytes, size, argv, envp, outfd, pid, 0);
}


static int
host_spawn_start_isolated(platform_t *self, const unsigned char *bytes,
                          size_t size, char *const argv[], int outfd,
                          pid_t *pid) {
  (void)self;

  return host_spawn_start_mode(bytes, size, argv, NULL, outfd, pid, 1);
}


static void
host_forget(pid_t pid) {
  size_t i;

  pthread_mutex_lock(&started_lock);
  for(i=0; i<HOST_STARTED_MAX; i++) {
    if(started[i].used && started[i].pid == pid) {
      host_file_remove(&started[i].file);
      started[i].used = 0;
      break;
    }
  }
  pthread_mutex_unlock(&started_lock);
}


static int
host_spawn_poll(platform_t *self, pid_t pid, int *status) {
  int wait_status;
  pid_t got;

  (void)self;

  do {
    got = waitpid(pid, &wait_status, WNOHANG);
  } while(got < 0 && errno == EINTR);

  if(got < 0) {
    host_forget(pid);
    return -1;
  }
  if(got == 0) {
    return 0;
  }

  host_forget(pid);
  return host_status(wait_status, status) ? -1 : 1;
}


static int
host_spawn_kill(platform_t *self, pid_t pid) {
  (void)self;

  return kill(pid, SIGKILL);
}


static int
host_run(platform_t *self, int argc, char *const argv[], int outfd, int errfd,
         runner_session_t *session, int *status) {
  return runner_run(self, argc, argv, outfd, errfd, session, status);
}


static int
host_system_act(platform_t *self, const approval_facts_t *facts) {
  (void)self;
  (void)facts;

  return 1;
}


/**
 * ARIEL_HOST_FAULT names the step at which this build ends itself. The
 * process aborts there, with nothing flushed after the step, so a restart
 * meets the store as the crash left it.
 **/
static void
host_fault(platform_t *self, const char *step) {
  const char *want = getenv("ARIEL_HOST_FAULT");

  (void)self;

  if(want && !strcmp(want, step)) {
    abort();
  }
}


// execv keeps the pid, stdout and stdin, so the harness reads the new port
// and token lines from the same pipe; the listener and the agent's sockets
// are CLOEXEC. The new process asks the OS for a port of its own rather than
// binding the one this process had: no other holder sits between the two, and
// the port line names the new one.
static int
host_reboot(platform_t *self) {
  char *args[] = {exe_path, "--port", "0", "--root", NULL, "--boot", NULL};

  args[4] = (char *)self->fs_root;
  fflush(stdout);
  fflush(stderr);
  execv(exe_path, args);
  return -1;
}


static int
host_http_get(platform_t *self, const char *url, size_t max, http_sink_t sink,
              void *ctx, int *status, char *location, size_t size) {
  (void)self;
  return http_fetch(url, max, sink, ctx, status, location, size);
}


static platform_t host_platform = {
  .listen = host_listen,
  .accept = host_accept,
  .clock = host_clock,
  .sleep_ms = host_sleep_ms,
  .wake_new = host_wake_new,
  .wake_close = host_wake_close,
  .wake_idle = host_wake_idle,
  .random = host_random,
  .console_id = host_console_id,
  .verify = host_verify,
  .anchor = host_anchor,
  .approval_request = host_approval_request,
  .approval_grant = host_approval_grant,
  .spawn = host_spawn,
  .spawn_start = host_spawn_start,
  .spawn_start_isolated = host_spawn_start_isolated,
  .spawn_poll = host_spawn_poll,
  .spawn_kill = host_spawn_kill,
  .http_get = host_http_get,
  .run = host_run,
  .system_act = host_system_act,
  .fault = host_fault,
  .processes = host_processes,
  .process_start = host_process_start,
  .process_critical = host_process_critical,
  .process_signal = host_process_signal,
  .reboot = host_reboot,
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
platform_host(const char *dir, const char *fs_root, const char *exe) {
  long limit;

  testclock_init();
  snprintf(run_dir, sizeof(run_dir), "%s", dir);
  snprintf(exe_path, sizeof(exe_path), "%s", exe);
  host_platform.fs_root = fs_root;

  // Read the descriptor bound here, before any connection thread exists:
  // the child after fork sweeps descriptors up to it and may not call
  // anything that reads the process environment safely. Neither limit is
  // shortened further; a descriptor above the sweep would survive into the
  // payload.
  limit = open_max();
  if(limit > 2) {
    fd_limit = limit;
  }

  if(approval_pubkey_parse(APPROVAL_TEST_PUBKEY_HEX, host_pubkey) ||
     approval_pin(host_pubkey) ||
     approval_pubkey_parse(HOST_RECOVERY_PUBKEY_HEX, host_recovery_pubkey) ||
     approval_pin(host_recovery_pubkey)) {
    fprintf(stderr, "the host build cannot pin its test keys\n");
    exit(EXIT_FAILURE);
  }
  memcpy(host_anchor_primary, host_pubkey, APPROVAL_PUBKEY_LEN);
  memcpy(host_anchor_recovery, host_recovery_pubkey, APPROVAL_PUBKEY_LEN);
  host_anchor_override("ARIEL_HOST_ANCHOR_PRIMARY", host_anchor_primary);
  host_anchor_override("ARIEL_HOST_ANCHOR_RECOVERY", host_anchor_recovery);

  // Read the seed here too, before any connection thread exists.
  {
    const char *seed = getenv("ARIEL_HOST_NONCE_SEED");

    if(seed && *seed && strlen(seed) < sizeof(nonce_seed)) {
      snprintf(nonce_seed, sizeof(nonce_seed), "%s", seed);
      nonce_seeded = 1;
    }
  }

  {
    const char *pid = getenv("ARIEL_HOST_CRITICAL_PID");

    if(pid && *pid) {
      critical_pid = (int32_t)strtol(pid, NULL, 10);
    }
  }

  vcontroller_start();
  return &host_platform;
}
