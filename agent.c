/* Ariel: the agent protocol.

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
/* macOS hides O_NOFOLLOW and AT_* behind _DARWIN_C_SOURCE once
   _POSIX_C_SOURCE is defined. The gallery walk opens nothing through a link. */
#define _DARWIN_C_SOURCE 1
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "addon.h"
#include "agent.h"
#include "allowlist.h"
#include "approval.h"
#include "autoload.h"
#include "builtins.h"
#include "fileops.h"
#include "http.h"
#include "protected.h"
#include "release.h"
#include "runner.h"
#include "runs.h"
#include "sha256.h"
#include "store.h"
#include "tar.h"
#include "token.h"

/**
 * The agent port bounds: a command line is at most 4 KiB and 64 tokens,
 * the auth line has its own short limit, and a connection lasts at most
 * 60 seconds.
 **/
#define LINE_LIMIT             4096
#define AUTH_LINE_MAX          64
#define MAX_TOKENS             64
#define AUTH_DEADLINE_MS       5000L
#define CONNECTION_DEADLINE_MS 60000L

/**
 * One upload waits at most this long for its next bytes: a second below the
 * connection deadline, so a stall names upload_mismatch before the deadline
 * ends the connection with timed_out.
 **/
#define UPLOAD_STALL_MS     (CONNECTION_DEADLINE_MS - 1000L)

/** A close drains unread input for at most this long. **/
#define CLOSE_DRAIN_MS      200L

#define READ_CHUNK          65536

#define ENV_NAME_MAX        32
#define ENV_LINE_MAX        1024

static const char bad_name[] =
  "bad_name\n"
  "exit 1\n";
static const char unknown[] =
  "unknown_command\n"
  "exit 1\n";
static const char bad_quoting_reply[] =
  "bad_quoting\n"
  "exit 1\n";
static const char too_many_arguments_reply[] =
  "too_many_arguments\n"
  "exit 1\n";
static const char timed_out_reply[] =
  "timed_out\n"
  "exit 1\n";
static const char bad_path[] =
  "bad_path\n"
  "exit 1\n";
static const char missing_operand[] =
  "missing_operand\n"
  "exit 1\n";
static const char bad_option[] =
  "bad_option\n"
  "exit 1\n";
static const char list_failed[] =
  "list_failed\n"
  "exit 1\n";
static const char mismatch[] =
  "upload_mismatch\n"
  "exit 81\n";
static const char staging_full[] =
  "staging_full\n"
  "exit 80\n";
static const char approval_busy[] =
  "approval_busy\n"
  "exit 76\n";
static const char approval_denied[] =
  "approval_denied\n"
  "exit 77\n";
static const char approval_expired[] =
  "approval_expired\n"
  "exit 88\n";
static const char signature_invalid[] =
  "signature_invalid\n"
  "exit 79\n";
static const char signature_malformed[] =
  "signature_malformed\n"
  "exit 83\n";
static const char signature_action_mismatch[] =
  "signature_action_mismatch\n"
  "exit 85\n";
static const char signature_console_mismatch[] =
  "signature_console_mismatch\n"
  "exit 86\n";
static const char approval_replayed[] =
  "approval_replayed\n"
  "exit 84\n";
static const char grant_failed[] =
  "grant_failed\n"
  "exit 1\n";
static const char approval_stale[] =
  "approval_stale\n"
  "exit 78\n";
static const char key_refused[] =
  "key_refused\n"
  "exit 1\n";
static const char no_anchor[] =
  "no_anchor\n"
  "exit 1\n";
static const char key_failed[] =
  "key_failed\n"
  "exit 1\n";
static const char frozen_reply[] =
  "frozen\n"
  "exit 89\n";
static const char suspended_reply[] =
  "suspended\n"
  "exit 90\n";
static const char no_shots[] =
  "no_shots\n"
  "exit 1\n";
static const char shots_done[] =
  "exit 0\n";
static const char shots_failed[] =
  "shots_failed\n"
  "exit 1\n";
/** The answer to an approval that could not be requested: a frozen console says so. **/
static const char *
approval_refused(void) {
  return store_frozen() ? frozen_reply : approval_busy;
}
static const char unknown_payload[] =
  "unknown_payload\n"
  "exit 1\n";

static const char ariel_pinned[] =
  "ariel_pinned\n"
  "exit 1\n";

static const char already_in_autoload[] =
  "already_in_autoload\n"
  "exit 1\n";

static const char not_in_autoload[] =
  "not_in_autoload\n"
  "exit 1\n";

static const char autoload_full[] =
  "autoload_full\n"
  "exit 1\n";

static const char autoload_failed[] =
  "autoload_failed\n"
  "exit 1\n";

static const char safe_boot_pending[] =
  "safe_boot_pending\n"
  "exit 1\n";
static const char unknown_approval[] =
  "unknown_approval\n"
  "exit 1\n";
static const char spawn_failed[] =
  "spawn_failed\n"
  "exit 1\n";
static const char audit_failed[] =
  "audit_failed\n"
  "exit 1\n";
static const char bad_signal[] =
  "bad_signal\n"
  "exit 1\n";
static const char no_such_process[] =
  "no_such_process\n"
  "exit 1\n";
static const char kill_failed[] =
  "kill_failed\n"
  "exit 1\n";
static const char protected_process[] =
  "protected\n"
  "exit 87\n";
static const char export_failed[] =
  "export_failed\n"
  "exit 1\n";
static const char value_too_long[] =
  "value_too_long\n"
  "exit 1\n";

// A session ID that is malformed, unknown or expired answers this one word,
// so a client knows to mint a new session whatever went wrong with this one.
static const char session_expired[] =
  "session_expired\n"
  "exit 93\n";
static const char session_full[] =
  "session_full\n"
  "exit 1\n";

/** Serializes the environment: setenv and getenv must not run at once. **/
static pthread_mutex_t environ_lock = PTHREAD_MUTEX_INITIALIZER;
static const char bad_argument[] =
  "bad_argument\n"
  "exit 1\n";
static const char too_large[] =
  "too_large\n"
  "exit 1\n";
static const char operation_failed[] =
  "operation_failed\n"
  "exit 1\n";

/** The signals kill accepts, by the name the owner reads. **/
static const struct {
  const char *name;
  int sig;
} kill_signals[] = {
  {"TERM", SIGTERM},
  {"KILL", SIGKILL},
  {"INT", SIGINT},
  {"HUP", SIGHUP},
};

static const char already_running[] =
  "already_running\n"
  "exit 1\n";

static const char too_many_runs[] =
  "too_many_runs\n"
  "exit 1\n";

static const char no_log[] =
  "no_log\n"
  "exit 1\n";

static const char log_failed[] =
  "log_failed\n"
  "exit 1\n";

static const char no_previous_version[] =
  "no_previous_version\n"
  "exit 1\n";

static const char rollback_failed[] =
  "rollback_failed\n"
  "exit 1\n";

static const char unsupported_kind[] =
  "unsupported_kind\n"
  "exit 1\n";

static const char health_unrecorded[] =
  "health_unrecorded\n"
  "exit 1\n";

static const char health_not_run[] =
  "health_not_run\n"
  "exit 1\n";

static const char health_partial[] =
  "health_partial\n"
  "exit 1\n";

static const char config_failed[] =
  "config_failed\n"
  "exit 1\n";

/** Whether text is a minus sign and at least one digit, as `-1` is. **/
static int
negative_number(const char *text) {
  if(text[0] != '-' || !text[1]) {
    return 0;
  }
  for(text++; *text; text++) {
    if(*text < '0' || *text > '9') {
      return 0;
    }
  }
  return 1;
}

static int
write_all(int fd, const char *buf, size_t len) {
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


/** The platform clock in milliseconds. **/
static int64_t
now_ms(platform_t *platform) {
  struct timespec now;

  platform->clock(platform, &now);

  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000L;
}


/** Throw away every wake a clock advance left in the pipe. **/
static void
wake_drain(int wake) {
  char buf[64];

  while(read(wake, buf, sizeof(buf)) > 0) {
  }
}


/**
 * Wait until fd is readable or the deadline passes. Returns 1 when it is
 * readable, 0 when the deadline passed, and -1 on error. The wait polls the
 * socket together with the connection's wake pipe, and the platform's clock
 * decides whether the deadline has passed: on the host the test clock moves
 * only when a scenario advances it, and an advance writes the pipe.
 **/
static int
wait_readable(platform_t *platform, int wake, int fd, int64_t deadline_ms) {
  while(1) {
    struct pollfd pfd[2];
    struct pollfd here;
    nfds_t nfds = 1;
    int64_t left;
    int rc;

    left = deadline_ms - now_ms(platform);
    if(left <= 0) {
      // The deadline ends an idle wait; it does not drop a line that is
      // already here. A caller reads a line a byte at a time, and an advance
      // between two bytes would otherwise lose the rest of a line that
      // arrived before it. The client cannot extend the wait this way: the
      // deadline above is absolute and the remaining bytes are already in
      // the socket.
      here.fd = fd;
      here.events = POLLIN;
      here.revents = 0;

      if(poll(&here, 1, 0) > 0 &&
         (here.revents & (POLLIN | POLLHUP | POLLERR))) {
        return 1;
      }
      return 0;
    }

    pfd[0].fd = fd;
    pfd[0].events = POLLIN;
    pfd[0].revents = 0;

    if(wake >= 0) {
      pfd[1].fd = wake;
      pfd[1].events = POLLIN;
      pfd[1].revents = 0;
      nfds = 2;
    }

    // With a test clock, real milliseconds are meaningless: only an
    // advance can pass the deadline, and that advance wakes this poll.
    if(wake >= 0 && platform->wake_idle) {
      platform->wake_idle(platform, wake, fd, 1);
    }
    rc = poll(pfd, nfds, wake >= 0 ? -1 : (int)left);
    if(wake >= 0 && platform->wake_idle) {
      platform->wake_idle(platform, wake, fd, 0);
    }
    if(rc < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }

    if(wake >= 0 && (pfd[1].revents & POLLIN)) {
      wake_drain(wake);
      continue;
    }

    if(pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      return 1;
    }

    if(rc == 0) {
      return 0;
    }
  }
}


/** The state a connection's deadline watchdog shares with its thread. **/
typedef struct {
  platform_t *platform;
  int wake;
  int64_t deadline;
  pthread_t target;
  pthread_t watchdog;
  int started;
  int fd;
  volatile int done;
  volatile int fired;
} deadline_watch_t;


/** One command line, answered in full, or cancelled by its deadline. **/
static void handle_command(agent_t *agent, int fd, int wake, char *line);

/**
 * The environment a child of this connection receives: the session's layer
 * over the process's, or NULL when there is no session or it set nothing.
 * Returns 0 when *envp is ready, or -1 when the copy cannot be made; the
 * caller frees a non-NULL result with free.
 **/
static int session_environ(const char *session_id, char ***envp);


/**
 * Stop the connection at its deadline. The watchdog does not read the
 * connection's wake pipe: an advance is one byte, and a second reader that
 * drained it would leave the connection asleep. With a test clock it looks
 * again a few real milliseconds later, since only a scenario can move that
 * clock, and marks the connection idle while it waits so a settle expects
 * it; on a console it waits out the remaining real time. When the deadline
 * passes, it marks the shared state and cancels the connection thread,
 * which answers timed_out from its cleanup handler.
 **/
static void *
deadline_watch(void *arg) {
  deadline_watch_t *watch = arg;

  while(!__atomic_load_n(&watch->done, __ATOMIC_ACQUIRE)) {
    int64_t left = watch->deadline - now_ms(watch->platform);

    if(left <= 0) {
      __atomic_store_n(&watch->fired, 1, __ATOMIC_RELEASE);
      pthread_cancel(watch->target);
      break;
    }

    if(watch->platform->wake_idle) {
      struct timespec brief = {0, 10 * 1000 * 1000L};

      // Check the socket as the connection's own wait does: a watched
      // connection with bytes to read is not idle, whatever this thread is
      // doing. The watchdog itself never reads the wake pipe.
      watch->platform->wake_idle(watch->platform, watch->wake, watch->fd, 1);
      nanosleep(&brief, NULL);
      watch->platform->wake_idle(watch->platform, watch->wake, watch->fd, 0);
    } else {
      poll(NULL, 0, left > INT_MAX ? INT_MAX : (int)left);
    }
  }

  return NULL;
}


/**
 * The connection thread was cancelled, or a command just returned. Join the
 * watchdog so the state can go, then answer timed_out when the deadline was
 * what stopped a command that had not finished.
 **/
static void
deadline_cleanup(void *arg) {
  deadline_watch_t *watch = arg;
  int was_done;
  int fired;

  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  was_done = __atomic_load_n(&watch->done, __ATOMIC_ACQUIRE);
  __atomic_store_n(&watch->done, 1, __ATOMIC_RELEASE);
  fired = __atomic_load_n(&watch->fired, __ATOMIC_ACQUIRE);

  if(watch->started) {
    pthread_cancel(watch->watchdog);
    pthread_join(watch->watchdog, NULL);
  }

  if(fired && !was_done) {
    write_all(watch->fd, timed_out_reply, sizeof(timed_out_reply) - 1);
  }

  free(watch);
}


/**
 * Run one command under the connection deadline. Returns normally when the
 * command finishes in time; on the deadline the thread is cancelled and
 * deadline_cleanup writes the answer.
 **/
static void
handle_bounded(agent_t *agent, int fd, int wake, char *line,
               int64_t deadline) {
  deadline_watch_t *watch;
  int oldstate;

  if(!(watch=calloc(1, sizeof(*watch)))) {
    handle_command(agent, fd, wake, line);
    return;
  }

  watch->platform = agent->platform;
  watch->wake = wake;
  watch->deadline = deadline;
  watch->target = pthread_self();
  watch->fd = fd;

  pthread_cleanup_push(deadline_cleanup, watch);

  if(!pthread_create(&watch->watchdog, NULL, deadline_watch, watch)) {
    watch->started = 1;
  }

  handle_command(agent, fd, wake, line);

  // Cancellation is off while the watchdog joins, so a deadline that
  // arrives in this window cannot make the handler join it twice.
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
  __atomic_store_n(&watch->done, 1, __ATOMIC_RELEASE);
  if(watch->started) {
    pthread_cancel(watch->watchdog);
    pthread_join(watch->watchdog, NULL);
  }
  pthread_cleanup_pop(0);
  free(watch);
  pthread_setcancelstate(oldstate, NULL);
}


/**
 * Read one line of at most LINE_LIMIT bytes, without the line ending.
 * Returns the length, -1 when the connection ended or the deadline passed,
 * or -2 when the line is too long.
 **/
static int
read_line(platform_t *platform, int wake, int fd, char *buf, size_t size,
          int64_t deadline_ms) {
  size_t len = 0;

  while(1) {
    char c;
    ssize_t n;
    int ready;

    ready = wait_readable(platform, wake, fd, deadline_ms);
    if(ready <= 0) {
      return -1;
    }

    n = read(fd, &c, 1);
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(n == 0) {
      return -1;
    }

    if(c == '\n') {
      if(len > 0 && buf[len - 1] == '\r') {
        len--;
      }
      buf[len] = '\0';
      return (int)len;
    }

    if(len + 1 >= size) {
      return -2;
    }
    buf[len++] = c;
  }
}


/**
 * Read and check the auth line. Returns 1 on a good token, 0 when the line
 * is missing or wrong (the connection is closed with exit 70), and -1 when
 * the line is over the limit (the connection is closed with no reply).
 **/
static int
authenticate(platform_t *platform, int wake, int fd, const char *token,
             int64_t deadline_ms) {
  char candidate[TOKEN_LEN];
  char line[AUTH_LINE_MAX + 1];
  int len;

  len = read_line(platform, wake, fd, line, sizeof(line), deadline_ms);
  if(len == -2) {
    return -1;
  }
  if(len != 5 + TOKEN_HEX_LEN || strncmp(line, "auth ", 5)) {
    return 0;
  }

  memcpy(candidate, line + 5, TOKEN_HEX_LEN);
  candidate[TOKEN_HEX_LEN] = '\0';

  return token_equal(candidate, token);
}


/**
 * Split line into tokens in place. Tokens are separated by spaces or tabs;
 * double and single quotes group a token and are removed; inside double
 * quotes \" and \\ escape, and inside single quotes nothing escapes. No
 * byte is globbed or expanded. Returns the number of tokens, max + 1 when
 * there is one token too many, or -1 when a quote is unbalanced.
 **/
static int
tokenize(char *line, char *argv[], int max) {
  char *src = line;
  char *dst = line;
  int argc = 0;
  int in_token = 0;

  while(*src) {
    char c = *src;

    if(c == ' ' || c == '\t') {
      if(in_token) {
        *dst++ = '\0';
        in_token = 0;
      }
      src++;
      continue;
    }

    if(!in_token) {
      if(argc == max) {
        return max + 1;
      }
      argv[argc++] = dst;
      in_token = 1;
    }

    if(c == '"' || c == '\'') {
      char quote = c;

      src++;
      while(*src && *src != quote) {
        if(quote == '"' && *src == '\\' &&
           (src[1] == '"' || src[1] == '\\')) {
          src++;
        }
        *dst++ = *src++;
      }
      if(!*src) {
        return -1;
      }
      src++;
    } else {
      *dst++ = *src++;
    }
  }

  if(in_token) {
    *dst++ = '\0';
  }

  return argc;
}


static int
parse_size(const char *text, uint64_t *size) {
  uint64_t value = 0;
  const char *p;

  if(!*text) {
    return -1;
  }

  for(p = text; *p; p++) {
    uint64_t digit;

    if(*p < '0' || *p > '9') {
      return -1;
    }
    digit = (uint64_t)(*p - '0');
    if(value > (UINT64_MAX - digit) / 10) {
      return -1;
    }
    value = value * 10 + digit;
  }

  *size = value;
  return 0;
}


/** Copy a 64-hex-digit hash into out in lowercase. **/
static int
parse_hash(const char *text, char out[SHA256_HEX_LEN + 1]) {
  size_t i;

  if(strlen(text) != SHA256_HEX_LEN) {
    return -1;
  }

  for(i=0; i<SHA256_HEX_LEN; i++) {
    char c = text[i];

    if(c >= 'A' && c <= 'F') {
      c = (char)(c - 'A' + 'a');
    }
    if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return -1;
    }
    out[i] = c;
  }

  out[SHA256_HEX_LEN] = '\0';
  return 0;
}


/**
 * Read the upload until the client's end of stream. Exactly size bytes are
 * written to outfd and hashed; anything past size is read and dropped, so
 * the reply still comes after the whole upload. Returns 0 on an end of
 * stream, -1 on a stall, error or overrun, and -2 when the file write fails.
 * buf holds READ_CHUNK bytes.
 **/
static int
upload_read_into(platform_t *platform, int wake, int fd, int outfd,
                 unsigned char *mem, uint64_t size, sha256_t *hash,
                 uint64_t *received, unsigned char *buf) {
  int64_t deadline = now_ms(platform) + UPLOAD_STALL_MS;
  uint64_t total = 0;

  while(1) {
    ssize_t n;
    int ready;

    ready = wait_readable(platform, wake, fd, deadline);
    if(ready <= 0) {
      *received = total;
      return -1;
    }

    n = read(fd, buf, READ_CHUNK);
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      *received = total;
      return -1;
    }
    if(n == 0) {
      break;
    }

    deadline = now_ms(platform) + UPLOAD_STALL_MS;

    {
      uint64_t room = size > total ? size - total : 0;
      size_t hashed = (uint64_t)n < room ? (size_t)n : (size_t)room;

      sha256_update(hash, buf, hashed);
      if(mem) {
        memcpy(mem + total, buf, hashed);
      } else if(hashed > 0 && write_all(outfd, (const char*)buf, hashed)) {
        *received = total;
        return -2;
      }
    }

    total += (uint64_t)n;
  }

  *received = total;
  return 0;
}


/**
 * upload_read_into with its chunk on the heap: a connection thread's stack
 * is CONNECTION_STACK, and a READ_CHUNK frame alone would overflow it.
 **/
static int
upload_read(platform_t *platform, int wake, int fd, int outfd,
            unsigned char *mem, uint64_t size, sha256_t *hash,
            uint64_t *received) {
  unsigned char *buf;
  int rc;

  if(!(buf=malloc(READ_CHUNK))) {
    *received = 0;
    return -1;
  }
  rc = upload_read_into(platform, wake, fd, outfd, mem, size, hash, received,
                        buf);
  free(buf);

  return rc;
}


static void
reply(int fd, const char *text) {
  write_all(fd, text, strlen(text));
}


/**
 * The question the owner answers: the approval, and the challenge that signs
 * it. The canonical action goes as hex, so no byte of it can be reshaped.
 **/
static void
challenge_reply(int fd, const approval_challenge_t *challenge) {
  char action_hex[2 * APPROVAL_ACTION_MAX + 1];
  char nonce_hex[2 * APPROVAL_NONCE_LEN + 1];
  char answer[2 * APPROVAL_ACTION_MAX + 512];
  int len;

  approval_hex_encode((const unsigned char*)challenge->action,
                      challenge->action_len, action_hex);
  approval_hex_encode(challenge->nonce, sizeof(challenge->nonce), nonce_hex);

  len = snprintf(answer, sizeof(answer),
                 "approval_required %s\n"
                 "challenge %s %s %s %llu %llu %s %u\nexit 75\n",
                 challenge->id, challenge->id, challenge->console, nonce_hex,
                 (unsigned long long)challenge->issued_ms,
                 (unsigned long long)challenge->expires_ms, action_hex,
                 (unsigned)challenge->generation);
  write_all(fd, answer, (size_t)len);
}


/** The answer for one file command's outcome: its word and exit, or ok. **/
static void
outcome_text(int rc, char *out, size_t size) {
  if(rc == FILEOPS_OK) {
    snprintf(out, size, "exit 0\n");
    return;
  }
  snprintf(out, size, "%s\nexit %d\n", fileops_word(rc), fileops_status(rc));
}


static const char *
outcome_event(int rc) {
  switch(rc) {
  case FILEOPS_OK:
    return "done";
  case FILEOPS_PROTECTED:
    return "protected";
  case FILEOPS_CHANGED:
    return "stale";
  case FILEOPS_FAILED:
    return "failed";
  default:
    return "refused";
  }
}


/**
 * The longest audit subject of a transfer, source and destination with '>'
 * between them. Two paths that would not fit one audit line are refused.
 **/
#define TRANSFER_SUBJECT_MAX 180


/**
 * Whether subject is one path, or a source and a destination joined by '>'.
 **/
static int
subject_ok(const char *subject) {
  const char *gt = strchr(subject, '>');
  char source[APPROVAL_TARGET_MAX + 1];
  size_t n;

  if(!gt) {
    return approval_target_valid(subject);
  }

  n = (size_t)(gt - subject);
  if(n > APPROVAL_TARGET_MAX) {
    return 0;
  }
  memcpy(source, subject, n);
  source[n] = '\0';
  return approval_target_valid(source) && approval_target_valid(gt + 1);
}


/**
 * The subject an action is audited under: its target alone, or its target and
 * destination. Paths that are not valid targets are logged as "-".
 **/
static const char *
subject_of(const char *target, const char *destination, char *out) {
  if(!destination[0]) {
    return target;
  }
  if(!approval_target_valid(target) || !approval_target_valid(destination)) {
    return "-";
  }
  if(snprintf(out, TRANSFER_SUBJECT_MAX + 1, "%s>%s", target, destination)
     > TRANSFER_SUBJECT_MAX) {
    return "-";
  }
  return out;
}


/**
 * Append one line for command's event: "<command>.<event> <subject> <id> none".
 * An invalid subject is logged as "-", so no argument can reshape the line.
 **/
static int
audit_line(const char *command, const char *event, const char *target,
           const char *id) {
  char kind[64];
  const char *name = subject_ok(target) ? target : "-";

  snprintf(kind, sizeof(kind), "%s.%s", command, event);
  return store_audit_append(kind, name, id, APPROVAL_NO_HASH);
}


/**
 * Record one action or refusal, then answer it. The line lands before the
 * answer, so an action the log cannot record is never reported as done.
 **/
static void
audit_reply(int fd, const char *command, const char *event,
            const char *target, const char *id, const char *answer) {
  if(audit_line(command, event, target, id)) {
    reply(fd, audit_failed);
    return;
  }
  reply(fd, answer);
}


static void
file_outcome(int fd, const char *command, const char *target, const char *id,
             int rc) {
  char text[64];

  outcome_text(rc, text, sizeof(text));
  audit_reply(fd, command, outcome_event(rc), target, id, text);
}


/**
 * Decide whether a gated command may run now. Returns 1 when the owner signed
 * these facts: the approval is spent by that answer and the caller acts.
 * Otherwise the answer is written here and 0 is returned.
 **/
static int
gate_pass_with(agent_t *agent, int fd, const approval_facts_t *facts,
               approval_challenge_t *challenge, int (*vet)(void *), void *ctx) {
  char subject[TRANSFER_SUBJECT_MAX + 1];
  const char *target = subject_of(facts->target, facts->dest, subject);
  int rc;

  switch(store_gate_check(facts, challenge)) {
  case STORE_GATE_GO:
    return 1;
  case STORE_GATE_PENDING:
    challenge_reply(fd, challenge);
    return 0;
  case STORE_GATE_STALE:
    audit_reply(fd, facts->command, "stale", target, challenge->id,
                approval_stale);
    return 0;
  case STORE_GATE_DENIED:
    audit_reply(fd, facts->command, "denied", target, challenge->id,
                approval_denied);
    return 0;
  case STORE_GATE_REFUSED:
    audit_reply(fd, facts->command, "refused", target, "-", unknown);
    return 0;
  case STORE_GATE_KEYRING:
    audit_reply(fd, facts->command, "refused", target, "-",
                store_anchor_missing() ? no_anchor : key_refused);
    return 0;
  case STORE_GATE_FROZEN:
    audit_reply(fd, facts->command, "refused", target, "-", frozen_reply);
    return 0;
  default:
    break;
  }

  if(vet) {
    rc = vet(ctx);
    if(rc) {
      file_outcome(fd, facts->command, target, "-", rc);
      return 0;
    }
  }

  if(agent->platform->approval_request(agent->platform, facts, challenge)) {
    reply(fd, approval_refused());
    return 0;
  }

  if(audit_line(facts->command, "request", target, challenge->id)) {
    store_approval_deny(challenge->id);
    reply(fd, audit_failed);
    return 0;
  }

  challenge_reply(fd, challenge);
  return 0;
}


static int
gate_pass(agent_t *agent, int fd, const approval_facts_t *facts,
          approval_challenge_t *challenge) {
  return gate_pass_with(agent, fd, facts, challenge, NULL, NULL);
}


/**
 * One file command on one absolute path: mkdir, rmdir, touch, rm, or chmod,
 * chown or chgrp with its operand. operand is NULL for the first four. A
 * recursive rm takes the whole tree below path.
 **/
/**
 * The longest path a gated action can name. The canonical action refuses a
 * longer target, so a resolved path that does not fit is refused here, with
 * the word a path refusal already answers, rather than cut to size.
 **/
#define GATED_PATH_MAX (APPROVAL_TARGET_MAX + 1)


/** Resolve one operand against the session's directory, answering the
    refusal itself when it cannot. Returns NULL once it has. **/
static const char *
session_operand(runner_session_t *session, const char *path, char *buf,
                size_t size, int fd) {
  // The resolver writes the word; a refused path exits 1, and the reply is
  // not finished until its status line follows.
  static const char refusal_exit[] = "exit 1\n";

  if(runner_resolve(session, path, buf, size, fd)) {
    reply(fd, refusal_exit);
    return NULL;
  }
  return buf;
}


static void
file_command(agent_t *agent, int fd, runner_session_t *session,
             const char *command, const char *path, const char *operand,
             int recursive) {
  const char *root = agent->platform->fs_root;
  char resolved[GATED_PATH_MAX];
  approval_challenge_t challenge;
  approval_facts_t facts;
  int rc;

  if(!(path=session_operand(session, path, resolved, sizeof(resolved), fd))) {
    return;
  }

  memset(&facts, 0, sizeof(facts));
  facts.recursive = recursive;
  rc = recursive ? fileops_tree_check(root, path, &facts) :
       fileops_check(root, command, path, operand, &facts);
  if(rc != FILEOPS_OK) {
    file_outcome(fd, command, path, "-", rc);
    return;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", command);
  snprintf(facts.target, sizeof(facts.target), "%s", path);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  rc = recursive ? fileops_tree_act(root, path, &facts) :
       fileops_act(root, command, path, operand, &facts);
  file_outcome(fd, command, path, challenge.id, rc);
}


/**
 * One transfer, cp, mv or ln, from source to destination: two absolute paths.
 * A recursive cp takes the whole tree below source.
 **/
static void
transfer_command(agent_t *agent, int fd, runner_session_t *session,
                 const char *command, const char *source,
                 const char *destination, int recursive) {
  const char *root = agent->platform->fs_root;
  char resolved_source[GATED_PATH_MAX];
  char resolved_destination[GATED_PATH_MAX];
  char subject[TRANSFER_SUBJECT_MAX + 1];
  approval_challenge_t challenge;
  approval_facts_t facts;
  int rc;

  if(!(source=session_operand(session, source, resolved_source,
                              sizeof(resolved_source), fd)) ||
     !(destination=session_operand(session, destination,
                                   resolved_destination,
                                   sizeof(resolved_destination), fd))) {
    return;
  }

  if(strlen(source) + strlen(destination) + 1 > TRANSFER_SUBJECT_MAX) {
    file_outcome(fd, command, "-", "-", FILEOPS_BAD_PATH);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  facts.recursive = recursive;
  rc = recursive ?
       fileops_tree_transfer_check(root, source, destination, &facts) :
       fileops_transfer_check(root, source, destination, &facts);
  if(rc != FILEOPS_OK) {
    file_outcome(fd, command, subject_of(source, destination, subject), "-",
                 rc);
    return;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", command);
  snprintf(facts.target, sizeof(facts.target), "%s", source);
  snprintf(facts.dest, sizeof(facts.dest), "%s", destination);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  rc = recursive ?
       fileops_tree_transfer_act(root, source, destination, &facts) :
       fileops_transfer_act(root, command, source, destination, &facts);
  file_outcome(fd, command, subject_of(source, destination, subject),
               challenge.id, rc);
}


/**
 * The options of the file commands. rm -r and cp -r take the tree below their
 * operands; any other option answers bad_option and asks nobody. Returns 1
 * when the line was answered here.
 **/
static int
file_options(agent_t *agent, int fd, runner_session_t *session, int argc,
             char *argv[]) {
  int cp = !strcmp(argv[0], "cp");
  int recursive;
  int i;

  if(!cp && strcmp(argv[0], "rm") && strcmp(argv[0], "mkdir") &&
     strcmp(argv[0], "rmdir") && strcmp(argv[0], "touch") &&
     strcmp(argv[0], "mv") && strcmp(argv[0], "ln")) {
    return 0;
  }

  recursive = argc >= 2 && !strcmp(argv[1], "-r") &&
              (cp || !strcmp(argv[0], "rm"));
  if(recursive) {
    int operands = argc - 2;

    // Every operand of a recursive command is an absolute path, so a dash-led
    // word after -r is an option the command does not take: it is answered
    // before the operands are counted, not as a bad argument.
    for(i=2; i<argc; i++) {
      if(argv[i][0] == '-') {
        audit_reply(fd, argv[0], "refused", "-", "-", bad_option);
        return 1;
      }
    }
    if(operands < (cp ? 2 : 1)) {
      audit_reply(fd, argv[0], "refused", "-", "-", missing_operand);
    } else if(operands > (cp ? 2 : 1)) {
      audit_reply(fd, argv[0], "refused", "-", "-", bad_argument);
    } else if(cp) {
      transfer_command(agent, fd, session, "cp", argv[2], argv[3], 1);
    } else {
      file_command(agent, fd, session, "rm", argv[2], NULL, 1);
    }
    return 1;
  }

  for(i=1; i<argc; i++) {
    if(argv[i][0] == '-') {
      audit_reply(fd, argv[0], "refused", "-", "-", bad_option);
      return 1;
    }
  }
  return 0;
}


/** unzip -l ARCHIVE: the members and their sizes, at once. Nothing is written, so nothing is asked. **/
static void
unzip_list(agent_t *agent, int fd, runner_session_t *session,
           const char *archive) {
  char resolved[PATH_MAX];
  const char *root = agent->platform->fs_root;
  char *text = NULL;
  size_t len = 0;
  int rc;

  if(!(archive=session_operand(session, archive, resolved, sizeof(resolved),
                               fd))) {
    return;
  }

  rc = fileops_unzip_list(root, archive, &text, &len);
  if(rc) {
    free(text);
    file_outcome(fd, "unzip", archive, "-", rc);
    return;
  }

  if(audit_line("unzip", "list", archive, "-")) {
    reply(fd, audit_failed);
  } else {
    write_all(fd, text, len);
    reply(fd, "exit 0\n");
  }
  free(text);
}


/** The member names a listing collects, so an archive that is not one answers alone. **/
#define TAR_LIST_MAX 8192

struct tar_list {
  char text[TAR_LIST_MAX];
  size_t len;
};


static int
list_member(void *ctx, const tar_member_t *member) {
  struct tar_list *list = ctx;
  size_t room = sizeof(list->text) - list->len;
  int n = snprintf(list->text + list->len, room, "%s\n", member->name);

  if(n < 0 || (size_t)n >= room) {
    return FILEOPS_FAILED;
  }
  list->len += (size_t)n;
  return FILEOPS_OK;
}


/** tar -t ARCHIVE: every member name at once, in archive order. **/
static void
tar_list_command(agent_t *agent, int fd, runner_session_t *session,
                 const char *path) {
  char resolved[PATH_MAX];
  struct tar_list list;
  int archive;
  int rc;

  if(!(path=session_operand(session, path, resolved, sizeof(resolved), fd))) {
    return;
  }

  rc = fileops_read_open(agent->platform->fs_root, path, &archive);
  if(rc) {
    file_outcome(fd, "tar", path, "-", rc);
    return;
  }

  list.len = 0;
  rc = tar_walk(archive, list_member, &list);
  close(archive);
  if(rc) {
    file_outcome(fd, "tar", path, "-", rc);
    return;
  }

  if(audit_line("tar", "list", path, "-")) {
    reply(fd, audit_failed);
    return;
  }
  write_all(fd, list.text, list.len);
  reply(fd, "exit 0\n");
}


static int
tar_vet_job(void *ctx) {
  return tar_vet(ctx);
}


/**
 * unzip ARCHIVE DEST: extract a stored archive under DEST, after the owner signs
 * its hash and DEST. Every member is checked before the first one is written.
 **/
static void
unzip_command(agent_t *agent, int fd, runner_session_t *session,
              const char *archive, const char *destination) {
  char resolved_archive[GATED_PATH_MAX];
  char resolved_dest[GATED_PATH_MAX];
  const char *root = agent->platform->fs_root;
  char subject[TRANSFER_SUBJECT_MAX + 1];
  approval_challenge_t challenge;
  approval_facts_t facts;
  int rc;

  if(!(archive=session_operand(session, archive, resolved_archive,
                               sizeof(resolved_archive), fd)) ||
     !(destination=session_operand(session, destination, resolved_dest,
                                   sizeof(resolved_dest), fd))) {
    return;
  }

  if(strlen(archive) + strlen(destination) + 1 > TRANSFER_SUBJECT_MAX) {
    file_outcome(fd, "unzip", "-", "-", FILEOPS_BAD_PATH);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  rc = fileops_unzip_check(root, archive, destination, &facts);
  if(rc != FILEOPS_OK) {
    file_outcome(fd, "unzip", subject_of(archive, destination, subject), "-",
                 rc);
    return;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", "unzip");
  snprintf(facts.target, sizeof(facts.target), "%s", archive);
  snprintf(facts.dest, sizeof(facts.dest), "%s", destination);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  rc = fileops_unzip_act(root, archive, destination, &facts);
  file_outcome(fd, "unzip", subject_of(archive, destination, subject),
               challenge.id, rc);
}


/**
 * tar -x ARCHIVE DEST: extracts after the owner signs the archive's hash and
 * the destination. A member that escapes the destination is refused before
 * the owner is asked, and an approved archive is extracted only if it is
 * still the object that was signed.
 **/
static void
tar_extract_command(agent_t *agent, int fd, runner_session_t *session,
                    const char *archive, const char *dest) {
  char resolved_archive[GATED_PATH_MAX];
  char resolved_dest[GATED_PATH_MAX];
  const char *root = agent->platform->fs_root;
  char subject[TRANSFER_SUBJECT_MAX + 1];
  approval_challenge_t challenge;
  approval_facts_t facts;
  tar_job_t job;
  int go;
  int rc;

  if(!(archive=session_operand(session, archive, resolved_archive,
                               sizeof(resolved_archive), fd)) ||
     !(dest=session_operand(session, dest, resolved_dest,
                            sizeof(resolved_dest), fd))) {
    return;
  }

  if(strlen(archive) + strlen(dest) + 1 > TRANSFER_SUBJECT_MAX) {
    file_outcome(fd, "tar", "-", "-", FILEOPS_BAD_PATH);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  rc = tar_open(root, archive, dest, &job, &facts);
  if(rc) {
    file_outcome(fd, "tar", subject_of(archive, dest, subject), "-", rc);
    return;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", "tar");
  snprintf(facts.target, sizeof(facts.target), "%s", archive);
  snprintf(facts.dest, sizeof(facts.dest), "%s", dest);
  go = gate_pass_with(agent, fd, &facts, &challenge, tar_vet_job, &job);
  tar_close(&job);
  if(!go) {
    return;
  }

  rc = tar_extract(root, archive, dest, &facts);
  file_outcome(fd, "tar", subject_of(archive, dest, subject), challenge.id, rc);
}


static void
tar_command(agent_t *agent, int fd, runner_session_t *session, int argc,
            char *argv[]) {
  if(argc == 3 && !strcmp(argv[1], "-t")) {
    tar_list_command(agent, fd, session, argv[2]);
    return;
  }
  if(argc == 4 && !strcmp(argv[1], "-x")) {
    tar_extract_command(agent, fd, session, argv[2], argv[3]);
    return;
  }
  file_outcome(fd, "tar", "-", "-", FILEOPS_BAD_ARG);
}


/**
 * A command nothing implements. The owner is asked about it like any other;
 * once signed it still does nothing, and the answer is unknown_command.
 **/
static void
unlisted_command(agent_t *agent, int fd, int argc, char *argv[]) {
  approval_challenge_t challenge;
  approval_facts_t facts;

  if(strlen(argv[0]) > APPROVAL_TARGET_MAX) {
    audit_reply(fd, "unlisted", "refused", "-", "-", unknown);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "unlisted");
  snprintf(facts.target, sizeof(facts.target), "%s", argv[0]);
  facts.argc = (uint64_t)argc;

  if(gate_pass(agent, fd, &facts, &challenge)) {
    audit_reply(fd, "unlisted", "refused", argv[0], challenge.id, unknown);
  }
}


/**
 * The first PATH entry that holds a file the run may take for name, in path.
 * An entry without the name, a file without an execute bit or a directory is
 * skipped, as a shell skips it. Returns FILEOPS_NOT_RUNNABLE when none does.
 **/
static int
elf_lookup(const char *root, const char *name, char *path, size_t size,
           approval_facts_t *facts, unsigned char **bytes, size_t *len) {
  const char *dirs = getenv("PATH");

  while(dirs && *dirs) {
    const char *colon = strchr(dirs, ':');
    size_t n = colon ? (size_t)(colon - dirs) : strlen(dirs);
    int rc;

    while(n > 0 && dirs[n - 1] == '/') {
      n--;
    }
    if(n > 0 && dirs[0] == '/' && n + strlen(name) + 2 <= size) {
      snprintf(path, size, "%.*s/%s", (int)n, dirs, name);
      rc = fileops_run_load(root, path, facts, bytes, len);
      if(rc != FILEOPS_NO_FILE && rc != FILEOPS_NOT_FILE &&
         rc != FILEOPS_NOT_EXEC && rc != FILEOPS_NOT_RUNNABLE &&
         rc != FILEOPS_BAD_PATH) {
        return rc;
      }
    }
    dirs = colon ? colon + 1 : NULL;
  }
  return FILEOPS_NOT_RUNNABLE;
}


/**
 * Copy a run's arguments, after its name, into facts. Returns -1 when there
 * are more than RUN_ARGS_MAX or one is longer than max, and -2 when one
 * carries a byte outside printable ASCII.
 **/
static int
run_arguments(approval_facts_t *facts, int argc, char *argv[], size_t max) {
  int i;

  if(argc - 1 > RUN_ARGS_MAX) {
    return -1;
  }
  facts->argc = (uint64_t)(argc - 1);
  for(i=1; i<argc; i++) {
    if(strlen(argv[i]) > max) {
      return -1;
    }
    if(!approval_arg_valid(argv[i])) {
      return -2;
    }
    snprintf(facts->arg[i - 1], sizeof(facts->arg[i - 1]), "%s", argv[i]);
  }
  return 0;
}


static int
audit_status(const char *path, const char *id, int status) {
  char sha256[32];
  const char *name = approval_target_valid(path) ? path : "-";

  snprintf(sha256, sizeof(sha256), "status-%d", status);
  return store_audit_append("run.status", name, id, sha256);
}


/**
 * One run of an executable, by absolute path or by a bare name on the PATH.
 * The owner signs the resolved path, the file's hash and the arguments, and
 * the bytes that were hashed are the bytes that run. Returns 0 when the name
 * is not an executable this platform runs, so the caller treats it as unlisted.
 **/
static int
elf_command(agent_t *agent, int fd, int argc, char *argv[],
            const char *session_id) {
  const char *root = agent->platform->fs_root;
  char path[PATH_MAX];
  approval_challenge_t challenge;
  approval_facts_t facts;
  unsigned char *bytes = NULL;
  char **envp = NULL;
  size_t size = 0;
  char answer[64];
  int status = 0;
  int rc;
  int len;

  if(strlen(argv[0]) > APPROVAL_TARGET_MAX) {
    return 0;
  }

  memset(&facts, 0, sizeof(facts));
  if(argv[0][0] == '/') {
    snprintf(path, sizeof(path), "%s", argv[0]);
    rc = fileops_run_load(root, path, &facts, &bytes, &size);
  } else if(strchr(argv[0], '/')) {
    return 0;
  } else {
    rc = elf_lookup(root, argv[0], path, sizeof(path), &facts, &bytes, &size);
  }

  if(rc == FILEOPS_NOT_RUNNABLE) {
    return 0;
  }
  if(rc != FILEOPS_OK) {
    file_outcome(fd, "run", path, "-", rc);
    return 1;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", "run");
  if(snprintf(facts.target, sizeof(facts.target), "%s", path)
     >= (int)sizeof(facts.target)) {
    // A PATH lookup found a path longer than a target: it cannot be approved.
    free(bytes);
    audit_reply(fd, "run", "refused", "-", "-", unknown);
    return 1;
  }
  {
    int arg_error = run_arguments(&facts, argc, argv, APPROVAL_VALUE_MAX);

    if(arg_error) {
      free(bytes);
      audit_reply(fd, "run", "refused", path, "-",
                  arg_error == -2 ? bad_path : unknown);
      return 1;
    }
  }
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    free(bytes);
    return 1;
  }

  if(audit_line("run", "start", path, challenge.id)) {
    free(bytes);
    reply(fd, audit_failed);
    return 1;
  }

  argv[argc] = NULL;
  if(session_environ(session_id, &envp)) {
    free(bytes);
    reply(fd, spawn_failed);
    return 1;
  }
  if(agent->platform->spawn(agent->platform, bytes, size, argv, envp, fd,
                            &status)) {
    free(envp);
    free(bytes);
    audit_line("run", "failed", path, challenge.id);
    reply(fd, spawn_failed);
    return 1;
  }
  free(envp);
  free(bytes);

  if(audit_status(path, challenge.id, status)) {
    reply(fd, audit_failed);
    return 1;
  }

  len = snprintf(answer, sizeof(answer), "status %d\nexit 0\n", status);
  write_all(fd, answer, (size_t)len);
  return 1;
}


/**
 * chmod MODE PATH, chown ID PATH and chgrp ID PATH, gated like the other file
 * commands. More than one path is not one of them, so it is unlisted.
 **/
static void
attribute_command(agent_t *agent, int fd, runner_session_t *session, int argc,
                  char *argv[]) {
  int i;

  // chmod, chown and chgrp take a mode and a path, and no option at all: a
  // dash-led word is answered before anything else, so the owner is never
  // asked for something that cannot run. A negative id in the first slot is
  // an operand and not an option (`chown -1 PATH` answers bad_owner), and the
  // path is absolute in every other slot, so a dash there is an option.
  for(i=2; i<argc; i++) {
    if(argv[i][0] == '-') {
      audit_reply(fd, argv[0], "refused", "-", "-", bad_option);
      return;
    }
  }
  if(argc >= 2 && argv[1][0] == '-' && !negative_number(argv[1])) {
    audit_reply(fd, argv[0], "refused", "-", "-", bad_option);
    return;
  }
  if(argc < 3) {
    audit_reply(fd, argv[0], "refused", "-", "-", missing_operand);
    return;
  }
  if(argc > 3) {
    unlisted_command(agent, fd, argc, argv);
    return;
  }
  file_command(agent, fd, session, argv[0], argv[2], argv[1], 0);
}


static int
system_name(const char *command) {
  return !strcmp(command, "mount") || !strcmp(command, "umount") ||
         !strcmp(command, "chroot") || !strcmp(command, "mknod");
}


/**
 * One gated system command. Its arguments and target are checked before the
 * owner is asked, and the check is made again after the signature, before the
 * platform acts.
 **/
static void
system_command(agent_t *agent, int fd, int argc, char *argv[]) {
  const char *root = agent->platform->fs_root;
  approval_challenge_t challenge;
  approval_facts_t facts;
  int act;
  int rc;

  memset(&facts, 0, sizeof(facts));
  rc = fileops_system_parse(argc, argv, &facts);
  if(rc == FILEOPS_OK) {
    rc = fileops_system_check(root, &facts);
  }
  if(rc != FILEOPS_OK) {
    file_outcome(fd, argv[0], facts.target, "-", rc);
    return;
  }

  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  rc = fileops_system_recheck(root, &facts);
  if(rc == FILEOPS_OK) {
    act = agent->platform->system_act(agent->platform, &facts);
    if(act == 1) {
      audit_reply(fd, facts.command, "unavailable", facts.target,
                  challenge.id, "not available on this platform\nexit 1\n");
      return;
    }
    rc = act ? FILEOPS_FAILED : FILEOPS_OK;
  }
  file_outcome(fd, facts.command, facts.target, challenge.id, rc);
}


static void
hash_hex(const void *data, size_t len, char hex[SHA256_HEX_LEN + 1]) {
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;

  sha256_init(&hash);
  sha256_update(&hash, data, len);
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
}


/** The hash of each argument followed by a NUL, so no two lists share one. **/
static void
args_hash(int argc, char *argv[], char hex[SHA256_HEX_LEN + 1]) {
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;
  int i;

  sha256_init(&hash);
  for(i=0; i<argc; i++) {
    sha256_update(&hash, argv[i], strlen(argv[i]) + 1);
  }
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
}


/** A variable name: a letter or '_', then letters, digits or '_'. **/
static int
env_name_valid(const char *name) {
  size_t i;

  if(!name[0] || strlen(name) > ENV_NAME_MAX) {
    return 0;
  }

  for(i=0; name[i]; i++) {
    int c = (unsigned char)name[i];
    int letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';

    if(!letter && !(i > 0 && c >= '0' && c <= '9')) {
      return 0;
    }
  }
  return 1;
}


/**
 * key rotate <primary> and key rotate-recovery <recovery>: the key of role is
 * replaced, signed by the key that role names.
 **/
static void
key_rotate_command(agent_t *agent, int fd, int role, const char *hex) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  const char *command;
  char answer[32];
  uint32_t generation = 0;

  command = role == STORE_KEY_ROLE_RECOVERY ? "key.rotate-recovery"
                                            : "key.rotate";
  // A build with no anchor refuses the key before the key's own merits are
  // judged: there is no keyring to rotate, and key_refused would send the
  // owner to look for a keyring problem that is not there.
  if(store_anchor_missing()) {
    audit_reply(fd, command, "refused", "keyring", "-", no_anchor);
    return;
  }
  if(store_key_check(hex)) {
    audit_reply(fd, command, "refused", "keyring", "-", key_refused);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", command);
  snprintf(facts.target, sizeof(facts.target), "%s", "keyring");
  snprintf(facts.arg[0], sizeof(facts.arg[0]), "%s", hex);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  switch(store_key_rotate(&challenge, hex, role, &generation)) {
  case STORE_KEY_ROTATED:
    snprintf(answer, sizeof(answer), "key_rotated %u\nexit 0\n",
             (unsigned)generation);
    reply(fd, answer);
    return;
  case STORE_KEY_STALE:
    audit_reply(fd, command, "stale", "keyring", challenge.id, approval_stale);
    return;
  case STORE_KEY_UNRECORDED:
    reply(fd, audit_failed);
    return;
  default:
    audit_reply(fd, command, "failed", "keyring", challenge.id, key_failed);
    return;
  }
}


/**
 * key adopt-anchor: the keyring takes the build's anchor as its keys, for the
 * owner's signature by the anchor's recovery key.
 **/
static void
key_adopt_command(agent_t *agent, int fd) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  unsigned char primary[APPROVAL_PUBKEY_LEN];
  unsigned char recovery[APPROVAL_PUBKEY_LEN];
  const char *command = "key.adopt-anchor";
  char answer[32];
  uint32_t generation = 0;

  if(agent->platform->anchor(agent->platform, primary, recovery)) {
    audit_reply(fd, command, "refused", "keyring", "-", no_anchor);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", command);
  snprintf(facts.target, sizeof(facts.target), "%s", "keyring");
  approval_hex_encode(primary, APPROVAL_PUBKEY_LEN, facts.arg[0]);
  approval_hex_encode(recovery, APPROVAL_PUBKEY_LEN, facts.arg[1]);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  switch(store_key_adopt(&challenge, &generation)) {
  case STORE_KEY_ADOPTED:
    snprintf(answer, sizeof(answer), "key_adopted %u\nexit 0\n",
             (unsigned)generation);
    reply(fd, answer);
    return;
  case STORE_KEY_STALE:
    audit_reply(fd, command, "stale", "keyring", challenge.id, approval_stale);
    return;
  case STORE_KEY_REFUSED:
    audit_reply(fd, command, "refused", "keyring", challenge.id, key_refused);
    return;
  case STORE_KEY_UNRECORDED:
    reply(fd, audit_failed);
    return;
  default:
    audit_reply(fd, command, "failed", "keyring", challenge.id, key_failed);
    return;
  }
}


/**
 * key revoke --since N <primary>: the recovery key declares every primary from
 * generation N on compromised. Their grants are suspended and primary becomes
 * the next generation's primary. It passes while frozen.
 **/
static void
key_revoke_command(agent_t *agent, int fd, const char *since_text,
                   const char *hex) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  const char *command = "key.revoke";
  unsigned long long since = 0;
  char answer[32];
  uint32_t generation = 0;
  size_t i;

  for(i=0; since_text[i]; i++) {
    if(i == 10 || since_text[i] < '0' || since_text[i] > '9') {
      break;
    }
    since = since * 10 + (unsigned)(since_text[i] - '0');
  }
  if(!i || since_text[i] || since > UINT32_MAX) {
    reply(fd, bad_argument);
    return;
  }

  if(store_revoke_check((uint32_t)since, hex)) {
    audit_reply(fd, command, "refused", "keyring", "-", key_refused);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", command);
  snprintf(facts.target, sizeof(facts.target), "%s", "keyring");
  snprintf(facts.arg[0], sizeof(facts.arg[0]), "%llu", since);
  snprintf(facts.arg[1], sizeof(facts.arg[1]), "%s", hex);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  switch(store_key_revoke(&challenge, (uint32_t)since, hex, &generation)) {
  case STORE_KEY_REVOKED:
    snprintf(answer, sizeof(answer), "key_revoked %u\nexit 0\n",
             (unsigned)generation);
    reply(fd, answer);
    return;
  case STORE_KEY_STALE:
    audit_reply(fd, command, "stale", "keyring", challenge.id, approval_stale);
    return;
  case STORE_KEY_REFUSED:
    audit_reply(fd, command, "refused", "keyring", challenge.id, key_refused);
    return;
  case STORE_KEY_UNRECORDED:
    reply(fd, audit_failed);
    return;
  default:
    audit_reply(fd, command, "failed", "keyring", challenge.id, key_failed);
    return;
  }
}


/** key unfreeze: lifts the owner's freeze, signed by the recovery key. **/
static void
key_unfreeze_command(agent_t *agent, int fd) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  char answer[32];
  uint32_t generation = 0;

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "key.unfreeze");
  snprintf(facts.target, sizeof(facts.target), "%s", "keyring");
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  switch(store_key_unfreeze(&challenge, &generation)) {
  case STORE_UNFREEZE_OK:
    snprintf(answer, sizeof(answer), "key_unfrozen %u\nexit 0\n",
             (unsigned)generation);
    reply(fd, answer);
    return;
  case STORE_UNFREEZE_STALE:
    audit_reply(fd, "key.unfreeze", "stale", "keyring", challenge.id,
                approval_stale);
    return;
  case STORE_UNFREEZE_UNRECORDED:
    reply(fd, audit_failed);
    return;
  default:
    audit_reply(fd, "key.unfreeze", "failed", "keyring", challenge.id,
                key_failed);
    return;
  }
}


/** NAME=value from the process environment, as env always answered it. **/
static int
process_env_line(const char *name, char *line, size_t size) {
  const char *value;
  int len = 0;

  pthread_mutex_lock(&environ_lock);
  value = getenv(name);
  if(value) {
    len = snprintf(line, size, "%s=%s\n", name, value);
  }
  pthread_mutex_unlock(&environ_lock);

  return len;
}


/**
 * env NAME: reveals the one variable the owner signed for. Inside a session
 * the answer is the layered view a payload started there would see, the
 * session's map over the process environment; outside one it is the process
 * environment, as it always was.
 **/
static void
env_command(agent_t *agent, int fd, const char *name, const char *session_id) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  char line[ENV_LINE_MAX];
  char session_line[SESSION_ENV_ASSIGN_MAX + 2];
  char value[SESSION_ENV_ASSIGN_MAX + 1];
  char *text = line;
  size_t room = sizeof(line);
  int len = 0;

  if(!env_name_valid(name)) {
    audit_reply(fd, "env", "refused", name, "-", bad_name);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "env");
  snprintf(facts.target, sizeof(facts.target), "%s", name);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  if(session_id) {
    int held = store_session_env_get(session_id, name, value, sizeof(value));

    if(held < 0) {
      // The session the prefix named is gone: the map went with it.
      reply(fd, session_expired);
      return;
    }
    if(held) {
      // A session's assignment is a whole line of its own, up to the limit
      // export holds it at, so the answer is never cut.
      text = session_line;
      room = sizeof(session_line);
      len = snprintf(text, room, "%s=%s\n", name, value);
    } else {
      len = process_env_line(name, line, sizeof(line));
    }
  } else {
    len = process_env_line(name, line, sizeof(line));
  }

  if(len < 0 || (size_t)len >= room) {
    audit_reply(fd, "env", "failed", name, challenge.id, value_too_long);
    return;
  }

  if(audit_line("env", "done", name, challenge.id)) {
    reply(fd, audit_failed);
    return;
  }
  write_all(fd, text, (size_t)len);
  reply(fd, "exit 0\n");
}


/**
 * export NAME=VALUE: sets the one variable the owner signed the value of.
 * Inside a session the value lands in that session's map and the signed
 * action says so; outside one it sets the process variable, as it always
 * did, so nothing leaks between the two.
 **/
static void
export_command(agent_t *agent, int fd, const char *assign,
               const char *session_id) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  char name[ENV_NAME_MAX + 1];
  char answer[64];
  const char *value;
  size_t len;
  int rc;

  value = strchr(assign, '=');
  len = (size_t)(value - assign);
  if(len > ENV_NAME_MAX) {
    audit_reply(fd, "export", "refused", "-", "-", bad_name);
    return;
  }
  memcpy(name, assign, len);
  name[len] = '\0';
  value++;

  if(!env_name_valid(name)) {
    audit_reply(fd, "export", "refused", name, "-", bad_name);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "export");
  snprintf(facts.target, sizeof(facts.target), "%s", name);
  facts.session = session_id != NULL;
  hash_hex(value, strlen(value), facts.sha256);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  // A session's map is written before its line is recorded, because the
  // write itself is what can refuse: a full map or an assignment past the
  // line limit answers its existing word.
  if(session_id) {
    switch(store_session_env_set(session_id, assign)) {
    case STORE_SESSION_OK:
      break;
    case STORE_SESSION_UNKNOWN:
      reply(fd, session_expired);
      return;
    case STORE_SESSION_FULL:
      audit_reply(fd, "export", "failed", name, challenge.id, export_failed);
      return;
    default:
      audit_reply(fd, "export", "failed", name, challenge.id, value_too_long);
      return;
    }
  }

  if(audit_line("export", "done", name, challenge.id)) {
    reply(fd, audit_failed);
    return;
  }
  if(!session_id) {
    pthread_mutex_lock(&environ_lock);
    rc = setenv(name, value, 1);
    pthread_mutex_unlock(&environ_lock);
    if(rc) {
      audit_reply(fd, "export", "failed", name, challenge.id, export_failed);
      return;
    }
  }

  snprintf(answer, sizeof(answer), "exported %s\nexit 0\n", name);
  reply(fd, answer);
}


extern char **environ;


/**
 * The environment a payload started from a session receives, as the NULL
 * terminated array a spawn call takes: the session's map over the process's
 * own, copied now so a later export cannot reach a payload that is already
 * running. *envp is NULL for a connection with no session, which hands the
 * child the process environment exactly as every payload got before one, or
 * when the session holds no name, so nothing changes for it either. Returns
 * 0 when *envp is ready, or -1 when the copy cannot be made; the caller
 * frees *envp with free.
 **/
static int
session_environ(const char *session_id, char ***envp) {
  char (*assignments)[SESSION_ENV_ASSIGN_MAX + 1];
  size_t session_count = 0;
  size_t session_bytes = 0;
  size_t process_bytes = 0;
  size_t entries = 0;
  size_t names;
  size_t size;
  char *block;
  char *cursor;
  size_t i;
  size_t j;

  *envp = NULL;
  if(!session_id) {
    return 0;
  }

  assignments = calloc(SESSION_ENV_MAX, SESSION_ENV_ASSIGN_MAX + 1);
  if(!assignments) {
    return -1;
  }
  if(store_session_env_list(session_id, assignments, SESSION_ENV_MAX,
                            &session_count) < 0) {
    free(assignments);
    return -1;
  }
  if(!session_count) {
    free(assignments);
    return 0;
  }

  // The process entries are copied under the lock, so an export on another
  // connection cannot free a string this array still points at.
  pthread_mutex_lock(&environ_lock);
  for(names=0; environ[names]; names++) {
    process_bytes += strlen(environ[names]) + 1;
  }
  for(i=0; i<session_count; i++) {
    session_bytes += strlen(assignments[i]) + 1;
  }

  // One block holds the array, the process strings and the session's, so a
  // caller frees the environment with one free.
  size = (names + session_count + 1) * sizeof(char *) + process_bytes +
         session_bytes;
  if(!(block=malloc(size))) {
    pthread_mutex_unlock(&environ_lock);
    free(assignments);
    return -1;
  }

  cursor = block + (names + session_count + 1) * sizeof(char *);
  for(i=0; i<names; i++) {
    size_t len = strlen(environ[i]);

    // A session's value wins over the process's own.
    for(j=0; j<session_count; j++) {
      size_t name_len = strcspn(assignments[j], "=");

      if(!strncmp(environ[i], assignments[j], name_len) &&
         environ[i][name_len] == '=') {
        break;
      }
    }
    if(j < session_count) {
      continue;
    }
    memcpy(cursor, environ[i], len + 1);
    ((char **)block)[entries++] = cursor;
    cursor += len + 1;
  }
  pthread_mutex_unlock(&environ_lock);

  for(i=0; i<session_count; i++) {
    size_t len = strlen(assignments[i]);

    memcpy(cursor, assignments[i], len + 1);
    ((char **)block)[entries++] = cursor;
    cursor += len + 1;
  }
  ((char **)block)[entries] = NULL;

  free(assignments);
  *envp = (char **)block;

  return 0;
}


/** exec <path> [args]: runs the bytes the owner signed for, with its arguments. **/
static void
exec_command(agent_t *agent, int fd, int argc, char *argv[],
             const char *session_id) {
  platform_t *platform = agent->platform;
  approval_challenge_t challenge;
  approval_facts_t facts;
  unsigned char *bytes = NULL;
  char **envp = NULL;
  size_t size = 0;
  char answer[64];
  int status = 0;
  int len;
  int rc;

  rc = fileops_program(platform->fs_root, argv[1], &bytes, &size);
  if(rc != FILEOPS_OK) {
    file_outcome(fd, "exec", argv[1], "-", rc);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "exec");
  snprintf(facts.target, sizeof(facts.target), "%s", argv[1]);
  hash_hex(bytes, size, facts.sha256);
  facts.argc = (uint64_t)(argc - 2);
  args_hash(argc - 2, &argv[2], facts.args);

  if(!gate_pass(agent, fd, &facts, &challenge)) {
    free(bytes);
    return;
  }

  if(audit_line("exec", "done", argv[1], challenge.id)) {
    free(bytes);
    reply(fd, audit_failed);
    return;
  }
  if(session_environ(session_id, &envp)) {
    free(bytes);
    reply(fd, spawn_failed);
    return;
  }
  if(platform->spawn(platform, bytes, size, &argv[1], envp, fd, &status)) {
    free(envp);
    free(bytes);
    audit_reply(fd, "exec", "failed", argv[1], challenge.id, spawn_failed);
    return;
  }
  free(envp);
  free(bytes);

  len = snprintf(answer, sizeof(answer), "status %d\nexit 0\n", status);
  write_all(fd, answer, (size_t)len);
}


/** Whether an addon's path argument names protected state, under the root or under /data. **/
static int
addon_path_protected(const char *root, const char *path) {
  char full[PATH_MAX];

  if(path[0] != '/') {
    return 0;
  }
  if(snprintf(full, sizeof(full), "%s%s", root, path) >= (int)sizeof(full)) {
    return 1;
  }
  if(protected_path(full)) {
    return 1;
  }
  if(snprintf(full, sizeof(full), "%s/data%s", root, path) >= (int)sizeof(full)) {
    return 1;
  }
  return protected_path(full);
}


/**
 * A failed addon run answers its word, its kept output and its exit code.
 * Every failure exits 1, except a path that names protected state, which
 * keeps the 87 that word answers everywhere else. An audit line that cannot
 * be written removes the kept file first, so nothing is left that the reply
 * does not name.
 **/
static void
addon_failure(int fd, const char *root, const char *name, const char *id,
              const char *word, const char *result, int code) {
  char text[PATH_MAX + 64];
  char full[PATH_MAX];

  if(result[0]) {
    snprintf(text, sizeof(text), "%s\nresult %s\nexit %d\n", word, result, code);
  } else {
    snprintf(text, sizeof(text), "%s\nexit %d\n", word, code);
  }
  if(audit_line("addon", "failed", name, id)) {
    if(result[0] &&
       snprintf(full, sizeof(full), "%s%s", root, result) < (int)sizeof(full)) {
      (void)fileops_discard(root, full);
    }
    reply(fd, audit_failed);
    return;
  }
  reply(fd, text);
}


/** Whether an addon run's signed action fits, each argument escaped at worst. **/
static int
addon_action_fits(const approval_facts_t *facts) {
  size_t size = 400;
  uint64_t i;

  for(i=0; i<facts->argc; i++) {
    size += 13 + 3 * strlen(facts->arg[i]);
  }
  return size <= APPROVAL_ACTION_MAX;
}


static void
addon_run_command(agent_t *agent, int fd, int argc, char *argv[]) {
  platform_t *platform = agent->platform;
  approval_challenge_t challenge;
  approval_facts_t facts;
  char result[PATH_MAX];
  char text[PATH_MAX + 32];
  char hex[SHA256_HEX_LEN + 1];
  char server[65];
  char refusal[128];
  addon_run_t outcome;
  int args = argc - 3;
  int arg_error;
  int len;
  int i;

  if(args > RUN_ARGS_MAX) {
    audit_reply(fd, "addon", "refused", argv[2], "-", too_many_arguments_reply);
    return;
  }
  if(!addon_accept(argv[2], args, hex, server, refusal, sizeof(refusal))) {
    audit_reply(fd, "addon", "refused", argv[2], "-", refusal);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "addon");
  snprintf(facts.target, sizeof(facts.target), "%s", argv[2]);
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", hex);
  snprintf(facts.server, sizeof(facts.server), "%s", server);
  arg_error = run_arguments(&facts, argc - 2, &argv[2], APPROVAL_ARG_MAX);
  if(arg_error) {
    audit_reply(fd, "addon", "refused", argv[2], "-",
                arg_error == -2 ? bad_path : bad_argument);
    return;
  }
  if(!addon_action_fits(&facts)) {
    audit_reply(fd, "addon", "refused", argv[2], "-", too_large);
    return;
  }
  for(i=0; i<args; i++) {
    if(addon_path_protected(platform->fs_root, argv[3 + i])) {
      audit_reply(fd, "addon", "refused", argv[2], "-", protected_process);
      return;
    }
  }

  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  if(audit_line("addon", "done", argv[2], challenge.id)) {
    reply(fd, audit_failed);
    return;
  }

  outcome = addon_run(platform, argv[2], args, &argv[3], result, sizeof(result));
  switch(outcome) {
  case ADDON_RAN:
    len = snprintf(text, sizeof(text), "result %s\nstatus 0\nexit 0\n", result);
    write_all(fd, text, (size_t)len);
    return;
  case ADDON_TIMED_OUT:
    addon_failure(fd, platform->fs_root, argv[2], challenge.id, "timed_out", result, 1);
    return;
  case ADDON_TOO_LARGE:
    addon_failure(fd, platform->fs_root, argv[2], challenge.id, "too_large", result, 1);
    return;
  case ADDON_PROTECTED:
    addon_failure(fd, platform->fs_root, argv[2], challenge.id, "protected", result, 87);
    return;
  case ADDON_BAD_PATH:
    addon_failure(fd, platform->fs_root, argv[2], challenge.id, "bad_path", result, 1);
    return;
  case ADDON_SPAWN_FAILED:
    addon_failure(fd, platform->fs_root, argv[2], challenge.id, "spawn_failed", result, 1);
    return;
  default:
    addon_failure(fd, platform->fs_root, argv[2], challenge.id, "operation_failed", result, 1);
    return;
  }
}


static void
payload_push(agent_t *agent, int fd, int wake, const char *name,
             const char *size_text, const char *hash_text) {
  char staging_id[APPROVAL_ID_MAX];
  char declared[SHA256_HEX_LEN + 1];
  char computed[SHA256_HEX_LEN + 1];
  unsigned char digest[SHA256_DIGEST_LEN];
  approval_facts_t facts;
  platform_t *platform = agent->platform;
  uint64_t size;
  uint64_t received;
  sha256_t hash;
  int rc;
  int outfd;

  if(!store_name_valid(name)) {
    reply(fd, bad_name);
    return;
  }

  if(parse_size(size_text, &size) || parse_hash(hash_text, declared)) {
    reply(fd, unknown);
    return;
  }

  store_staging_next_id(staging_id, sizeof(staging_id));

  if((outfd=store_staging_create(staging_id, size)) < 0) {
    reply(fd, staging_full);
    return;
  }

  sha256_init(&hash);
  rc = upload_read(platform, wake, fd, outfd, NULL, size, &hash, &received);

  if(rc || received != size) {
    close(outfd);
    store_staging_discard(staging_id);
    // A full disk is a staging failure; every other bad stream is a mismatch.
    reply(fd, rc == -2 ? staging_full : mismatch);
    return;
  }

  sha256_final(&hash, digest);
  sha256_hex(digest, computed);

  if(strcmp(computed, declared)) {
    close(outfd);
    store_staging_discard(staging_id);
    reply(fd, mismatch);
    return;
  }

  if(close(outfd)) {
    store_staging_discard(staging_id);
    reply(fd, staging_full);
    return;
  }

  // The approval is bound to an immutable copy of these facts: what the
  // owner sees and approves, and nothing the client can change later.
  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "payload.commit");
  snprintf(facts.name, sizeof(facts.name), "%s", name);
  facts.size = size;
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", computed);
  snprintf(facts.staging_id, sizeof(facts.staging_id), "%s", staging_id);
  facts.run = 1;

  if(store_frozen()) {
    store_staging_discard(staging_id);
    audit_reply(fd, "payload", "push.refused", name, staging_id, frozen_reply);
    return;
  }

  {
    approval_challenge_t challenge;
    char answer[64];

    if(platform->approval_request(platform, &facts, &challenge)) {
      store_staging_discard(staging_id);
      reply(fd, approval_refused());
      return;
    }

    store_stage(staging_id, &facts, challenge.id);

    // A push the log cannot record is refused: nothing stays staged or pending.
    if(store_audit_append("push", name, staging_id, computed)) {
      store_approval_deny(challenge.id);
      store_staging_discard(staging_id);
      reply(fd, audit_failed);
      return;
    }

    snprintf(answer, sizeof(answer), "staged %s\n", staging_id);
    reply(fd, answer);
    challenge_reply(fd, &challenge);
  }
}


static int
write_vet(void *ctx) {
  const approval_facts_t *facts = ctx;

  return strcmp(facts->kind, "absent") ? FILEOPS_EXISTS : FILEOPS_OK;
}


static void
write_outcome(int fd, const char *target, const char *id, int rc) {
  char text[64];
  const char *event = rc == FILEOPS_OK ? "done" :
                      rc == FILEOPS_CHANGED ? "stale" : "refused";

  outcome_text(rc, text, sizeof(text));
  audit_reply(fd, "write", event, target, id, text);
}


/**
 * write PATH SIZE SHA256: the body follows in the push frame. The path must be
 * writable, unprotected and absent. The body is read and checked before the
 * owner is asked, and each attempt sends it again.
 **/
static void
write_command(agent_t *agent, int fd, int wake, runner_session_t *session,
              const char *path, const char *size_text, const char *hash_text) {
  const char *root = agent->platform->fs_root;
  platform_t *platform = agent->platform;
  char resolved_path[GATED_PATH_MAX];
  char declared[SHA256_HEX_LEN + 1];
  char computed[SHA256_HEX_LEN + 1];
  unsigned char digest[SHA256_DIGEST_LEN];
  approval_challenge_t challenge;
  approval_facts_t facts;
  unsigned char *body;
  uint64_t size;
  uint64_t received;
  sha256_t hash;
  int rc;

  if(!(path=session_operand(session, path, resolved_path,
                            sizeof(resolved_path), fd))) {
    return;
  }
  if(parse_size(size_text, &size) || parse_hash(hash_text, declared)) {
    reply(fd, unknown);
    return;
  }
  if(size > FILEOPS_WRITE_MAX) {
    write_outcome(fd, path, "-", FILEOPS_TOO_LARGE);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  rc = fileops_write_check(root, path, &facts);
  if(rc != FILEOPS_OK) {
    write_outcome(fd, path, "-", rc);
    return;
  }

  body = malloc(size ? size : 1);
  if(!body) {
    write_outcome(fd, path, "-", FILEOPS_FAILED);
    return;
  }

  sha256_init(&hash);
  rc = upload_read(platform, wake, fd, -1, body, size, &hash, &received);
  if(rc || received != size) {
    free(body);
    reply(fd, mismatch);
    return;
  }

  sha256_final(&hash, digest);
  sha256_hex(digest, computed);
  if(strcmp(computed, declared)) {
    free(body);
    reply(fd, mismatch);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  rc = fileops_write_check(root, path, &facts);
  if(rc != FILEOPS_OK) {
    free(body);
    write_outcome(fd, path, "-", rc);
    return;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", "write");
  snprintf(facts.target, sizeof(facts.target), "%s", path);
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", computed);
  facts.size = size;
  if(!gate_pass_with(agent, fd, &facts, &challenge, write_vet, &facts)) {
    free(body);
    return;
  }

  rc = fileops_write_act(root, path, body, size);
  free(body);
  write_outcome(fd, path, challenge.id, rc);
}


/**
 * The one-shot health check of the build an activation just made current.
 * Returns 1 when it passed. Otherwise the store replaces or marks the build,
 * the change is audited, the failure is answered and 0 is returned.
 **/
static int
activation_healthy(agent_t *agent, int fd, const char *name,
                   const char *sha256) {
  store_object_t object;
  char failed[SHA256_HEX_LEN + 1];
  char restored[SHA256_HEX_LEN + 1];
  char answer[256];
  uint64_t timeout = 0;
  int flagged;
  int run;
  int outcome;

  if(state_health_get(name, &timeout, &flagged)) {
    outcome = STORE_RUN_STALE;
  } else {
    outcome = store_run_load(name, &object);
  }
  if(outcome == STORE_RUN_SUSPENDED) {
    // The build is current but a revoked key approved it: it never runs.
    if(store_audit_append("health.suspended", name, "-", sha256)) {
      reply(fd, audit_failed);
      return 0;
    }
    reply(fd, suspended_reply);
    return 0;
  }
  if(outcome != STORE_RUN_OK) {
    if(store_audit_append("health.skipped", name, "-", sha256)) {
      reply(fd, audit_failed);
      return 0;
    }
    reply(fd, health_not_run);
    return 0;
  }
  snprintf(failed, sizeof(failed), "%s", object.sha256);

  run = runs_health(agent->platform, name, object.sha256, object.bytes,
                    object.size,
                    (timeout ? timeout : HEALTH_TIMEOUT_S) * 1000ULL);
  store_object_free(&object);

  if(run == RUNS_HEALTHY) {
    return 1;
  }
  if(run == RUNS_AUDIT) {
    reply(fd, audit_failed);
    return 0;
  }

  outcome = store_health_failed(name, failed, restored, sizeof(restored));
  switch(outcome) {
  case STORE_HEALTH_REPLACED:
    if(store_audit_append("health.replace", name, restored, failed)) {
      reply(fd, audit_failed);
      return 0;
    }
    break;
  case STORE_HEALTH_MARKED:
    if(store_audit_append("health.failed", name, "-", failed)) {
      reply(fd, audit_failed);
      return 0;
    }
    break;
  case STORE_HEALTH_UNAUDITED:
    reply(fd, audit_failed);
    return 0;
  case STORE_HEALTH_PARTIAL:
    if(store_audit_append("health.partial", name, "-", failed)) {
      reply(fd, audit_failed);
      return 0;
    }
    reply(fd, health_partial);
    return 0;
  default:
    if(store_audit_append("health.skipped", name, "-", failed)) {
      reply(fd, audit_failed);
      return 0;
    }
    reply(fd, health_unrecorded);
    return 0;
  }

  snprintf(answer, sizeof(answer), "health_failed %s %s\nexit 1\n", name,
           failed);
  reply(fd, answer);
  return 0;
}


/** The longest release document an install reads. **/
#define RELEASE_JSON_MAX 16384

struct install_work {
  char text[ALLOWLIST_TEXT_MAX];
  char json[RELEASE_JSON_MAX];
  allowlist_t list;
  release_t release;
};

struct text_sink {
  char *buf;
  size_t size;
  size_t len;
  const int *status;
};

struct asset_sink {
  int fd;
  sha256_t hash;
  uint64_t size;
  uint64_t total;
  int status;
};


static int
text_sink(void *ctx, const unsigned char *data, size_t len) {
  struct text_sink *text = ctx;

  if(*text->status != 200) {
    return 0;
  }

  if(len > text->size - 1 - text->len) {
    return -1;
  }

  memcpy(text->buf + text->len, data, len);
  text->len += len;
  return 0;
}


static int
asset_sink(void *ctx, const unsigned char *data, size_t len) {
  struct asset_sink *asset = ctx;

  if(asset->status != 200) {
    return 0;
  }

  if(len > asset->size - asset->total ||
     write_all(asset->fd, (const char *)data, len)) {
    return -1;
  }

  sha256_update(&asset->hash, data, len);
  asset->total += len;
  return 0;
}


static int
fetch_text(platform_t *platform, const char *url, char *buf, size_t size) {
  struct text_sink text;
  char location[RELEASE_URL_MAX + 1];
  int status = 0;

  text.buf = buf;
  text.size = size;
  text.len = 0;
  text.status = &status;

  if(platform->http_get(platform, url, size - 1, text_sink, &text, &status,
                        location, sizeof(location)) || status != 200) {
    return -1;
  }

  buf[text.len] = '\0';
  return 0;
}


/**
 * Fetch the asset along its redirects: one hop to the CDN, which may not
 * redirect again. Returns 0 with the bytes in asset, or -1 with the refusal
 * word in refusal.
 **/
static int
fetch_asset(platform_t *platform, const allowlist_t *list, const char *url,
            struct asset_sink *asset, const char **refusal) {
  char current[RELEASE_URL_MAX + 1];
  char location[RELEASE_URL_MAX + 1];
  char authority[ALLOWLIST_TOKEN_MAX];
  int hop;

  snprintf(current, sizeof(current), "%s", url);

  for(hop=0; hop<2; hop++) {
    asset->status = 0;
    location[0] = '\0';

    if(platform->http_get(platform, current, asset->size, asset_sink, asset,
                          &asset->status, location, sizeof(location))) {
      *refusal = "download_failed";
      return -1;
    }

    if(asset->status == 200) {
      return 0;
    }

    if(asset->status < 300 || asset->status > 399) {
      *refusal = "download_failed";
      return -1;
    }

    if(hop) {
      *refusal = "second_redirect";
      return -1;
    }

    if(http_url_host(location, authority, sizeof(authority)) ||
       !allowlist_cdn_host(list, authority)) {
      *refusal = "redirect_refused";
      return -1;
    }

    snprintf(current, sizeof(current), "%s", location);
  }

  *refusal = "second_redirect";
  return -1;
}


static int
asset_url_has_id(const char *url, uint64_t asset_id) {
  const char *slash = strrchr(url, '/');
  char expect[24];

  if(!slash) {
    return 0;
  }

  snprintf(expect, sizeof(expect), "%llu", (unsigned long long)asset_id);
  return !strcmp(slash + 1, expect);
}


static void
install_refuse(int fd, const char *name, const char *word) {
  char answer[64];

  snprintf(answer, sizeof(answer), "%s\nexit 1\n", word);
  audit_reply(fd, "payload", "install.refused", name, word, answer);
}


/**
 * Record an installed release and join it to autoload, after its health
 * check passed, and pin its hash when the allowlist does not yet.
 **/
static void
install_settle(agent_t *agent, int fd, const store_install_t *install) {
  char release[24];
  char answer[256];

  snprintf(release, sizeof(release), "%llu",
           (unsigned long long)install->release);

  if(state_release_set(install->name, install->tag, install->release,
                       install->asset)) {
    install_refuse(fd, install->name, "install_failed");
    return;
  }

  if(!activation_healthy(agent, fd, install->name, install->sha256)) {
    return;
  }

  switch(store_autoload_join(install->name, install->generation)) {
  case 0:
    break;
  case 1:
    audit_reply(fd, "payload", "install.refused", install->name, "suspended",
                suspended_reply);
    return;
  default:
    install_refuse(fd, install->name, "install_failed");
    return;
  }

  switch(store_allowlist_pin(install->name, install->sha256,
                             install->generation)) {
  case 0:
    break;
  case 1:
    audit_reply(fd, "payload", "install.refused", install->name, "suspended",
                suspended_reply);
    return;
  default:
    install_refuse(fd, install->name, "pin_failed");
    return;
  }

  if(audit_line("payload", "install.done", install->name, release)) {
    reply(fd, audit_failed);
    return;
  }

  snprintf(answer, sizeof(answer), "installed %s %s\nexit 0\n",
           install->name, install->sha256);
  reply(fd, answer);
}


static void
payload_install(agent_t *agent, int fd, const char *name, const char *repo,
                const char *asset_name, const char *tag) {
  platform_t *platform = agent->platform;
  struct install_work *work = NULL;
  struct asset_sink asset;
  approval_facts_t facts;
  store_install_t install;
  char staging_id[APPROVAL_ID_MAX];
  char authority[ALLOWLIST_TOKEN_MAX];
  char url[1024];
  char computed[SHA256_HEX_LEN + 1];
  unsigned char digest[SHA256_DIGEST_LEN];
  const char *api;
  const char *pinned;
  const char *refusal = NULL;
  int outfd;
  int rc;

  if(!store_name_valid(name)) {
    install_refuse(fd, name, "bad_name");
    return;
  }

  if(!strcmp(name, AUTOLOAD_SELF)) {
    audit_reply(fd, "payload", "install.refused", name, "protected",
                protected_process);
    return;
  }

  if(tag && !approval_value_valid(tag)) {
    install_refuse(fd, name, "bad_path");
    return;
  }

  if(strlen(repo) > APPROVAL_TARGET_MAX) {
    install_refuse(fd, name, "not_allowlisted");
    return;
  }

  work = calloc(1, sizeof(*work));
  if(!work) {
    install_refuse(fd, name, "install_failed");
    return;
  }

  if(store_allowlist_read(work->text, sizeof(work->text)) ||
     allowlist_parse(work->text, &work->list) ||
     !allowlist_has_repo(&work->list, repo)) {
    install_refuse(fd, name, "not_allowlisted");
    goto out;
  }

  api = allowlist_api_host(&work->list);
  if(!api) {
    install_refuse(fd, name, "not_allowlisted");
    goto out;
  }

  if(tag) {
    snprintf(url, sizeof(url), "http://%s/repos/%s/releases/tags/%s", api, repo,
             tag);
  } else {
    snprintf(url, sizeof(url), "http://%s/repos/%s/releases/latest", api, repo);
  }

  if(fetch_text(platform, url, work->json, sizeof(work->json))) {
    install_refuse(fd, name, "download_failed");
    goto out;
  }

  rc = release_parse(work->json, asset_name, &work->release);
  if(rc == RELEASE_NO_ASSET) {
    install_refuse(fd, name, "asset_missing");
    goto out;
  }
  if(rc || !work->release.tag[0] || !approval_value_valid(work->release.tag)) {
    install_refuse(fd, name, "download_failed");
    goto out;
  }

  if(tag && strcmp(work->release.tag, tag)) {
    install_refuse(fd, name, "tag_mismatch");
    goto out;
  }

  if(http_url_host(work->release.asset_url, authority, sizeof(authority)) ||
     !allowlist_has_host(&work->list, authority)) {
    install_refuse(fd, name, "host_refused");
    goto out;
  }

  if(!asset_url_has_id(work->release.asset_url, work->release.asset_id)) {
    install_refuse(fd, name, "asset_mismatch");
    goto out;
  }

  store_staging_next_id(staging_id, sizeof(staging_id));
  if((outfd=store_staging_create(staging_id, work->release.asset_size)) < 0) {
    install_refuse(fd, name, "staging_full");
    goto out;
  }

  asset.fd = outfd;
  asset.size = work->release.asset_size;
  asset.total = 0;
  sha256_init(&asset.hash);

  if(fetch_asset(platform, &work->list, work->release.asset_url, &asset,
                 &refusal)) {
    close(outfd);
    store_staging_discard(staging_id);
    install_refuse(fd, name, refusal);
    goto out;
  }

  if(close(outfd) || asset.total != asset.size) {
    store_staging_discard(staging_id);
    install_refuse(fd, name, "download_failed");
    goto out;
  }

  sha256_final(&asset.hash, digest);
  sha256_hex(digest, computed);

  pinned = allowlist_pin(&work->list, name);
  if(pinned && strcmp(pinned, computed)) {
    store_staging_discard(staging_id);
    install_refuse(fd, name, "hash_mismatch");
    goto out;
  }

  // A pin a revoked key approved admits nothing until the owner approves the
  // build again; that approval restores the pin.
  if(pinned && store_pin_suspended(name, pinned)) {
    pinned = NULL;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "payload.install");
  snprintf(facts.name, sizeof(facts.name), "%s", name);
  snprintf(facts.target, sizeof(facts.target), "%s", repo);
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", computed);
  snprintf(facts.staging_id, sizeof(facts.staging_id), "%s", staging_id);
  snprintf(facts.tag, sizeof(facts.tag), "%s", work->release.tag);
  facts.size = work->release.asset_size;
  facts.release = work->release.id;
  facts.asset = work->release.asset_id;

  if(pinned) {
    int pinned_outcome;

    memset(&install, 0, sizeof(install));
    store_stage(staging_id, &facts, "");
    pinned_outcome = store_commit_pinned(staging_id, &install);
    if(pinned_outcome == STORE_APPROVAL_FROZEN) {
      audit_reply(fd, "payload", "install.refused", name, "frozen",
                  frozen_reply);
      goto out;
    }
    if(pinned_outcome == STORE_APPROVAL_SUSPENDED) {
      store_staging_discard(staging_id);
      audit_reply(fd, "payload", "install.refused", name, "suspended",
                  suspended_reply);
      goto out;
    }
    if(pinned_outcome != STORE_INSTALLED) {
      install_refuse(fd, name, "install_failed");
      goto out;
    }
    install_settle(agent, fd, &install);
    goto out;
  }

  {
    approval_challenge_t challenge;
    char answer[64];

    if(store_frozen()) {
      store_staging_discard(staging_id);
      audit_reply(fd, "payload", "install.refused", name, "frozen",
                  frozen_reply);
      goto out;
    }

    if(platform->approval_request(platform, &facts, &challenge)) {
      store_staging_discard(staging_id);
      audit_reply(fd, "payload", "install.refused", name, "approval_busy",
                  approval_refused());
      goto out;
    }

    store_stage(staging_id, &facts, challenge.id);

    if(store_audit_append("payload.install.staged", name, staging_id, computed)) {
      store_approval_deny(challenge.id);
      store_staging_discard(staging_id);
      reply(fd, audit_failed);
      goto out;
    }

    snprintf(answer, sizeof(answer), "staged %s\n", staging_id);
    reply(fd, answer);
    challenge_reply(fd, &challenge);
  }

out:
  free(work);
}


static void
payload_commit(agent_t *agent, int fd, const char *staging_id) {
  char approval_id[APPROVAL_ID_MAX];
  char answer[256];
  store_install_t install;
  int outcome;

  approval_id[0] = '\0';
  memset(&install, 0, sizeof(install));

  outcome = store_commit(staging_id, &install, approval_id,
                         sizeof(approval_id));

  switch(outcome) {
  case STORE_INSTALLED:
    if(install.release) {
      install_settle(agent, fd, &install);
      return;
    }
    // The install already happened, so a commit that cannot be logged still
    // stands; the agent is told it was not recorded.
    if(store_audit_append("commit", install.name, staging_id, install.sha256)) {
      reply(fd, audit_failed);
      return;
    }
    if(!activation_healthy(agent, fd, install.name, install.sha256)) {
      return;
    }
    snprintf(answer, sizeof(answer), "installed %s %s\nexit 0\n",
             install.name, install.sha256);
    reply(fd, answer);
    return;
  case STORE_APPROVAL_REQUIRED:
    snprintf(answer, sizeof(answer), "approval_required %s\nexit 75\n",
             approval_id);
    reply(fd, answer);
    return;
  case STORE_APPROVAL_DENIED:
    audit_reply(fd, "payload", "commit.denied", install.name, staging_id,
                approval_denied);
    return;
  case STORE_APPROVAL_EXPIRED:
    audit_reply(fd, "payload", "commit.expired", install.name, staging_id,
                approval_expired);
    return;
  case STORE_APPROVAL_FROZEN:
    audit_reply(fd, "payload", "commit.refused", install.name, staging_id,
                frozen_reply);
    return;
  default:
    // An approval that is gone is not an approval: push the build again.
    audit_reply(fd, "payload", "commit.stale", install.name, staging_id,
                approval_stale);
    return;
  }
}


static void
number_text(uint64_t value, char *out, size_t size) {
  if(value) {
    snprintf(out, size, "%llu", (unsigned long long)value);
  } else {
    snprintf(out, size, "-");
  }
}


/** payload list: one line per installed payload, read-only. **/
static void
payload_list(int fd) {
  state_payload_t *entries;
  char line[1024];
  char release[24];
  char asset[24];
  size_t count = 0;
  size_t i;

  entries = calloc(STATE_PAYLOADS_MAX, sizeof(*entries));
  if(!entries || store_list(entries, STATE_PAYLOADS_MAX, &count)) {
    free(entries);
    reply(fd, list_failed);
    return;
  }

  for(i=0; i<count; i++) {
    entries[i].running = runs_running(entries[i].name);
    number_text(entries[i].release, release, sizeof(release));
    number_text(entries[i].asset, asset, sizeof(asset));
    snprintf(line, sizeof(line),
             "payload %s source=%s version=%s release=%s asset=%s sha256=%s "
             "path=%s running=%s failed=%s previous=%s\n",
             entries[i].name, entries[i].source,
             entries[i].version[0] ? entries[i].version : "-",
             release, asset, entries[i].sha256, entries[i].path,
             entries[i].running ? "yes" : "no",
             entries[i].failed ? "yes" : "no", entries[i].previous);
    reply(fd, line);
  }

  free(entries);
  reply(fd, "exit 0\n");
}


/**
 * approval status <id>: what state one approval is in. It is a question, so
 * it grants nothing and needs no approval of its own. An id Ariel never
 * issued is an error.
 **/
static void
approval_status(int fd, const char *id) {
  char answer[APPROVAL_ID_MAX + 40];
  const char *word;
  int len;

  switch(store_approval_status(id)) {
  case STORE_STATUS_PENDING:
    word = "pending";
    break;
  case STORE_STATUS_GRANTED:
    word = "granted";
    break;
  case STORE_STATUS_EXPIRED:
    word = "expired";
    break;
  case STORE_STATUS_CONSUMED:
    word = "consumed";
    break;
  case STORE_STATUS_DENIED:
    word = "denied";
    break;
  default:
    reply(fd, unknown_approval);
    return;
  }

  len = snprintf(answer, sizeof(answer), "approval_status %s %s\nexit 0\n",
                 id, word);
  write_all(fd, answer, (size_t)len);
}


/**
 * approval grant <id> <signature> [<console> <action-sha256>]: the owner's
 * signature arrives here, on whatever connection carries it, the agent's
 * included. It cannot be forged there, so relaying it is fine: the platform
 * verifies it behind the port, and nothing else makes an approval approved.
 * The optional console and action hash are the signer's claim of what it
 * signed. They only say which part is wrong; they never grant anything.
 **/
static void
approval_grant(agent_t *agent, int fd, const char *id,
               const char *signature_text, const char *console,
               const char *action_sha256) {
  unsigned char signature[APPROVAL_SIG_LEN];
  unsigned char digest[SHA256_DIGEST_LEN];
  approval_facts_t facts;
  char subject[TRANSFER_SUBJECT_MAX + 1];
  char answer[APPROVAL_ID_MAX + 32];

  if(approval_hex_decode(signature_text, signature, sizeof(signature)) ||
     (console && (strlen(console) > APPROVAL_CONSOLE_MAX ||
                  approval_hex_decode(action_sha256, digest,
                                      sizeof(digest))))) {
    reply(fd, signature_malformed);
    return;
  }

  switch(agent->platform->approval_grant(agent->platform, id, signature,
                                         console, action_sha256)) {
  case STORE_GRANT_OK:
    // The grant stands once recorded, so a grant the log cannot record is
    // reported as such and is not undone.
    if(store_approval_facts(id, &facts) ||
       store_audit_append("grant",
                          facts.target[0] ? subject_of(facts.target, facts.dest,
                                                       subject) : facts.name,
                          id, facts.sha256[0] ? facts.sha256 : APPROVAL_NO_HASH)) {
      reply(fd, audit_failed);
      return;
    }
    snprintf(answer, sizeof(answer), "approval_granted %s\nexit 0\n", id);
    reply(fd, answer);
    return;
  case STORE_GRANT_EXPIRED:
    reply(fd, approval_expired);
    return;
  case STORE_GRANT_INVALID:
    reply(fd, signature_invalid);
    return;
  case STORE_GRANT_WRONG_ACTION:
    reply(fd, signature_action_mismatch);
    return;
  case STORE_GRANT_WRONG_CONSOLE:
    reply(fd, signature_console_mismatch);
    return;
  case STORE_GRANT_REPLAYED:
    reply(fd, approval_replayed);
    return;
  case STORE_GRANT_FROZEN:
    reply(fd, frozen_reply);
    return;
  case STORE_GRANT_DENIED:
    reply(fd, approval_denied);
    return;
  case STORE_GRANT_ERROR:
    reply(fd, grant_failed);
    return;
  default:
    // An approval that is gone is not an approval: push the build again.
    reply(fd, approval_stale);
    return;
  }
}


static void
payload_run(agent_t *agent, int fd, const char *name, char *argv[],
            const char *session_id) {
  store_object_t object;
  char answer[64];
  char **envp = NULL;
  int status = 0;
  int outcome;
  int len;

  if(!store_name_valid(name)) {
    reply(fd, bad_name);
    return;
  }

  // Read the object once and hash those bytes. Only the verified bytes are
  // ever spawned: run never hashes one path and loads another.
  outcome = store_run_load(name, &object);

  if(outcome == STORE_RUN_FROZEN) {
    reply(fd, frozen_reply);
    return;
  }

  if(outcome == STORE_RUN_SUSPENDED) {
    reply(fd, suspended_reply);
    return;
  }

  if(outcome == STORE_RUN_UNKNOWN) {
    reply(fd, unknown_payload);
    return;
  }

  if(outcome != STORE_RUN_OK) {
    // The store no longer holds what it recorded: push the build again.
    reply(fd, approval_stale);
    return;
  }

  if(session_environ(session_id, &envp)) {
    store_object_free(&object);
    reply(fd, spawn_failed);
    return;
  }

  if(agent->platform->spawn(agent->platform, object.bytes, object.size,
                            argv, envp, fd, &status)) {
    free(envp);
    store_object_free(&object);
    reply(fd, spawn_failed);
    return;
  }

  free(envp);
  store_object_free(&object);

  // status is the payload's own exit status; exit is the protocol's.
  len = snprintf(answer, sizeof(answer), "status %d\nexit 0\n", status);
  write_all(fd, answer, (size_t)len);
}


/** A refused background command is audited, then answers its word. **/
static void
refuse(int fd, const char *name, const char *word, const char *answer) {
  if(store_audit_append("refuse", name, word, "-")) {
    reply(fd, audit_failed);
    return;
  }
  reply(fd, answer);
}


/** 1 when digits is a timeout in seconds from 1 to HEALTH_TIMEOUT_MAX_S. **/
static int
timeout_seconds(const char *digits, uint64_t *seconds) {
  size_t i;

  if(!digits[0] || strlen(digits) > 9) {
    return 0;
  }
  for(i=0; digits[i]; i++) {
    if(digits[i] < '0' || digits[i] > '9') {
      return 0;
    }
  }

  *seconds = strtoull(digits, NULL, 10);
  return *seconds > 0 && *seconds <= HEALTH_TIMEOUT_MAX_S;
}


/**
 * payload config <name> kind=one-shot timeout=<s>: sets the health check an
 * activation runs. Gated: the owner signs the kind and timeout first.
 **/
static void
payload_config(agent_t *agent, int fd, const char *name, const char *kind,
               const char *timeout) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  uint64_t seconds = 0;
  uint64_t stored = 0;
  char answer[128];
  int flagged;

  if(!store_name_valid(name)) {
    reply(fd, bad_name);
    return;
  }
  if(state_health_get(name, &stored, &flagged)) {
    refuse(fd, name, "unknown_payload", unknown_payload);
    return;
  }
  if(strcmp(kind, "kind=one-shot")) {
    refuse(fd, name, "unsupported_kind", unsupported_kind);
    return;
  }
  if(strncmp(timeout, "timeout=", 8) || !timeout_seconds(timeout + 8, &seconds)) {
    refuse(fd, name, "bad_argument", bad_argument);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "payload.config");
  snprintf(facts.target, sizeof(facts.target), "%s", name);
  facts.argc = seconds;
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  if(audit_line("payload.config", "done", name, challenge.id)) {
    reply(fd, audit_failed);
    return;
  }
  if(state_health_set(name, seconds)) {
    audit_reply(fd, "payload.config", "failed", name, challenge.id,
                config_failed);
    return;
  }

  snprintf(answer, sizeof(answer),
           "configured %s kind=one-shot timeout=%llu\nexit 0\n", name,
           (unsigned long long)seconds);
  reply(fd, answer);
}


static void
payload_rollback(agent_t *agent, int fd, const char *name) {
  platform_t *platform = agent->platform;
  approval_challenge_t challenge;
  approval_facts_t facts;
  store_install_t install;
  char approval_id[APPROVAL_ID_MAX];
  char answer[256];
  int outcome;

  if(!store_name_valid(name)) {
    reply(fd, bad_name);
    return;
  }

  switch(store_rollback_target(name, &facts)) {
  case STORE_ROLLBACK_UNKNOWN:
    refuse(fd, name, "unknown_payload", unknown_payload);
    return;
  case STORE_ROLLBACK_NO_PREVIOUS:
    refuse(fd, name, "no_previous_version", no_previous_version);
    return;
  case STORE_ROLLBACK_ERROR:
    refuse(fd, name, "rollback_failed", rollback_failed);
    return;
  }

  approval_id[0] = '\0';
  memset(&install, 0, sizeof(install));
  outcome = store_rollback(name, approval_id, sizeof(approval_id), &install);

  switch(outcome) {
  case STORE_APPROVAL_NEW:
    if(platform->approval_request(platform, &facts, &challenge)) {
      refuse(fd, name, "approval_busy", approval_refused());
      return;
    }
    if(store_audit_append("request", name, challenge.id, facts.sha256)) {
      store_approval_deny(challenge.id);
      reply(fd, audit_failed);
      return;
    }
    challenge_reply(fd, &challenge);
    return;
  case STORE_APPROVAL_REQUIRED:
    snprintf(answer, sizeof(answer), "approval_required %s\nexit 75\n",
             approval_id);
    reply(fd, answer);
    return;
  case STORE_APPROVAL_DENIED:
    refuse(fd, name, "approval_denied", approval_denied);
    return;
  case STORE_APPROVAL_STALE:
    refuse(fd, name, "approval_stale", approval_stale);
    return;
  case STORE_INSTALLED:
    if(store_audit_append("rollback_done", install.name, approval_id,
                          install.sha256)) {
      reply(fd, audit_failed);
      return;
    }
    if(!activation_healthy(agent, fd, install.name, install.sha256)) {
      return;
    }
    snprintf(answer, sizeof(answer), "rolled_back %s %s\nexit 0\n",
             install.name, install.sha256);
    reply(fd, answer);
    return;
  default:
    refuse(fd, name, "rollback_failed", rollback_failed);
    return;
  }
}


/** 1 when name is an installed payload, 0 when not, -1 when unreadable. **/
static int
payload_installed(const char *name) {
  state_payload_t *entries;
  size_t count = 0;
  size_t i;
  int found = 0;

  entries = calloc(STATE_PAYLOADS_MAX, sizeof(*entries));
  if(!entries || store_list(entries, STATE_PAYLOADS_MAX, &count)) {
    free(entries);
    return -1;
  }

  for(i=0; i<count; i++) {
    if(!strcmp(entries[i].name, name)) {
      found = 1;
    }
  }

  free(entries);
  return found;
}


/**
 * payload run <name>: start the committed build in the background. Its PID
 * comes back at once; its output goes to the payload's log.
 **/
static void
payload_start(agent_t *agent, int fd, const char *name, const char *session_id) {
  store_object_t object;
  char answer[64];
  char **envp = NULL;
  pid_t pid = 0;
  int outcome;
  int started;
  int len;

  if(!store_name_valid(name)) {
    reply(fd, bad_name);
    return;
  }

  outcome = store_run_load(name, &object);

  if(outcome == STORE_RUN_FROZEN) {
    refuse(fd, name, "frozen", frozen_reply);
    return;
  }

  if(outcome == STORE_RUN_SUSPENDED) {
    refuse(fd, name, "suspended", suspended_reply);
    return;
  }

  if(outcome == STORE_RUN_UNKNOWN) {
    refuse(fd, name, "unknown_payload", unknown_payload);
    return;
  }

  if(outcome != STORE_RUN_OK) {
    refuse(fd, name, "approval_stale", approval_stale);
    return;
  }

  if(session_environ(session_id, &envp)) {
    store_object_free(&object);
    reply(fd, spawn_failed);
    return;
  }

  started = runs_start(agent->platform, name, object.sha256, object.bytes,
                       object.size, envp, &pid);
  free(envp);
  store_object_free(&object);

  switch(started) {
  case RUNS_STARTED:
    len = snprintf(answer, sizeof(answer), "pid %ld\nexit 0\n", (long)pid);
    write_all(fd, answer, (size_t)len);
    return;
  case RUNS_ALREADY:
    refuse(fd, name, "already_running", already_running);
    return;
  case RUNS_FULL:
    refuse(fd, name, "too_many_runs", too_many_runs);
    return;
  case RUNS_AUDIT:
    reply(fd, audit_failed);
    return;
  default:
    refuse(fd, name, "spawn_failed", spawn_failed);
    return;
  }
}


/**
 * payload logs <name>: the payload's output. A background run still going is
 * waited for; its reaper cuts it at the timeout, so the wait is bounded.
 **/
static void
payload_logs(int fd, const char *name) {
  struct timespec pause = {0, 20 * 1000 * 1000};
  char buf[4096];
  ssize_t n;
  int installed;
  int logfd;

  if(!store_name_valid(name)) {
    reply(fd, bad_name);
    return;
  }

  installed = payload_installed(name);
  if(installed < 0) {
    reply(fd, list_failed);
    return;
  }
  if(!installed) {
    refuse(fd, name, "unknown_payload", unknown_payload);
    return;
  }

  while(runs_running(name)) {
    (void)nanosleep(&pause, NULL);
  }

  if((logfd=store_log_open(name, 0)) < 0) {
    refuse(fd, name, "no_log", no_log);
    return;
  }

  for(;;) {
    n = read(logfd, buf, sizeof(buf));
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n < 0) {
      close(logfd);
      reply(fd, log_failed);
      return;
    }
    if(n == 0 || write_all(fd, buf, (size_t)n)) {
      break;
    }
  }

  close(logfd);
  reply(fd, "exit 0\n");
}


/** One command on the platform, with its status but no exit line yet. **/
static int
run_command_status(agent_t *agent, int fd, int argc, char *argv[],
                   runner_session_t *session, int *status) {
  argv[argc] = NULL;

  return !agent->platform->run(agent->platform, argc, argv, fd, fd, session,
                               status);
}


/** The exit line of one command's status. **/
static void
exit_answer(int fd, int status) {
  char answer[32];
  int len = snprintf(answer, sizeof(answer), "exit %d\n", status);

  if(len > 0) {
    write_all(fd, answer, (size_t)len);
  }
}


/** One command, one connection: output and diagnostics both go to fd. **/
static int
run_command(agent_t *agent, int fd, int argc, char *argv[],
            runner_session_t *session) {
  int status = 0;

  if(!run_command_status(agent, fd, argc, argv, session, &status)) {
    return 0;
  }
  exit_answer(fd, status);

  return 1;
}


static int
kill_signal(const char *name) {
  size_t i;

  for(i=0; i<sizeof(kill_signals)/sizeof(kill_signals[0]); i++) {
    if(!strcmp(kill_signals[i].name, name)) {
      return i;
    }
  }
  return -1;
}


/** The identity of a process: the SHA-256 of "pid start". **/
static int
kill_identity(const char *pid, const char *start,
              char hex[SHA256_HEX_LEN + 1]) {
  char record[64];
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;
  int len;

  len = snprintf(record, sizeof(record), "%s %s", pid, start);
  if(len < 0 || (size_t)len >= sizeof(record)) {
    return -1;
  }

  sha256_init(&hash);
  sha256_update(&hash, record, (size_t)len);
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
  return 0;
}


/**
 * kill <pid> <SIGNAL>: a process is signalled only with the owner's approval
 * for its pid, signal and start identity. A critical process, and Ariel
 * itself, is refused whatever is approved. A granted approval whose start no
 * longer matches is spent and answers approval_stale; nothing is signalled.
 **/
static void
kill_command(agent_t *agent, int fd, const char *pid_text,
             const char *signal_name) {
  platform_t *platform = agent->platform;
  approval_challenge_t challenge;
  approval_facts_t facts;
  char pid_str[16];
  char start[PROCESS_START_MAX + 1];
  char identity[SHA256_HEX_LEN + 1];
  char answer[64];
  uint64_t value;
  int32_t pid;
  int index;

  if(parse_size(pid_text, &value) || value == 0 || value > INT32_MAX) {
    reply(fd, unknown);
    return;
  }
  pid = (int32_t)value;
  snprintf(pid_str, sizeof(pid_str), "%d", (int)pid);

  if((index=kill_signal(signal_name)) < 0) {
    reply(fd, bad_signal);
    return;
  }

  if(platform->process_start(platform, pid, start, sizeof(start))) {
    reply(fd, no_such_process);
    return;
  }

  if(kill_identity(pid_str, start, identity)) {
    reply(fd, unknown);
    return;
  }

  if(platform->process_critical(platform, pid)) {
    audit_reply(fd, "kill", "protected", pid_str, "-", protected_process);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "kill");
  snprintf(facts.target, sizeof(facts.target), "%s", pid_str);
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", identity);
  snprintf(facts.signal, sizeof(facts.signal), "%s", kill_signals[index].name);
  snprintf(facts.start, sizeof(facts.start), "%s", start);

  // A start that changed since the owner signed answers approval_stale there.
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  // The record comes before the signal: a kill the log cannot hold is not sent.
  if(audit_line("kill", "done", pid_str, challenge.id)) {
    reply(fd, audit_failed);
    return;
  }
  if(platform->process_signal(platform, pid, kill_signals[index].sig)) {
    audit_reply(fd, "kill", "failed", pid_str, challenge.id, kill_failed);
    return;
  }
  snprintf(answer, sizeof(answer), "killed %s %s\nexit 0\n", pid_str,
           kill_signals[index].name);
  reply(fd, answer);
}


#define HTTP2_BODY_MAX (1024UL * 1024)

struct http2_work {
  char text[ALLOWLIST_TEXT_MAX];
  allowlist_t list;
  char body[HTTP2_BODY_MAX];
};


static void
http2_refuse(int fd, const char *word, int status) {
  char answer[64];

  snprintf(answer, sizeof(answer), "%s\nexit %d\n", word, status);
  audit_reply(fd, "http2_get", "refused", "download", word, answer);
}


static void
http2_failed(int fd, const char *id, const char *word, int status) {
  char answer[64];

  audit_line("http2_get", "failed", "download", id);
  snprintf(answer, sizeof(answer), "%s\nexit %d\n", word, status);
  reply(fd, answer);
}


/**
 * http2_get [-o PATH] URL: the owner signs the URL and, with -o, the
 * destination's identity. The host must be on the download allowlist both
 * before the owner is asked and again before anything is fetched. A redirect
 * is refused, never followed.
 **/
static void
http2_get_command(agent_t *agent, int fd, int argc, char *argv[]) {
  const char *root = agent->platform->fs_root;
  const char *url = argv[argc - 1];
  const char *dest = argc == 4 ? argv[2] : NULL;
  platform_t *platform = agent->platform;
  char authority[HTTP_HOST_MAX + 1];
  char location[RELEASE_URL_MAX + 1];
  approval_challenge_t challenge;
  approval_facts_t facts;
  struct text_sink text;
  struct http2_work *work;
  int status = 0;
  int outfd;
  int rc;

  if(argc == 4 && strcmp(argv[1], "-o")) {
    reply(fd, unknown);
    return;
  }

  if(strlen(url) > APPROVAL_URL_MAX ||
     (dest && strlen(dest) > APPROVAL_TARGET_MAX)) {
    http2_refuse(fd, "bad_argument", 1);
    return;
  }

  work = calloc(1, sizeof(*work));
  if(!work) {
    http2_refuse(fd, "download_failed", 1);
    return;
  }

  if(http_url_host(url, authority, sizeof(authority)) ||
     store_allowlist_read(work->text, sizeof(work->text)) ||
     allowlist_parse(work->text, &work->list) ||
     !allowlist_has_host(&work->list, authority)) {
    http2_refuse(fd, "not_allowlisted", 1);
    goto out;
  }

  memset(&facts, 0, sizeof(facts));
  if(dest) {
    rc = fileops_check(root, "touch", dest, NULL, &facts);
    if(rc != FILEOPS_OK) {
      http2_refuse(fd, fileops_word(rc), fileops_status(rc));
      goto out;
    }
    snprintf(facts.dest, sizeof(facts.dest), "%s", dest);
  }
  snprintf(facts.command, sizeof(facts.command), "%s", "http2_get");
  snprintf(facts.target, sizeof(facts.target), "%s", "download");
  snprintf(facts.url, sizeof(facts.url), "%s", url);

  if(!gate_pass(agent, fd, &facts, &challenge)) {
    goto out;
  }

  text.buf = work->body;
  text.size = sizeof(work->body);
  text.len = 0;
  text.status = &status;
  if(platform->http_get(platform, url, sizeof(work->body) - 1, text_sink, &text,
                        &status, location, sizeof(location)) || status != 200) {
    if(status >= 300 && status < 400) {
      http2_failed(fd, challenge.id, "redirect_refused", 1);
    } else {
      http2_failed(fd, challenge.id, "download_failed", 1);
    }
    goto out;
  }

  if(dest) {
    rc = fileops_write_open(root, dest, &facts, &outfd);
    if(rc != FILEOPS_OK) {
      http2_failed(fd, challenge.id, fileops_word(rc), fileops_status(rc));
      goto out;
    }
    if(write_all(outfd, work->body, text.len)) {
      close(outfd);
      http2_failed(fd, challenge.id, "download_failed", 1);
      goto out;
    }
    close(outfd);
    if(audit_line("http2_get", "done", "download", challenge.id)) {
      reply(fd, audit_failed);
      goto out;
    }
    reply(fd, "exit 0\n");
    goto out;
  }

  if(audit_line("http2_get", "done", "download", challenge.id)) {
    reply(fd, audit_failed);
    goto out;
  }
  if(write_all(fd, work->body, text.len) ||
     (text.len && work->body[text.len - 1] != '\n' &&
      write_all(fd, "\n", 1))) {
    goto out;
  }
  reply(fd, "exit 0\n");

out:
  free(work);
}


/**
 * reboot: the owner signs the boot list the restart will run. The answer and
 * its audit line come before the restart, which replaces this process.
 **/
static void
reboot_command(agent_t *agent, int fd) {
  char text[AUTOLOAD_TEXT_MAX];
  char hex[SHA256_HEX_LEN + 1];
  unsigned char digest[SHA256_DIGEST_LEN];
  approval_facts_t facts;
  approval_challenge_t challenge;
  sha256_t hash;

  if(store_autoload_show(text, sizeof(text)) < 0) {
    reply(fd, list_failed);
    return;
  }

  sha256_init(&hash);
  sha256_update(&hash, text, strlen(text));
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "reboot");
  snprintf(facts.target, sizeof(facts.target), "%s", "console");
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", hex);

  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  if(audit_line("reboot", "done", "console", challenge.id)) {
    reply(fd, audit_failed);
    return;
  }
  reply(fd, "rebooting\nexit 0\n");
  if(agent->platform->reboot(agent->platform)) {
    audit_line("reboot", "failed", "console", challenge.id);
  }
}


/**
 * autoload safe-boot: the owner signs the boot list it leaves aside. Only Ariel
 * runs on the next boot, and the list comes back at the start after it.
 **/
static void
safe_boot_command(agent_t *agent, int fd) {
  char text[AUTOLOAD_TEXT_MAX];
  char hex[SHA256_HEX_LEN + 1];
  unsigned char digest[SHA256_DIGEST_LEN];
  approval_facts_t facts;
  approval_challenge_t challenge;
  sha256_t hash;

  if(store_autoload_skip_pending() == 1) {
    audit_reply(fd, "autoload.safe-boot", "refused", "autoload", "-",
                safe_boot_pending);
    return;
  }

  if(store_autoload_show(text, sizeof(text)) < 0) {
    reply(fd, list_failed);
    return;
  }

  sha256_init(&hash);
  sha256_update(&hash, text, strlen(text));
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "autoload.safe-boot");
  snprintf(facts.target, sizeof(facts.target), "%s", "autoload");
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", hex);

  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  switch(store_autoload_safe_boot(challenge.id, hex)) {
  case STORE_SAFE_BOOT_OK:
    reply(fd, "autoload safe-boot\nexit 0\n");
    return;
  case STORE_SAFE_BOOT_PENDING:
    audit_reply(fd, "autoload.safe-boot", "refused", "autoload", challenge.id,
                safe_boot_pending);
    return;
  case STORE_SAFE_BOOT_STALE:
    audit_reply(fd, "autoload.safe-boot", "stale", "autoload", challenge.id,
                approval_stale);
    return;
  case STORE_SAFE_BOOT_UNRECORDED:
    reply(fd, audit_failed);
    return;
  default:
    audit_reply(fd, "autoload.safe-boot", "failed", "autoload", challenge.id,
                autoload_failed);
    return;
  }
}


/**
 * audit tail [n]: the newest n lines of the audit log, at most AUDIT_TAIL_MAX.
 * Reading the log writes nothing to it.
 **/
static void
audit_tail_reply(int fd, const char *count_text) {
  size_t size = AUDIT_TAIL_MAX * AUDIT_LINE_MAX;
  uint64_t count = 0;
  char *buf;
  int len;

  if(count_text && parse_size(count_text, &count)) {
    reply(fd, unknown);
    return;
  }

  if(!(buf=malloc(size))) {
    reply(fd, audit_failed);
    return;
  }

  len = store_audit_tail((unsigned long)count, buf, size);
  if(len < 0) {
    free(buf);
    reply(fd, audit_failed);
    return;
  }

  write_all(fd, buf, (size_t)len);
  free(buf);
  reply(fd, "exit 0\n");
}


/** autoload show: the boot list, one line per entry, read-only. **/
static void
autoload_show(int fd) {
  char text[AUTOLOAD_TEXT_MAX];
  char *p;
  char *nl;

  if(store_autoload_show(text, sizeof(text)) < 0) {
    refuse(fd, "autoload", "list_failed", list_failed);
    return;
  }

  for(p=text; (nl=strchr(p, '\n')); p=nl + 1) {
    *nl = '\0';
    reply(fd, "autoload ");
    reply(fd, p);
    reply(fd, "\n");
    *nl = '\n';
  }

  reply(fd, "exit 0\n");
}


/**
 * Copy argv[first] to argv[last - 1] into facts, as the text the owner reads.
 * Returns -1 when there are more than the action can name, or one is longer
 * than an option value, and -2 when one carries a byte outside printable
 * ASCII.
 **/
static int
builtin_bind(int first, int last, char *argv[], approval_facts_t *facts) {
  int i;

  if(last - first > BUILTIN_ARGS_MAX) {
    return -1;
  }
  for(i=first; i<last; i++) {
    if(strlen(argv[i]) > APPROVAL_VALUE_MAX) {
      return -1;
    }
    if(!approval_value_valid(argv[i])) {
      return -2;
    }
    snprintf(facts->arg[i - first], sizeof(facts->arg[0]), "%s", argv[i]);
  }
  return 0;
}


/**
 * Copy a built-in's arguments from argv[first] on into facts, as the text the
 * owner reads. Returns -1 when there are more than the action can name, or
 * one is longer than an option value, and -2 when one carries a byte outside
 * printable ASCII.
 **/
static int
builtin_args(int argc, char *argv[], int first, approval_facts_t *facts) {
  return builtin_bind(first, argc, argv, facts);
}


/** A key-value pair of an sfocreate output, built before the owner is asked. **/
typedef struct sfocreate_item {
  char *key;
  unsigned char *val;
  uint32_t type;
  uint32_t val_len;
  uint32_t val_size;
} sfocreate_item_t;


/** A PARAM.SFO is small; an output past this is refused. **/
#define SFOCREATE_MAX_SIZE (1024UL * 1024)
#define SFOCREATE_HEADER   20
#define SFOCREATE_ENTRY    16
#define SFOCREATE_TYPE_STR 2
#define SFOCREATE_TYPE_INT 4
#define SFOCREATE_MAGIC    0x46535000u
#define SFOCREATE_VERSION  0x00000101u


static void
put_le16(unsigned char *p, uint16_t value) {
  p[0] = (unsigned char)(value & 0xff);
  p[1] = (unsigned char)((value >> 8) & 0xff);
}


static void
put_le32(unsigned char *p, uint32_t value) {
  p[0] = (unsigned char)(value & 0xff);
  p[1] = (unsigned char)((value >> 8) & 0xff);
  p[2] = (unsigned char)((value >> 16) & 0xff);
  p[3] = (unsigned char)((value >> 24) & 0xff);
}


static void
sfocreate_free(sfocreate_item_t *items, int count) {
  int i;

  for(i=0; i<count; i++) {
    free(items[i].key);
    free(items[i].val);
  }
}


/**
 * Parse one KEY=VALUE operand. An integer is four little-endian bytes; a
 * string is size bytes zero-filled, its NUL included when it fits. Returns 0,
 * or -1 when the pair has no key or no usable value.
 **/
static int
sfocreate_item_parse(const char *text, uint32_t type, uint32_t size,
                     sfocreate_item_t *item) {
  const char *delim = strchr(text, '=');
  const char *value;
  size_t key_len;
  size_t text_len;

  if(!delim || delim == text) {
    return -1;
  }
  key_len = (size_t)(delim - text);
  value = delim + 1;

  item->key = malloc(key_len + 1);
  if(!item->key) {
    return -1;
  }
  memcpy(item->key, text, key_len);
  item->key[key_len] = '\0';
  item->type = type;

  if(type == SFOCREATE_TYPE_INT) {
    char *end = NULL;
    long number;

    errno = 0;
    number = strtol(value, &end, 10);
    if(errno || end == value || *end ||
       number < INT32_MIN || number > INT32_MAX) {
      free(item->key);
      item->key = NULL;
      return -1;
    }
    item->val = malloc(4);
    if(!item->val) {
      free(item->key);
      item->key = NULL;
      return -1;
    }
    put_le32(item->val, (uint32_t)(int32_t)number);
    item->val_len = 4;
    item->val_size = 4;
    return 0;
  }

  text_len = strlen(value);
  item->val = calloc(size, 1);
  if(!item->val) {
    free(item->key);
    item->key = NULL;
    return -1;
  }
  memcpy(item->val, value, text_len < (size_t)size ? text_len : (size_t)size);
  item->val_size = size;
  item->val_len = text_len + 1 <= (size_t)size ? (uint32_t)(text_len + 1)
                                               : size;
  return 0;
}


/**
 * Parse the operands before the output path: "-i KEY=VALUE" and
 * "-sSIZE KEY=VALUE". Returns NULL, or the refusal word to answer.
 **/
static const char *
sfocreate_parse(int argc, char *argv[], sfocreate_item_t *items, int *count) {
  int i;
  int n = 0;

  for(i=1; i<argc-1; i++) {
    sfocreate_item_t *item = &items[n];

    if(!strcmp(argv[i], "-i")) {
      if(i + 1 >= argc - 1) {
        *count = n;
        return bad_argument;
      }
      if(sfocreate_item_parse(argv[++i], SFOCREATE_TYPE_INT, 0, item)) {
        *count = n;
        return bad_argument;
      }
    } else if(!strncmp(argv[i], "-s", 2) && isdigit((unsigned char)argv[i][2])) {
      char *end = NULL;
      unsigned long size;

      errno = 0;
      size = strtoul(argv[i] + 2, &end, 10);
      if(errno || *end || size == 0) {
        *count = n;
        return bad_option;
      }
      if(size > SFOCREATE_MAX_SIZE) {
        *count = n;
        return too_large;
      }
      if(i + 1 >= argc - 1) {
        *count = n;
        return bad_argument;
      }
      if(sfocreate_item_parse(argv[++i], SFOCREATE_TYPE_STR, (uint32_t)size,
                              item)) {
        *count = n;
        return bad_argument;
      }
    } else {
      *count = n;
      return bad_option;
    }
    n++;
  }
  *count = n;
  return NULL;
}


/**
 * Lay the pairs out as a PARAM.SFO in bytes the caller frees. The keys are
 * sorted, as the shell built-in sorts them. Returns 0, -1 when the file would
 * be too large, or -2 when it cannot be allocated.
 **/
static int
sfocreate_emit(sfocreate_item_t *items, int count, unsigned char **bytes,
               size_t *size) {
  uint64_t keys_size = 0;
  uint64_t data_size = 0;
  uint64_t keys_offset;
  uint64_t data_offset;
  uint64_t total;
  size_t key_at;
  size_t data_at;
  unsigned char *out;
  int i;
  int j;

  for(i=1; i<count; i++) {
    sfocreate_item_t item = items[i];

    for(j=i; j>0 && strcmp(items[j-1].key, item.key) > 0; j--) {
      items[j] = items[j-1];
    }
    items[j] = item;
  }

  for(i=0; i<count; i++) {
    keys_size += strlen(items[i].key) + 1;
    data_size += items[i].val_size;
  }
  if(keys_size > UINT16_MAX) {
    return -1;
  }
  total = SFOCREATE_HEADER + (uint64_t)SFOCREATE_ENTRY * (uint64_t)count +
          keys_size + data_size;
  if(total > SFOCREATE_MAX_SIZE) {
    return -1;
  }
  out = calloc((size_t)total, 1);
  if(!out) {
    return -2;
  }

  keys_offset = SFOCREATE_HEADER + (uint64_t)SFOCREATE_ENTRY * (uint64_t)count;
  data_offset = keys_offset + keys_size;
  put_le32(out, SFOCREATE_MAGIC);
  put_le32(out + 4, SFOCREATE_VERSION);
  put_le32(out + 8, (uint32_t)keys_offset);
  put_le32(out + 12, (uint32_t)data_offset);
  put_le32(out + 16, (uint32_t)count);

  key_at = (size_t)keys_offset;
  data_at = (size_t)data_offset;
  for(i=0; i<count; i++) {
    unsigned char *entry = out + SFOCREATE_HEADER + (size_t)i * SFOCREATE_ENTRY;
    size_t key_len = strlen(items[i].key) + 1;

    put_le16(entry, (uint16_t)(key_at - keys_offset));
    entry[2] = 4;
    entry[3] = (unsigned char)items[i].type;
    put_le32(entry + 4, items[i].val_len);
    put_le32(entry + 8, items[i].val_size);
    put_le32(entry + 12, (uint32_t)(data_at - data_offset));

    memcpy(out + key_at, items[i].key, key_len);
    memcpy(out + data_at, items[i].val, items[i].val_size);
    key_at += key_len;
    data_at += items[i].val_size;
  }

  *bytes = out;
  *size = (size_t)total;
  return 0;
}


static int
sfocreate_vet(void *ctx) {
  const approval_facts_t *facts = ctx;

  return strcmp(facts->kind, "absent") ? FILEOPS_EXISTS : FILEOPS_OK;
}


/**
 * sfocreate [-i KEY=VALUE] [-sSIZE KEY=VALUE]... PATH: the last operand is
 * the output path, and every operand before it is bound as text the owner
 * reads. The file is built before the owner is asked and created
 * exclusively, so an existing output is never replaced.
 **/
static void
sfocreate_command(agent_t *agent, int fd, int argc, char *argv[]) {
  const char *root = agent->platform->fs_root;
  sfocreate_item_t *items;
  approval_challenge_t challenge;
  approval_facts_t facts;
  unsigned char *bytes = NULL;
  const char *path;
  const char *word;
  size_t size = 0;
  int count = 0;
  int arg_error;
  int rc;

  if(argc < 2) {
    audit_reply(fd, argv[0], "refused", "-", "-", missing_operand);
    return;
  }
  path = argv[argc - 1];

  items = calloc((size_t)argc, sizeof(*items));
  if(!items) {
    audit_reply(fd, argv[0], "refused", path, "-", operation_failed);
    return;
  }
  word = sfocreate_parse(argc, argv, items, &count);
  if(!word) {
    switch(sfocreate_emit(items, count, &bytes, &size)) {
    case 0:
      break;
    case -1:
      word = too_large;
      break;
    default:
      word = operation_failed;
      break;
    }
  }
  sfocreate_free(items, count);
  free(items);
  if(word) {
    audit_reply(fd, argv[0], "refused", path, "-", word);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  rc = fileops_write_check(root, path, &facts);
  if(rc != FILEOPS_OK) {
    free(bytes);
    file_outcome(fd, argv[0], path, "-", rc);
    return;
  }

  arg_error = builtin_bind(1, argc - 1, argv, &facts);
  if(arg_error) {
    free(bytes);
    audit_reply(fd, argv[0], "refused", path, "-",
                arg_error == -2 ? bad_path : bad_argument);
    return;
  }
  snprintf(facts.command, sizeof(facts.command), "%s", argv[0]);
  snprintf(facts.target, sizeof(facts.target), "%s", path);
  facts.argc = (uint64_t)argc;
  if(!gate_pass_with(agent, fd, &facts, &challenge, sfocreate_vet, &facts)) {
    free(bytes);
    return;
  }

  rc = fileops_write_act(root, path, bytes, size);
  free(bytes);
  file_outcome(fd, argv[0], path, challenge.id, rc);
}


/**
 * autoload edit <add|remove> <name> [<approval-id>]: without an approval the
 * edit is asked (75); with one, it is applied if the owner granted it and the
 * list is still the one it was asked about.
 **/
static void
autoload_change(agent_t *agent, int fd, int add, const char *name,
                const char *id) {
  const char *command = add ? "autoload.add" : "autoload.remove";
  char text[AUTOLOAD_TEXT_MAX];
  char next[AUTOLOAD_TEXT_MAX];
  char hex[SHA256_HEX_LEN + 1];
  unsigned char digest[SHA256_DIGEST_LEN];
  char answer[128];
  approval_facts_t facts;
  approval_challenge_t challenge;
  sha256_t hash;
  int len;

  if(!store_name_valid(name)) {
    refuse(fd, name, "bad_name", bad_name);
    return;
  }

  if(id) {
    switch(store_autoload_apply(id, command, name, &challenge)) {
    case STORE_AUTOLOAD_APPLIED:
      snprintf(answer, sizeof(answer), "autoload %s %s\nexit 0\n",
               add ? "add" : "remove", name);
      reply(fd, answer);
      return;
    case STORE_AUTOLOAD_PENDING:
      challenge_reply(fd, &challenge);
      return;
    case STORE_AUTOLOAD_DENIED:
      refuse(fd, name, "approval_denied", approval_denied);
      return;
    case STORE_AUTOLOAD_EXPIRED:
      refuse(fd, name, "approval_expired", approval_expired);
      return;
    case STORE_AUTOLOAD_UNKNOWN:
      refuse(fd, name, "unknown_approval", unknown_approval);
      return;
    case STORE_AUTOLOAD_STALE:
      refuse(fd, name, "approval_stale", approval_stale);
      return;
    case STORE_AUTOLOAD_UNRECORDED:
      reply(fd, audit_failed);
      return;
    default:
      refuse(fd, name, "autoload_failed", autoload_failed);
      return;
    }
  }

  if(store_autoload_show(text, sizeof(text)) < 0) {
    refuse(fd, name, "list_failed", list_failed);
    return;
  }

  switch(autoload_edit(text, add, name, next, sizeof(next))) {
  case AUTOLOAD_OK:
    break;
  case AUTOLOAD_PINNED:
    refuse(fd, name, "ariel_pinned", ariel_pinned);
    return;
  case AUTOLOAD_PRESENT:
    refuse(fd, name, "already_in_autoload", already_in_autoload);
    return;
  case AUTOLOAD_ABSENT:
    refuse(fd, name, "not_in_autoload", not_in_autoload);
    return;
  case AUTOLOAD_FULL:
    refuse(fd, name, "autoload_full", autoload_full);
    return;
  default:
    refuse(fd, name, "autoload_failed", autoload_failed);
    return;
  }

  if(add) {
    len = payload_installed(name);
    if(len < 0) {
      refuse(fd, name, "list_failed", list_failed);
      return;
    }
    if(!len) {
      refuse(fd, name, "unknown_payload", unknown_payload);
      return;
    }
  }

  sha256_init(&hash);
  sha256_update(&hash, text, strlen(text));
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", command);
  snprintf(facts.name, sizeof(facts.name), "%s", name);
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", hex);

  if(agent->platform->approval_request(agent->platform, &facts, &challenge)) {
    refuse(fd, name, "approval_busy", approval_refused());
    return;
  }

  challenge_reply(fd, &challenge);
}


/**
 * One built-in, asked of the owner before it runs. Its arguments after the
 * target are bound as text, so a grant for one set does not run another. Once
 * signed, the built-in runs with its arguments and its done record comes
 * first. Returns 1 when it ran, with its exit status in status, and 0 when the
 * answer was written here.
 **/
static int
builtin_run_status(agent_t *agent, int fd, int argc, char *argv[], int first,
                   approval_facts_t *facts, int *status) {
  approval_challenge_t challenge;
  int arg_error = builtin_args(argc, argv, first, facts);

  if(arg_error) {
    audit_reply(fd, argv[0], "refused", "-", "-",
                arg_error == -2 ? bad_path : bad_argument);
    return 0;
  }
  facts->argc = (uint64_t)argc;
  if(!gate_pass(agent, fd, facts, &challenge)) {
    return 0;
  }

  if(audit_line(argv[0], "done", facts->target, challenge.id)) {
    reply(fd, audit_failed);
    return 0;
  }
  if(!run_command_status(agent, fd, argc, argv, NULL, status)) {
    reply(fd, spawn_failed);
    return 0;
  }
  return 1;
}


/** One built-in whose own exit status is its answer. **/
static void
builtin_run(agent_t *agent, int fd, int argc, char *argv[], int first,
            approval_facts_t *facts) {
  int status;

  if(builtin_run_status(agent, fd, argc, argv, first, facts, &status)) {
    exit_answer(fd, status);
  }
}


/** The gallery the console's Create button writes, and where a copy lands. **/
#define SHOTS_GALLERY "/user/av_contents/photo"
#define SHOTS_DIR     "/data/shots"
/** One copy is named shots-<ms>-<n>.jpg, so a selector never asks for more. **/
#define SHOTS_MAX     64

/**
 * One image the Create button wrote. path is the name the owner reads, below
 * the gallery. mtime is the time it was written, on the platform clock: the
 * host build's files carry wall-clock times, and the test clock starts
 * at zero, so the walk records the file's own time and `shots --minutes`
 * compares against the wall clock too.
 **/
typedef struct {
  char   path[PATH_MAX];
  time_t mtime;
} shot_t;


/** The part of path below root, starting with '/', or NULL when it is not. **/
static const char *
shots_below(const char *root, const char *path) {
  size_t n = strlen(root);

  if(strncmp(path, root, n) || path[n] != '/') {
    return NULL;
  }
  return path + n;
}


/**
 * Open the directory at the absolute console path, walking down from the
 * platform root without following a symbolic link. On a console the root is
 * empty and the walk starts at the file system root.
 **/
static int
shots_dir_open(const char *root, const char *path) {
  const char *rel = shots_below(root, path);
  char walk[PATH_MAX];
  char *part;
  char *slash;
  int fd;
  int next;

  if(!rel) {
    return -1;
  }
  if(snprintf(walk, sizeof(walk), "%s", rel + 1) >= (int)sizeof(walk)) {
    return -1;
  }

  fd = open(*root ? root : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if(fd < 0) {
    return -1;
  }

  part = walk;
  while((slash = strchr(part, '/'))) {
    *slash = '\0';
    next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    if(next < 0) {
      return -1;
    }
    fd = next;
    part = slash + 1;
  }

  next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  close(fd);
  return next;
}


/**
 * Record every regular file under the directory open at dirfd. rel is that
 * directory's path as the owner reads it. A subdirectory is walked into; a
 * symbolic link is skipped, so the walk never leaves the gallery. count
 * stops the walk at SHOTS_MAX, which is a refusal.
 **/
static int
shots_collect(int dirfd, const char *rel, shot_t *shots, int *count) {
  int copy = dup(dirfd);
  DIR *handle;
  struct dirent *entry;

  if(copy < 0) {
    return -1;
  }
  if(!(handle = fdopendir(copy))) {
    close(copy);
    return -1;
  }

  while((entry = readdir(handle))) {
    struct stat st;
    char child[PATH_MAX];
    int sub;

    if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
      continue;
    }
    if(fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      continue;
    }
    if(S_ISLNK(st.st_mode)) {
      continue;
    }
    if(snprintf(child, sizeof(child), "%s/%s", rel, entry->d_name)
       >= (int)sizeof(child)) {
      continue;
    }
    if(S_ISDIR(st.st_mode)) {
      sub = openat(dirfd, entry->d_name,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if(sub < 0 || shots_collect(sub, child, shots, count)) {
        if(sub >= 0) {
          close(sub);
        }
        closedir(handle);
        return -1;
      }
      close(sub);
      continue;
    }
    if(!S_ISREG(st.st_mode)) {
      continue;
    }
    if(*count >= SHOTS_MAX) {
      closedir(handle);
      return -1;
    }
    snprintf(shots[*count].path, sizeof(shots[*count].path), "%s", child);
    shots[*count].mtime = st.st_mtime;
    (*count)++;
  }

  closedir(handle);
  return 0;
}


/** Newest first, so --last is the first and --count takes a prefix. **/
static int
shot_newer(const void *a, const void *b) {
  time_t left = ((const shot_t *)a)->mtime;
  time_t right = ((const shot_t *)b)->mtime;

  if(left != right) {
    return left > right ? -1 : 1;
  }
  return strcmp(((const shot_t *)a)->path, ((const shot_t *)b)->path);
}


/**
 * The directory a copy lands in, made below the platform root. On a console
 * the root is empty and the path is the console's own.
 **/
static int
shots_mkdir(const char *root) {
  char path[PATH_MAX];

  if(snprintf(path, sizeof(path), "%s%s", root, SHOTS_DIR)
     >= (int)sizeof(path)) {
    return -1;
  }
  if(mkdir(path, 0755) && errno != EEXIST) {
    return -1;
  }
  return 0;
}


/**
 * Copy one image to /data/shots and answer its path, size and sha256. The
 * name carries the clock and the position, so two copies never collide. Both
 * files are opened by walking down from the platform root, so a symbolic
 * link is never followed.
 **/
static int
shot_copy(agent_t *agent, int fd, const shot_t *shot, int index,
          char *copied, size_t copied_size, char *hex_out) {
  const char *root = agent->platform->fs_root;
  char source[PATH_MAX];
  char dest[PATH_MAX];
  char line[PATH_MAX + 96];
  unsigned char digest[SHA256_DIGEST_LEN];
  char hex[SHA256_HEX_LEN + 1];
  unsigned char buf[8192];
  sha256_t ctx;
  struct stat st;
  ssize_t n;
  off_t total = 0;
  int64_t stamp = now_ms(agent->platform);
  int in;
  int out;

  if(snprintf(source, sizeof(source), "%s%s", root, shot->path)
     >= (int)sizeof(source)) {
    return -1;
  }
  if(snprintf(dest, sizeof(dest), "%s%s/shots-%lld-%d.jpg", root, SHOTS_DIR,
              (long long)stamp, index) >= (int)sizeof(dest)) {
    return -1;
  }

  if((in = open(source, O_RDONLY | O_NOFOLLOW)) < 0) {
    return -1;
  }
  if(fstat(in, &st) || !S_ISREG(st.st_mode)) {
    close(in);
    return -1;
  }
  if((out = open(dest, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644)) < 0) {
    close(in);
    return -1;
  }

  sha256_init(&ctx);
  while((n = read(in, buf, sizeof(buf))) > 0) {
    if(write(out, buf, (size_t)n) != n) {
      n = -1;
      break;
    }
    sha256_update(&ctx, buf, (size_t)n);
    total += n;
  }
  sha256_final(&ctx, digest);
  close(in);
  if(close(out) || n < 0) {
    unlink(dest);
    return -1;
  }

  sha256_hex(digest, hex);
  if(snprintf(copied, copied_size, "%s/shots-%lld-%d.jpg", SHOTS_DIR,
              (long long)stamp, index) >= (int)copied_size) {
    return -1;
  }
  snprintf(hex_out, SHA256_HEX_LEN + 1, "%s", hex);
  snprintf(line, sizeof(line), "shot %s %lld %s\n", copied,
           (long long)total, hex);
  if(write(fd, line, strlen(line)) < 0) {
    return -1;
  }
  return 0;
}


/**
 * session new | close <sid> | list: the Stage 5 lifecycle.
 *
 * A session is state, never authority: minting one needs the token every
 * connection already presents, and a gated command run inside one still
 * asks the owner. The ID never lands in the audit log or in a signed
 * action, and the table dies with the process.
 **/
static void
session_command(agent_t *agent, int fd, int argc, char *argv[]) {
  store_session_t entries[SESSIONS_MAX];
  char answer[128];
  size_t live;
  size_t count = 0;
  size_t i;

  (void)agent;

  if(argc == 2 && !strcmp(argv[1], "new")) {
    char id[SESSION_ID_MAX + 1];

    switch(store_session_new(id)) {
    case STORE_SESSION_OK:
      if(store_audit_append("session.new", "-", "-", "-")) {
        reply(fd, audit_failed);
        return;
      }
      snprintf(answer, sizeof(answer), "session %s ttl %llu\nexit 0\n", id,
               (unsigned long long)(SESSION_TTL_MS / 1000));
      reply(fd, answer);
      return;
    case STORE_SESSION_FULL:
      reply(fd, session_full);
      return;
    default:
      reply(fd, operation_failed);
      return;
    }
  }

  if(argc == 3 && !strcmp(argv[1], "close")) {
    switch(store_session_close(argv[2])) {
    case STORE_SESSION_OK:
      if(store_audit_append("session.close", "-", "-", "-")) {
        reply(fd, audit_failed);
        return;
      }
      snprintf(answer, sizeof(answer), "session_closed %s\nexit 0\n", argv[2]);
      reply(fd, answer);
      return;
    case STORE_SESSION_UNKNOWN:
      reply(fd, session_expired);
      return;
    default:
      reply(fd, operation_failed);
      return;
    }
  }

  if(argc == 2 && !strcmp(argv[1], "list")) {
    live = store_session_list(entries, SESSIONS_MAX, &count);

    // The table is capped at SESSIONS_MAX, so the answer is bounded by
    // construction and never reaches the one output cap.
    for(i=0; i<count; i++) {
      char line[SESSION_CWD_MAX + 96];
      int len = snprintf(line, sizeof(line),
                         "session %s idle %llu cwd %s env %u\n",
                         entries[i].id,
                         (unsigned long long)(entries[i].idle_ms / 1000),
                         entries[i].cwd, entries[i].env_count);

      if(len < 0 || len >= (int)sizeof(line)) {
        reply(fd, operation_failed);
        return;
      }
      write_all(fd, line, (size_t)len);
    }

    (void)live;
    reply(fd, "exit 0\n");
    return;
  }

  // session, and any other word or count of them, takes nothing: the three
  // forms above are the whole grammar.
  reply(fd, bad_option);
}


/**
 * shots --last, shots --count <n> or shots --minutes <n>: copy the Create
 * button's images out of the gallery into /data/shots.
 *
 * The gallery is the system's, so the command never captures and never writes
 * there. The selector is bound into the approval as the select fact, so a
 * grant for one selection does not run another. The copies are the agent's to
 * read and to delete with the gated rm.
 **/
static void
shots_command(agent_t *agent, int fd, int argc, char *argv[]) {
  approval_challenge_t challenge;
  approval_facts_t facts;
  shot_t *shots;
  int count = 0;
  int kept = 0;
  int i;
  long number = 0;
  int by_count = 0;
  int by_minutes = 0;
  time_t cutoff = 0;

  if(argc != 2 && argc != 3) {
    audit_reply(fd, "shots", "refused", "-", "-", bad_option);
    return;
  }
  if(argc == 2 && !strcmp(argv[1], "--last")) {
    number = 1;
    by_count = 1;
  } else if(argc == 3 && (!strcmp(argv[1], "--count") ||
                          !strcmp(argv[1], "--minutes"))) {
    char *end = NULL;
    errno = 0;
    number = strtol(argv[2], &end, 10);
    if(errno || end == argv[2] || *end || number < 1 || number > SHOTS_MAX) {
      audit_reply(fd, "shots", "refused", "-", "-", bad_argument);
      return;
    }
    by_minutes = !strcmp(argv[1], "--minutes");
    by_count = !by_minutes;
  } else {
    audit_reply(fd, "shots", "refused", "-", "-", bad_option);
    return;
  }

  if(protected_path(SHOTS_GALLERY) || protected_path(SHOTS_DIR)) {
    audit_reply(fd, "shots", "protected", "-", "-", protected_process);
    return;
  }

  // SHOTS_MAX of these paths alone is several times a connection thread's
  // stack on a build whose PATH_MAX is 4096, so they are held on the heap.
  if(!(shots=calloc(SHOTS_MAX, sizeof(*shots)))) {
    audit_reply(fd, "shots", "failed", "-", "-", shots_failed);
    return;
  }

  {
    const char *root = agent->platform->fs_root;
    char gallery[PATH_MAX];
    int dirfd;

    if(snprintf(gallery, sizeof(gallery), "%s%s", root, SHOTS_GALLERY)
       >= (int)sizeof(gallery)) {
      audit_reply(fd, "shots", "refused", "-", "-", shots_failed);
      goto out;
    }
    if((dirfd = shots_dir_open(root, gallery)) < 0) {
      /* No gallery is no image: the Create button has written nothing. */
      audit_reply(fd, "shots", "refused", "-", "-", no_shots);
      goto out;
    }
    if(shots_collect(dirfd, SHOTS_GALLERY, shots, &count)) {
      close(dirfd);
      audit_reply(fd, "shots", "refused", "-", "-", shots_failed);
      goto out;
    }
    close(dirfd);
  }
  qsort(shots, (size_t)count, sizeof(shots[0]), shot_newer);

  if(by_minutes) {
    time_t now = time(NULL);
    cutoff = now - (time_t)number * 60;
  }

  for(i = 0, kept = 0; i < count; i++) {
    if(by_minutes && shots[i].mtime < cutoff) {
      continue;
    }
    kept++;
    if(by_count && kept >= number) {
      break;
    }
  }
  if(!kept) {
    audit_reply(fd, "shots", "refused", "-", "-", no_shots);
    goto out;
  }
  kept = 0;

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "shots");
  snprintf(facts.target, sizeof(facts.target), "%s", SHOTS_DIR);
  snprintf(facts.value, sizeof(facts.value), "%s:%ld",
           by_minutes ? "minutes" : "count", number);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    goto out;
  }

  if(shots_mkdir(agent->platform->fs_root)) {
    audit_reply(fd, "shots", "failed", SHOTS_DIR, challenge.id, shots_failed);
    goto out;
  }

  for(i = 0; i < count && kept < SHOTS_MAX; i++) {
    if(by_minutes && shots[i].mtime < cutoff) {
      continue;
    }
    if(by_count && kept >= number) {
      break;
    }
    char copied[PATH_MAX];
    char hex[SHA256_HEX_LEN + 1];

    if(shot_copy(agent, fd, &shots[i], kept, copied, sizeof(copied), hex)) {
      audit_reply(fd, "shots", "failed", SHOTS_DIR, challenge.id, shots_failed);
      goto out;
    }
    if(store_audit_append("shots.done", copied, challenge.id, hex)) {
      reply(fd, audit_failed);
      goto out;
    }
    kept++;
  }

  reply(fd, shots_done);
out:
  free(shots);
}


/** An install is asynchronous and a connection ends at 60 s: wait below
    that deadline for the app directory rather than trust the call's return. **/
#define PKG_INSTALL_WAIT_MS 45000L


/** An install that did not finish names the title and the part missing. **/
static void
pkg_install_incomplete(int fd, const char *title, const char *part) {
  char answer[256];
  int len = snprintf(answer, sizeof(answer),
                     "install_incomplete %s %s\nexit 1\n", title, part);

  if(len > 0) {
    write_all(fd, answer, (size_t)len);
  }
}


/**
 * pkg_install's ending, after the owner's grant. The install call returns once
 * the request is accepted, not once the app is there, so the title's app
 * directory is waited for, then its parts are checked. A finished install
 * names the title, the bytes and the SHA-256 of the package it installed. The
 * owner signed the operand as it was written; the payload is given the local
 * path a file URI names.
 **/
static void
pkg_install_command(agent_t *agent, int fd, int argc, char *argv[],
                    approval_facts_t *facts, const char *path) {
  char title[FILEOPS_TITLE_MAX + 1];
  char hex[SHA256_HEX_LEN + 1];
  char answer[256];
  const char *part = "package";
  uint64_t bytes = 0;
  int status;
  int len;
  int named;

  argv[1] = (char *)path;
  if(!builtin_run_status(agent, fd, argc, argv, 2, facts, &status)) {
    return;
  }

  named = !fileops_title_id(path, title, sizeof(title));
  if(!named) {
    snprintf(title, sizeof(title), "-");
  }
  if(status != 0 || !named ||
     agent->platform->install_result(agent->platform, title,
                                     PKG_INSTALL_WAIT_MS) != 1) {
    pkg_install_incomplete(fd, title, "package");
    return;
  }
  if(runner_title_missing(agent->platform->fs_root, title, &part)) {
    pkg_install_incomplete(fd, title, part);
    return;
  }

  switch(runner_package_fact(path, &bytes, hex)) {
  case 0:
    break;
  case 2:
    snprintf(hex, sizeof(hex), "-");
    break;
  default:
    pkg_install_incomplete(fd, title, "package");
    return;
  }
  len = snprintf(answer, sizeof(answer), "installed %s %llu %s\nexit 0\n",
                 title, (unsigned long long)bytes, hex);
  if(len > 0) {
    write_all(fd, answer, (size_t)len);
  }
}


static void
builtin_file_command(agent_t *agent, int fd, int argc, char *argv[]) {
  char local[PATH_MAX];
  approval_facts_t facts;
  const char *path;
  int rc;

  if(argc < 2) {
    audit_reply(fd, argv[0], "refused", "-", "-", missing_operand);
    return;
  }
  path = argv[1];

  // pkg_install takes a package as a path or as the file URI its usage
  // documents. The check and the payload see the local path; the owner sees
  // the operand as written, so a grant covers that URI and no other.
  if(!strcmp(argv[0], "pkg_install")) {
    // The operand as written is the target the owner signs, so it is the
    // operand that must fit the target the encoder can carry, not only the
    // path a URI reduces to.
    if(fileops_local_path(argv[1], local, sizeof(local)) ||
       strlen(argv[1]) > APPROVAL_TARGET_MAX) {
      audit_reply(fd, argv[0], "refused", argv[1], "-", bad_path);
      return;
    }
    path = local;
  }

  memset(&facts, 0, sizeof(facts));
  rc = fileops_builtin_check(agent->platform->fs_root, path, &facts);
  if(rc != FILEOPS_OK) {
    file_outcome(fd, argv[0], argv[1], "-", rc);
    return;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", argv[0]);
  snprintf(facts.target, sizeof(facts.target), "%s", argv[1]);
  if(!strcmp(argv[0], "pkg_install")) {
    pkg_install_command(agent, fd, argc, argv, &facts, path);
    return;
  }
  builtin_run(agent, fd, argc, argv, 2, &facts);
}


/** launch and notify take one operand, a word; suspend takes none. **/
static void
builtin_word_command(agent_t *agent, int fd, int argc, char *argv[]) {
  approval_facts_t facts;
  const char *target = argv[0];

  if(strcmp(argv[0], "suspend")) {
    if(argc < 2) {
      audit_reply(fd, argv[0], "refused", "-", "-", missing_operand);
      return;
    }
    target = argv[1];
    if(!approval_target_valid(target)) {
      audit_reply(fd, argv[0], "refused", "-", "-", bad_path);
      return;
    }
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", argv[0]);
  snprintf(facts.target, sizeof(facts.target), "%s", target);
  builtin_run(agent, fd, argc, argv, target == argv[0] ? 1 : 2, &facts);
}


/** reptyr PID: a process the built-in takes over, bound to its start. **/
static void
reptyr_command(agent_t *agent, int fd, int argc, char *argv[]) {
  platform_t *platform = agent->platform;
  char start[PROCESS_START_MAX + 1];
  char identity[SHA256_HEX_LEN + 1];
  char pid_str[16];
  approval_facts_t facts;
  uint64_t value;
  int32_t pid;

  if(argc < 2) {
    audit_reply(fd, argv[0], "refused", "-", "-", missing_operand);
    return;
  }
  if(argc > 2 || parse_size(argv[1], &value) || value == 0 ||
     value > INT32_MAX) {
    audit_reply(fd, argv[0], "refused", "-", "-", bad_argument);
    return;
  }
  pid = (int32_t)value;
  snprintf(pid_str, sizeof(pid_str), "%d", (int)pid);

  if(platform->process_start(platform, pid, start, sizeof(start))) {
    reply(fd, no_such_process);
    return;
  }
  if(kill_identity(pid_str, start, identity)) {
    reply(fd, unknown);
    return;
  }
  if(platform->process_critical(platform, pid)) {
    audit_reply(fd, "reptyr", "protected", pid_str, "-", protected_process);
    return;
  }

  memset(&facts, 0, sizeof(facts));
  snprintf(facts.command, sizeof(facts.command), "%s", "reptyr");
  snprintf(facts.target, sizeof(facts.target), "%s", pid_str);
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", identity);
  snprintf(facts.start, sizeof(facts.start), "%s", start);
  builtin_run(agent, fd, argc, argv, 2, &facts);
}


static void
builtin_command(agent_t *agent, int fd, int argc, char *argv[]) {
  if(!strcmp(argv[0], "reptyr")) {
    reptyr_command(agent, fd, argc, argv);
  } else if(!strcmp(argv[0], "sfocreate")) {
    sfocreate_command(agent, fd, argc, argv);
  } else if(!strcmp(argv[0], "pkg_install") || !strcmp(argv[0], "hbldr") ||
            !strcmp(argv[0], "hbdbg")) {
    builtin_file_command(agent, fd, argc, argv);
  } else {
    builtin_word_command(agent, fd, argc, argv);
  }
}


/** An ID is exactly 32 lowercase hex characters and nothing else. **/
static int
session_id_valid(const char *id) {
  int i;

  for(i=0; i<SESSION_ID_MAX; i++) {
    char c = id[i];

    if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }

  return id[SESSION_ID_MAX] == '\0';
}


static void
handle_command(agent_t *agent, int fd, int wake, char *line) {
  char *argv[MAX_TOKENS + 1];
  char session_id[SESSION_ID_MAX + 1];
  char session_cwd[SESSION_CWD_MAX];
  char session_new_cwd[SESSION_CWD_MAX];
  runner_session_t session;
  runner_session_t *context = NULL;
  int argc = tokenize(line, argv, MAX_TOKENS);
  int i;

  if(argc < 0) {
    reply(fd, bad_quoting_reply);
    return;
  }

  if(argc == MAX_TOKENS + 1) {
    reply(fd, too_many_arguments_reply);
    return;
  }

  // The session prefix: any first token that begins with '@' must name a
  // live session, and is refused before the rest of the line is read as a
  // command. It never reaches the unlisted-command path, which would ask
  // the owner for a signature, so a typo costs one reply and no prompt.
  if(argc >= 1 && argv[0][0] == '@') {
    store_session_t info;

    if(!session_id_valid(argv[0] + 1) ||
       store_session_use(argv[0] + 1, &info) != STORE_SESSION_OK) {
      reply(fd, session_expired);
      return;
    }

    if(argc == 1) {
      reply(fd, unknown);
      return;
    }

    memcpy(session_id, info.id, sizeof(session_id));
    memcpy(session_cwd, info.cwd, sizeof(session_cwd));
    session_new_cwd[0] = '\0';
    memset(&session, 0, sizeof(session));
    session.cwd = session_cwd;
    session.new_cwd = session_new_cwd;
    session.new_cwd_size = sizeof(session_new_cwd);
    context = &session;

    // Run the rest of the line as an ordinary command.
    for(i=1; i<argc; i++) {
      argv[i - 1] = argv[i];
    }
    argv[argc - 1] = NULL;
    argc--;
  }

  // Exactly one command per connection.
  if(argc == 5 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "push")) {
    payload_push(agent, fd, wake, argv[2], argv[3], argv[4]);
    return;
  }

  if(argc == 4 && !strcmp(argv[0], "write")) {
    write_command(agent, fd, wake, context, argv[1], argv[2], argv[3]);
    return;
  }

  if((argc == 5 || argc == 6) && !strcmp(argv[0], "payload") &&
     !strcmp(argv[1], "install")) {
    payload_install(agent, fd, argv[2], argv[3], argv[4],
                    argc == 6 ? argv[5] : NULL);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "commit")) {
    payload_commit(agent, fd, argv[2]);
    return;
  }

  if(argc == 2 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "list")) {
    payload_list(fd);
    return;
  }

  if(argc == 2 && !strcmp(argv[0], "autoload") && !strcmp(argv[1], "show")) {
    autoload_show(fd);
    return;
  }

  if(argc == 2 && !strcmp(argv[0], "autoload") &&
     !strcmp(argv[1], "safe-boot")) {
    safe_boot_command(agent, fd);
    return;
  }

  // autoload edit <add|remove> <name> [<approval-id>]: the Stage 3 list edit.
  if((argc == 4 || argc == 5) && !strcmp(argv[0], "autoload") &&
     !strcmp(argv[1], "edit") &&
     (!strcmp(argv[2], "add") || !strcmp(argv[2], "remove"))) {
    autoload_change(agent, fd, !strcmp(argv[2], "add"), argv[3],
                    argc == 5 ? argv[4] : NULL);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "rollback")) {
    payload_rollback(agent, fd, argv[2]);
    return;
  }

  if(argc == 5 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "config")) {
    payload_config(agent, fd, argv[2], argv[3], argv[4]);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "kill")) {
    kill_command(agent, fd, argv[1], argv[2]);
    return;
  }

  // approval grant <id> <signature> [<console> <action-sha256>]: the
  // optional envelope is what the signer printed after the signature.
  if((argc == 4 || argc == 6) && !strcmp(argv[0], "approval") &&
     !strcmp(argv[1], "grant")) {
    approval_grant(agent, fd, argv[2], argv[3], argc == 6 ? argv[4] : NULL,
                   argc == 6 ? argv[5] : NULL);
    return;
  }

  // approval status <id>: a question, so it runs at once and grants nothing.
  if(argc == 3 && !strcmp(argv[0], "approval") &&
     !strcmp(argv[1], "status")) {
    approval_status(fd, argv[2]);
    return;
  }

  // payload run --wait <name> [args]: the name and its arguments are the
  // payload's own argv, so argv[0] is the name.
  if(argc >= 4 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "run") &&
     !strcmp(argv[2], "--wait")) {
    argv[argc] = NULL;
    payload_run(agent, fd, argv[3], &argv[3], context ? session_id : NULL);
    return;
  }

  // payload run <name> and payload logs <name>: the Stage 2 background pair.
  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "run") &&
     strcmp(argv[2], "--wait")) {
    payload_start(agent, fd, argv[2], context ? session_id : NULL);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "logs")) {
    payload_logs(fd, argv[2]);
    return;
  }

  // addon check <name> and addon list: the manifest verdicts, asked of nobody.
  if(argc == 3 && !strcmp(argv[0], "addon") && !strcmp(argv[1], "check")) {
    addon_check(fd, argv[2]);
    return;
  }

  if(argc == 2 && !strcmp(argv[0], "addon") && !strcmp(argv[1], "list")) {
    addon_list(fd);
    return;
  }

  if(argc >= 3 && !strcmp(argv[0], "addon") && !strcmp(argv[1], "run")) {
    addon_run_command(agent, fd, argc, argv);
    return;
  }

  if((argc == 2 || argc == 3) && !strcmp(argv[0], "audit") &&
     !strcmp(argv[1], "tail")) {
    audit_tail_reply(fd, argc == 3 ? argv[2] : NULL);
    return;
  }

  if(argc >= 2 && file_options(agent, fd, context, argc, argv)) {
    return;
  }

  if(argc == 2 && (!strcmp(argv[0], "mkdir") || !strcmp(argv[0], "rmdir") ||
                   !strcmp(argv[0], "touch") || !strcmp(argv[0], "rm"))) {
    file_command(agent, fd, context, argv[0], argv[1], NULL, 0);
    return;
  }

  if(argc >= 1 && (!strcmp(argv[0], "chmod") || !strcmp(argv[0], "chown") ||
                   !strcmp(argv[0], "chgrp"))) {
    attribute_command(agent, fd, context, argc, argv);
    return;
  }

  if(argc == 3 && (!strcmp(argv[0], "cp") || !strcmp(argv[0], "mv") ||
                   !strcmp(argv[0], "ln"))) {
    transfer_command(agent, fd, context, argv[0], argv[1], argv[2], 0);
    return;
  }

  if(argc >= 1 && !strcmp(argv[0], "tar")) {
    tar_command(agent, fd, context, argc, argv);
    return;
  }

  if(argc >= 1 && system_name(argv[0])) {
    system_command(agent, fd, argc, argv);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "key") && !strcmp(argv[1], "rotate")) {
    key_rotate_command(agent, fd, STORE_KEY_ROLE_PRIMARY, argv[2]);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "key") &&
     !strcmp(argv[1], "rotate-recovery")) {
    key_rotate_command(agent, fd, STORE_KEY_ROLE_RECOVERY, argv[2]);
    return;
  }

  if(argc == 2 && !strcmp(argv[0], "key") && !strcmp(argv[1], "adopt-anchor")) {
    key_adopt_command(agent, fd);
    return;
  }

  if(argc == 2 && !strcmp(argv[0], "key") && !strcmp(argv[1], "unfreeze")) {
    key_unfreeze_command(agent, fd);
    return;
  }

  if(argc == 5 && !strcmp(argv[0], "key") && !strcmp(argv[1], "revoke") &&
     !strcmp(argv[2], "--since")) {
    key_revoke_command(agent, fd, argv[3], argv[4]);
    return;
  }

  // env, export and exec are gated on the one name or program they carry.
  if(argc == 2 && !strcmp(argv[0], "env")) {
    env_command(agent, fd, argv[1], context ? session_id : NULL);
    return;
  }

  if(argc == 2 && !strcmp(argv[0], "export") && strchr(argv[1], '=')) {
    export_command(agent, fd, argv[1], context ? session_id : NULL);
    return;
  }

  if(argc >= 2 && !strcmp(argv[0], "exec")) {
    argv[argc] = NULL;
    exec_command(agent, fd, argc, argv, context ? session_id : NULL);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "unzip")) {
    if(!strcmp(argv[1], "-l")) {
      unzip_list(agent, fd, context, argv[2]);
    } else {
      unzip_command(agent, fd, context, argv[1], argv[2]);
    }
    return;
  }

  if(argc >= 1 && !strcmp(argv[0], "session")) {
    session_command(agent, fd, argc, argv);
    return;
  }

  if(argc >= 1 && !strcmp(argv[0], "shots")) {
    shots_command(agent, fd, argc, argv);
    return;
  }

  if(argc >= 1 && builtin_gated(argv[0])) {
    builtin_command(agent, fd, argc, argv);
    return;
  }

  if((argc == 2 || argc == 4) && !strcmp(argv[0], "http2_get")) {
    http2_get_command(agent, fd, argc, argv);
    return;
  }

  if(argc == 1 && !strcmp(argv[0], "reboot")) {
    reboot_command(agent, fd);
    return;
  }

  if(argc >= 1 && run_command(agent, fd, argc, argv, context)) {
    // Only cd fills new_cwd, and the caller that owns the session is the
    // one that stores it: the runner never holds session state itself.
    if(context && context->new_cwd[0]) {
      store_session_set_cwd(session_id, context->new_cwd);
    }
    return;
  }

  if(argc < 1) {
    reply(fd, unknown);
    return;
  }

  if(elf_command(agent, fd, argc, argv, context ? session_id : NULL)) {
    return;
  }

  unlisted_command(agent, fd, argc, argv);
}


void
agent_serve(agent_t *agent, int fd, int wake) {
  static const char auth_failed[] = "exit 70\n";
  char line[LINE_LIMIT + 1];
  int64_t start;
  int64_t deadline;
  int len;
  int auth;

  // The auth deadline runs from the moment the connection is served; the
  // one connection deadline covers everything after it.
  start = now_ms(agent->platform);
  deadline = start + CONNECTION_DEADLINE_MS;
  auth = authenticate(agent->platform, wake, fd, agent->token,
                      start + AUTH_DEADLINE_MS);

  if(auth < 0) {
    // A line over the limit is not an auth line: close without a reply.
    return;
  }
  if(!auth) {
    write_all(fd, auth_failed, sizeof(auth_failed) - 1);
    return;
  }

  len = read_line(agent->platform, wake, fd, line, sizeof(line), deadline);
  if(len == -2) {
    // A command line over the 4 KiB limit is refused before it can run.
    reply(fd, too_many_arguments_reply);
    return;
  }
  if(len < 0) {
    reply(fd, timed_out_reply);
    return;
  }

  handle_bounded(agent, fd, wake, line, deadline);
}


void
agent_close(platform_t *platform, int fd, int wake) {
  char buf[4096];
  int64_t deadline;
  int i;

  shutdown(fd, SHUT_WR);
  deadline = now_ms(platform) + CLOSE_DRAIN_MS;

  for(i=0; i<8; i++) {
    if(wait_readable(platform, wake, fd, deadline) <= 0) {
      break;
    }
    if(read(fd, buf, sizeof(buf)) <= 0) {
      break;
    }
  }

  close(fd);
}
