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

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "approval.h"
#include "sha256.h"
#include "store.h"
#include "token.h"

/**
 * The agent port bounds: a line is at most 1 KiB, and auth and the command
 * each have a deadline. A line over the limit and a missed deadline are the
 * same failure here: no line was read.
 **/
#define LINE_LIMIT          1024
#define AUTH_DEADLINE_MS    5000L
#define COMMAND_DEADLINE_MS 5000L

/** One upload waits at most this long for its next bytes. **/
#define UPLOAD_STALL_MS     60000L

/** A close drains unread input for at most this long. **/
#define CLOSE_DRAIN_MS      200L

#define READ_CHUNK          65536

/** One line is at most 1 KiB, so this many words covers every command. **/
#define MAX_ARGS            512

static const char bad_name[] =
  "bad_name\n"
  "exit 1\n";
static const char unknown[] =
  "unknown_command\n"
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
  "exit 77\n";
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
static const char unknown_payload[] =
  "unknown_payload\n"
  "exit 1\n";
static const char spawn_failed[] =
  "spawn_failed\n"
  "exit 1\n";

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
    nfds_t nfds = 1;
    int64_t left;
    int rc;

    left = deadline_ms - now_ms(platform);
    if(left <= 0) {
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
  char line[LINE_LIMIT + 1];
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
 * Split line on spaces into at most max arguments. Returns the number of
 * arguments, or max + 1 when there are more.
 **/
static int
split_args(char *line, char *argv[], int max) {
  int argc = 0;
  char *p = line;

  while(*p) {
    while(*p == ' ' || *p == '\t') {
      p++;
    }
    if(!*p) {
      break;
    }
    if(argc == max) {
      return max + 1;
    }
    argv[argc++] = p;
    while(*p && *p != ' ' && *p != '\t') {
      p++;
    }
    if(*p) {
      *p++ = '\0';
    }
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
 **/
static int
upload_read(platform_t *platform, int wake, int fd, int outfd, uint64_t size,
            sha256_t *hash, uint64_t *received) {
  unsigned char buf[READ_CHUNK];
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

    n = read(fd, buf, sizeof(buf));
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
      if(hashed > 0 && write_all(outfd, (const char*)buf, hashed)) {
        *received = total;
        return -2;
      }
    }

    total += (uint64_t)n;
  }

  *received = total;
  return 0;
}


static void
reply(int fd, const char *text) {
  write_all(fd, text, strlen(text));
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
  rc = upload_read(platform, wake, fd, outfd, size, &hash, &received);

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
  snprintf(facts.name, sizeof(facts.name), "%s", name);
  facts.size = size;
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", computed);
  snprintf(facts.staging_id, sizeof(facts.staging_id), "%s", staging_id);
  facts.run = 1;

  {
    approval_challenge_t challenge;
    char action_hex[2 * APPROVAL_ACTION_MAX + 1];
    char nonce_hex[2 * APPROVAL_NONCE_LEN + 1];
    char answer[2048];
    int len;

    if(platform->approval_request(platform, &facts, &challenge)) {
      store_staging_discard(staging_id);
      reply(fd, approval_busy);
      return;
    }

    store_stage(staging_id, &facts, challenge.id);

    // The challenge is everything the owner's signer needs: the canonical
    // action as bytes in hex, so no byte of it can be reshaped on the way.
    approval_hex_encode((const unsigned char*)challenge.action,
                        challenge.action_len, action_hex);
    approval_hex_encode(challenge.nonce, sizeof(challenge.nonce), nonce_hex);

    len = snprintf(answer, sizeof(answer),
                   "staged %s\napproval_required %s\n"
                   "challenge %s %s %s %llu %llu %s\nexit 75\n",
                   staging_id, challenge.id, challenge.id, challenge.console,
                   nonce_hex, (unsigned long long)challenge.issued_ms,
                   (unsigned long long)challenge.expires_ms, action_hex);
    write_all(fd, answer, (size_t)len);
  }
}


static void
payload_commit(int fd, const char *staging_id) {
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
    reply(fd, approval_denied);
    return;
  case STORE_APPROVAL_EXPIRED:
    reply(fd, approval_expired);
    return;
  default:
    // An approval that is gone is not an approval: push the build again.
    reply(fd, approval_stale);
    return;
  }
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
payload_run(agent_t *agent, int fd, const char *name, char *argv[]) {
  store_object_t object;
  char answer[64];
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

  if(outcome == STORE_RUN_UNKNOWN) {
    reply(fd, unknown_payload);
    return;
  }

  if(outcome != STORE_RUN_OK) {
    // The store no longer holds what it recorded: push the build again.
    reply(fd, approval_stale);
    return;
  }

  if(agent->platform->spawn(agent->platform, object.bytes, object.size,
                            argv, fd, &status)) {
    store_object_free(&object);
    reply(fd, spawn_failed);
    return;
  }

  store_object_free(&object);

  // status is the payload's own exit status; exit is the protocol's.
  len = snprintf(answer, sizeof(answer), "status %d\nexit 0\n", status);
  write_all(fd, answer, (size_t)len);
}


static void
handle_command(agent_t *agent, int fd, int wake, char *line) {
  char *argv[MAX_ARGS + 1];
  int argc = split_args(line, argv, MAX_ARGS);

  if(argc == MAX_ARGS + 1) {
    reply(fd, unknown);
    return;
  }

  // Exactly one command per connection.
  if(argc == 5 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "push")) {
    payload_push(agent, fd, wake, argv[2], argv[3], argv[4]);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "commit")) {
    payload_commit(fd, argv[2]);
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

  // payload run --wait <name> [args]: the name and its arguments are the
  // payload's own argv, so argv[0] is the name.
  if(argc >= 4 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "run") &&
     !strcmp(argv[2], "--wait")) {
    argv[argc] = NULL;
    payload_run(agent, fd, argv[3], &argv[3]);
    return;
  }

  reply(fd, unknown);
}


void
agent_serve(agent_t *agent, int fd, int wake) {
  static const char auth_failed[] = "exit 70\n";
  char line[LINE_LIMIT + 1];
  int64_t start;
  int len;
  int auth;

  // The auth deadline runs from the moment the connection is served.
  start = now_ms(agent->platform);
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

  len = read_line(agent->platform, wake, fd, line, sizeof(line),
                  now_ms(agent->platform) + COMMAND_DEADLINE_MS);
  if(len == -2) {
    // A command line over the limit closes the connection too.
    return;
  }
  if(len < 0) {
    reply(fd, unknown);
    return;
  }

  handle_command(agent, fd, wake, line);
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
