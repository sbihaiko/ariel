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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "approval.h"
#include "fileops.h"
#include "runs.h"
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
static const char unknown_payload[] =
  "unknown_payload\n"
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
 * buf holds READ_CHUNK bytes.
 **/
static int
upload_read_into(platform_t *platform, int wake, int fd, int outfd,
                 uint64_t size, sha256_t *hash, uint64_t *received,
                 unsigned char *buf) {
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


/**
 * upload_read_into with its chunk on the heap: a connection thread's stack
 * is CONNECTION_STACK, and a READ_CHUNK frame alone would overflow it.
 **/
static int
upload_read(platform_t *platform, int wake, int fd, int outfd, uint64_t size,
            sha256_t *hash, uint64_t *received) {
  unsigned char *buf;
  int rc;

  if(!(buf=malloc(READ_CHUNK))) {
    *received = 0;
    return -1;
  }
  rc = upload_read_into(platform, wake, fd, outfd, size, hash, received, buf);
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
  char answer[2048];
  int len;

  approval_hex_encode((const unsigned char*)challenge->action,
                      challenge->action_len, action_hex);
  approval_hex_encode(challenge->nonce, sizeof(challenge->nonce), nonce_hex);

  len = snprintf(answer, sizeof(answer),
                 "approval_required %s\n"
                 "challenge %s %s %s %llu %llu %s\nexit 75\n",
                 challenge->id, challenge->id, challenge->console, nonce_hex,
                 (unsigned long long)challenge->issued_ms,
                 (unsigned long long)challenge->expires_ms, action_hex);
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
 * Append one line for command's event: "<command>.<event> <target> <id> none".
 * An invalid target is logged as "-", so no argument can reshape the line.
 **/
static int
audit_line(const char *command, const char *event, const char *target,
           const char *id) {
  char kind[64];
  const char *name = approval_target_valid(target) ? target : "-";

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
gate_pass(agent_t *agent, int fd, const approval_facts_t *facts,
          approval_challenge_t *challenge) {
  switch(store_gate_check(facts, challenge)) {
  case STORE_GATE_GO:
    return 1;
  case STORE_GATE_PENDING:
    challenge_reply(fd, challenge);
    return 0;
  case STORE_GATE_STALE:
    audit_reply(fd, facts->command, "stale", facts->target, challenge->id,
                approval_stale);
    return 0;
  case STORE_GATE_DENIED:
    audit_reply(fd, facts->command, "denied", facts->target, challenge->id,
                approval_denied);
    return 0;
  case STORE_GATE_REFUSED:
    audit_reply(fd, facts->command, "refused", facts->target, "-", unknown);
    return 0;
  default:
    break;
  }

  if(agent->platform->approval_request(agent->platform, facts, challenge)) {
    reply(fd, approval_busy);
    return 0;
  }

  if(audit_line(facts->command, "request", facts->target, challenge->id)) {
    store_approval_deny(challenge->id);
    reply(fd, audit_failed);
    return 0;
  }

  challenge_reply(fd, challenge);
  return 0;
}


/** One file command, mkdir, rmdir, touch or rm, on one absolute path. **/
static void
file_command(agent_t *agent, int fd, const char *command, const char *path) {
  const char *root = agent->platform->fs_root;
  approval_challenge_t challenge;
  approval_facts_t facts;
  int rc;

  memset(&facts, 0, sizeof(facts));
  rc = fileops_check(root, command, path, &facts);
  if(rc != FILEOPS_OK) {
    file_outcome(fd, command, path, "-", rc);
    return;
  }

  snprintf(facts.command, sizeof(facts.command), "%s", command);
  snprintf(facts.target, sizeof(facts.target), "%s", path);
  if(!gate_pass(agent, fd, &facts, &challenge)) {
    return;
  }

  rc = fileops_act(root, command, path, &facts);
  file_outcome(fd, command, path, challenge.id, rc);
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
  snprintf(facts.command, sizeof(facts.command), "%s", "payload.commit");
  snprintf(facts.name, sizeof(facts.name), "%s", name);
  facts.size = size;
  snprintf(facts.sha256, sizeof(facts.sha256), "%s", computed);
  snprintf(facts.staging_id, sizeof(facts.staging_id), "%s", staging_id);
  facts.run = 1;

  {
    approval_challenge_t challenge;
    char answer[64];

    if(platform->approval_request(platform, &facts, &challenge)) {
      store_staging_discard(staging_id);
      reply(fd, approval_busy);
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
    // The install already happened, so a commit that cannot be logged still
    // stands; the agent is told it was not recorded.
    if(store_audit_append("commit", install.name, staging_id, install.sha256)) {
      reply(fd, audit_failed);
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
             "path=%s running=%s previous=%s\n",
             entries[i].name, entries[i].source,
             entries[i].version[0] ? entries[i].version : "-",
             release, asset, entries[i].sha256, entries[i].path,
             entries[i].running ? "yes" : "no", entries[i].previous);
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
       store_audit_append("grant", facts.target[0] ? facts.target : facts.name,
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


/** A refused background command is audited, then answers its word. **/
static void
refuse(int fd, const char *name, const char *word, const char *answer) {
  if(store_audit_append("refuse", name, word, "-")) {
    reply(fd, audit_failed);
    return;
  }
  reply(fd, answer);
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
payload_start(agent_t *agent, int fd, const char *name) {
  store_object_t object;
  char answer[64];
  pid_t pid = 0;
  int outcome;
  int started;
  int len;

  if(!store_name_valid(name)) {
    reply(fd, bad_name);
    return;
  }

  outcome = store_run_load(name, &object);

  if(outcome == STORE_RUN_UNKNOWN) {
    refuse(fd, name, "unknown_payload", unknown_payload);
    return;
  }

  if(outcome != STORE_RUN_OK) {
    refuse(fd, name, "approval_stale", approval_stale);
    return;
  }

  started = runs_start(agent->platform, name, object.sha256, object.bytes,
                       object.size, &pid);
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


/** One command, one connection: output and diagnostics both go to fd. **/
static int
run_command(agent_t *agent, int fd, int argc, char *argv[]) {
  char answer[32];
  int status = 0;
  int len;

  argv[argc] = NULL;

  if(agent->platform->run(agent->platform, argc, argv, fd, fd, &status)) {
    return 0;
  }

  len = snprintf(answer, sizeof(answer), "exit %d\n", status);
  write_all(fd, answer, (size_t)len);

  return 1;
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

  if(argc == 2 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "list")) {
    payload_list(fd);
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
    payload_run(agent, fd, argv[3], &argv[3]);
    return;
  }

  // payload run <name> and payload logs <name>: the Stage 2 background pair.
  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "run") &&
     strcmp(argv[2], "--wait")) {
    payload_start(agent, fd, argv[2]);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "logs")) {
    payload_logs(fd, argv[2]);
    return;
  }

  if((argc == 2 || argc == 3) && !strcmp(argv[0], "audit") &&
     !strcmp(argv[1], "tail")) {
    audit_tail_reply(fd, argc == 3 ? argv[2] : NULL);
    return;
  }

  if(argc == 2 && (!strcmp(argv[0], "mkdir") || !strcmp(argv[0], "rmdir") ||
                   !strcmp(argv[0], "touch") || !strcmp(argv[0], "rm"))) {
    file_command(agent, fd, argv[0], argv[1]);
    return;
  }

  if(argc >= 1 && run_command(agent, fd, argc, argv)) {
    return;
  }

  if(argc < 1) {
    reply(fd, unknown);
    return;
  }

  unlisted_command(agent, fd, argc, argv);
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
