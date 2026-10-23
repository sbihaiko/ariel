/* Ariel host build: the agent protocol.

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
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
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

/** One upload is at most 64 MiB. **/
#define UPLOAD_LIMIT        (64ULL * 1024ULL * 1024ULL)

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


static long
millis_left(platform_t *platform, const struct timespec *start, long budget) {
  struct timespec now;
  long elapsed;

  platform->clock(platform, &now);
  elapsed  = (now.tv_sec - start->tv_sec) * 1000L;
  elapsed += (now.tv_nsec - start->tv_nsec) / 1000000L;

  return budget - elapsed;
}


/**
 * Read one line of at most LINE_LIMIT bytes, without the line ending.
 * Returns the length, -1 when the connection ended or the deadline passed,
 * or -2 when the line is too long.
 **/
static int
read_line(platform_t *platform, int fd, char *buf, size_t size,
          long budget_ms) {
  struct timespec start;
  size_t len = 0;

  platform->clock(platform, &start);

  while(1) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    long left = millis_left(platform, &start, budget_ms);
    char c;
    ssize_t n;
    int rc;

    if(left <= 0) {
      return -1;
    }

    rc = poll(&pfd, 1, (int)left);
    if(rc < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(rc == 0) {
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


static int
authenticate(platform_t *platform, int fd, const char *token) {
  char candidate[TOKEN_LEN];
  char line[LINE_LIMIT + 1];
  int len;

  len = read_line(platform, fd, line, sizeof(line), AUTH_DEADLINE_MS);
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
upload_read(platform_t *platform, int fd, int outfd, uint64_t size,
            sha256_t *hash, uint64_t *received) {
  unsigned char buf[READ_CHUNK];
  struct timespec last;
  uint64_t total = 0;

  platform->clock(platform, &last);

  while(1) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    long left = millis_left(platform, &last, UPLOAD_STALL_MS);
    ssize_t n;

    if(left <= 0) {
      *received = total;
      return -1;
    }

    if(poll(&pfd, 1, (int)left) < 0) {
      if(errno == EINTR) {
        continue;
      }
      *received = total;
      return -1;
    }
    if(!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
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

    platform->clock(platform, &last);

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
payload_push(agent_t *agent, int fd, const char *name, const char *size_text,
             const char *hash_text) {
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

  if(size > UPLOAD_LIMIT) {
    reply(fd, staging_full);
    return;
  }

  store_staging_next_id(staging_id, sizeof(staging_id));

  if((outfd=store_staging_create(staging_id)) < 0) {
    reply(fd, staging_full);
    return;
  }

  sha256_init(&hash);
  rc = upload_read(platform, fd, outfd, size, &hash, &received);

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
    char approval_id[APPROVAL_ID_MAX];
    char answer[256];
    int len;

    if(platform->approval_request(platform, &facts,
                                  approval_id, sizeof(approval_id))) {
      store_staging_discard(staging_id);
      reply(fd, approval_busy);
      return;
    }

    store_stage(staging_id, &facts, approval_id);

    len = snprintf(answer, sizeof(answer),
                   "staged %s\napproval_required %s\nexit 75\n",
                   staging_id, approval_id);
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
handle_command(agent_t *agent, int fd, char *line) {
  char *argv[MAX_ARGS + 1];
  int argc = split_args(line, argv, MAX_ARGS);

  if(argc == MAX_ARGS + 1) {
    reply(fd, unknown);
    return;
  }

  // Exactly one command per connection.
  if(argc == 5 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "push")) {
    payload_push(agent, fd, argv[2], argv[3], argv[4]);
    return;
  }

  if(argc == 3 && !strcmp(argv[0], "payload") && !strcmp(argv[1], "commit")) {
    payload_commit(fd, argv[2]);
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
agent_serve(agent_t *agent, int fd) {
  static const char auth_failed[] = "exit 70\n";
  char line[LINE_LIMIT + 1];

  if(!authenticate(agent->platform, fd, agent->token)) {
    write_all(fd, auth_failed, sizeof(auth_failed) - 1);
    return;
  }

  if(read_line(agent->platform, fd, line, sizeof(line),
               COMMAND_DEADLINE_MS) < 0) {
    reply(fd, unknown);
    return;
  }

  handle_command(agent, fd, line);
}
