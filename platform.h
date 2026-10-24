/* Ariel: the narrow platform port.

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

#ifndef ARIEL_PLATFORM_H
#define ARIEL_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "approval.h"

/** The longest payload name the agent port accepts. **/
#define PAYLOAD_NAME_MAX 32

/** An approval ID is short, for example a-1. **/
#define APPROVAL_ID_MAX 32

/**
 * The immutable fact record an approval is bound to: what exactly the
 * owner approves. A copy of it, never a pointer, is what the platform
 * holds, so a caller cannot change the facts after the request.
 **/
typedef struct {
  char name[PAYLOAD_NAME_MAX + 1];
  uint64_t size;
  char sha256[65];
  char staging_id[APPROVAL_ID_MAX];
  int run;  /** The approved build will be executed. **/
} approval_facts_t;

/**
 * What the owner signs to approve one action: the approval ID, the console
 * it is for, the canonical action bytes, a nonce and the window it is good
 * for. issued_ms and expires_ms are on the platform clock.
 **/
typedef struct {
  char id[APPROVAL_ID_MAX];
  char console[APPROVAL_CONSOLE_MAX + 1];
  char action[APPROVAL_ACTION_MAX + 1];
  size_t action_len;
  unsigned char nonce[APPROVAL_NONCE_LEN];
  uint64_t issued_ms;
  uint64_t expires_ms;
} approval_challenge_t;

/**
 * The platform port: everything the agent port needs from the system it
 * runs on. Both builds share this header and the command logic above it;
 * platform_host.c and platform_ps5.c are the two implementations. The port
 * widens in Stage 2.
 **/
typedef struct platform platform_t;

struct platform {
  /** Return a socket listening on port, or -1 on error. **/
  int (*listen)(platform_t *self, uint16_t port);

  /** Return the next connection on srvfd, or -1 on error. **/
  int (*accept)(platform_t *self, int srvfd);

  /** Read the platform's monotonic clock. **/
  void (*clock)(platform_t *self, struct timespec *now);

  /**
   * Create the wake pipe of one connection and return its read end, or -1
   * when this platform has none. A wait polls the pipe together with its
   * socket, so moving the clock wakes it to recompute its deadline. On a
   * console no clock moves on its own, so the pipe is not needed.
   **/
  int (*wake_new)(platform_t *self);

  /** Close a wake pipe made by wake_new. **/
  void (*wake_close)(platform_t *self, int fd);

  /**
   * Tell the platform that the waiter of wake pipe wake is about to block
   * with nothing to read on fd (idle 1), or has woken (idle 0); fd is -1
   * for a waiter without a socket. A test clock uses this to tell a
   * scenario that every waiter has seen an advance. A console may leave it
   * NULL.
   **/
  void (*wake_idle)(platform_t *self, int wake, int fd, int idle);

  /**
   * Fill buf with len bytes from the system's cryptographic random source.
   * Returns 0, or -1 when it cannot.
   **/
  int (*random)(platform_t *self, unsigned char *buf, size_t len);

  /** The identity of this console: the text every signature names. **/
  const char *(*console_id)(platform_t *self);

  /**
   * Verify an Ed25519 signature of APPROVAL_SIG_LEN bytes over msg against
   * the public key pinned in this build. Returns 0 only for a valid one;
   * with no key pinned, nothing is valid.
   **/
  int (*verify)(platform_t *self, const unsigned char *msg, size_t len,
                const unsigned char *signature);

  /**
   * Ask the owner to approve the facts' action and show the prompt on the
   * console. On success fill challenge, what the owner signs, and return
   * 0; return -1 when no approval can be requested now.
   **/
  int (*approval_request)(platform_t *self, const approval_facts_t *facts,
                          approval_challenge_t *challenge);

  /**
   * Take the owner's signature for an approval: verify it behind the port
   * and, when it holds, mark the approval decided with its nonce recorded
   * as consumed. console and action_sha256 are the signer's envelope, both
   * NULL for a bare signature: a mismatch names the wrong console or action
   * instead of an invalid signature. Returns one of the STORE_GRANT_*
   * outcomes.
   **/
  int (*approval_grant)(platform_t *self, const char *id,
                        const unsigned char *signature,
                        const char *console, const char *action_sha256);

  /**
   * Run a payload in the foreground from its verified bytes: put the bytes
   * in a fresh file only Ariel can read, execute it with argv (argv[0] is
   * the payload's name) with its output on outfd, wait for it and return
   * its exit status in status. Returns 0 when the payload ran, -1 on a
   * platform error. The bytes are never loaded from a path.
   **/
  int (*spawn)(platform_t *self, const unsigned char *bytes, size_t size,
               char *const argv[], int outfd, int *status);
};

/**
 * The implementation for the host operating system. run_dir is a directory
 * only Ariel can read, where the bytes of a run are written before they are
 * executed and removed afterwards.
 **/
platform_t *platform_host(const char *run_dir);

#endif /* ARIEL_PLATFORM_H */
