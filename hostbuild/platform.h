/* Ariel host build: the narrow platform port.

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
 * The platform port. For this tracer it holds only what the agent port
 * needs to run: listening, accepting, a clock and approval requests. The
 * PS5 implementation and the rest of the port arrive with the Stage 1
 * tickets.
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
   * Ask the owner to approve the facts' action and show the prompt on the
   * console. On success write the approval ID into id and return 0; return
   * -1 when no approval can be requested now.
   **/
  int (*approval_request)(platform_t *self, const approval_facts_t *facts,
                          char *id, size_t idlen);

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
