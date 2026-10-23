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
};

/** The implementation for the host operating system. **/
platform_t *platform_host(void);

#endif /* ARIEL_PLATFORM_H */
