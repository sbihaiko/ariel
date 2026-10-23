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

#ifndef ARIEL_AGENT_H
#define ARIEL_AGENT_H

#include "platform.h"

/**
 * What one agent connection needs: the platform port and the access token.
 * The server fills it in once and shares it with every connection. Ariel's
 * state lives in the store, not here.
 **/
typedef struct {
  platform_t *platform;
  const char *token;
} agent_t;

/**
 * Serve one agent connection: read the auth line, read exactly one command,
 * write the reply and return. wake is the connection's wake pipe read end,
 * or -1 when the platform has none; every wait polls it. The caller owns fd
 * and wake and closes them.
 **/
void agent_serve(agent_t *agent, int fd, int wake);

/**
 * Close a connection after its reply. Read what the client already sent
 * first: a close with unread input resets the connection, and the reset can
 * discard a reply the client has not read yet. A refused push leaves its
 * body unread. The drain has a deadline on the platform clock and polls
 * wake like every other wait, and it reads a bounded amount, so a client
 * that keeps sending cannot hold the connection.
 **/
void agent_close(platform_t *platform, int fd, int wake);

#endif /* ARIEL_AGENT_H */
