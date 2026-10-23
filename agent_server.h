/* Ariel: the agent port listener.

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

#ifndef ARIEL_AGENT_SERVER_H
#define ARIEL_AGENT_SERVER_H

#include <stdint.h>

#include "agent.h"
#include "platform.h"

/**
 * Serve agent connections on srvfd: accept each one and hand it to a thread
 * of this same process, so approvals, staging and the pending count share
 * the store's mutexes and die with the process. A fifth connection at once
 * is answered busy and closed.
 *
 * Both builds run this loop: the host build as its main loop, the PS5 build
 * in a thread beside the telnet shell. It returns only when the listener
 * fails; the caller owns srvfd and agent, and agent must outlive every
 * connection thread still in flight when this returns.
 **/
void agent_server_serve(agent_t *agent, int srvfd);

#endif /* ARIEL_AGENT_SERVER_H */
