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

#ifndef ARIEL_AGENT_H
#define ARIEL_AGENT_H

#include "platform.h"

/**
 * Serve one agent connection: read the auth line, read exactly one command,
 * write the reply and return. The caller owns fd and closes it.
 **/
void agent_serve(platform_t *platform, int fd, const char *token);

#endif /* ARIEL_AGENT_H */
