/* Ariel host build: the MCP server's link to the console's agent port.

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

#ifndef ARIEL_MCP_LINK_H
#define ARIEL_MCP_LINK_H

#include <stddef.h>

#define MCP_LINK_WHY_MAX 256

/**
 * Connect to the agent at host:port, send the token and pwd, and read the
 * reply. It returns 0 when the console accepted the token. Otherwise it returns
 * -1 and writes one line to why that names the failure and never the token.
 **/
int mcp_probe(const char *host, int port, const char *token, int timeout_s,
              char *why, size_t why_len);

#endif /* ARIEL_MCP_LINK_H */
