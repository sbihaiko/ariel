/* Ariel host build: the MCP server's check of a console, one line each way.

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

#ifndef ARIEL_MCP_CHECK_H
#define ARIEL_MCP_CHECK_H

#include <stdio.h>

/**
 * Connect to the console at host and port, authenticate with token and ask it
 * for sysinfo. One line naming the console goes to out when it answers exit 0;
 * one line naming the failure goes to err otherwise. Returns 0 on success.
 * The token is never written to either stream.
 **/
int mcp_check(const char *host, const char *port, const char *token,
              int timeout, FILE *out, FILE *err);

#endif /* ARIEL_MCP_CHECK_H */
