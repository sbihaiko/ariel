/* Ariel host build: the MCP server's protocol, one JSON-RPC message per line.

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

#ifndef ARIEL_MCP_H
#define ARIEL_MCP_H

#include <stdio.h>

#define MCP_PROTOCOL_REVISION "2026-07-28"
#define MCP_SERVER_VERSION "0.20"

/**
 * Answer each request line read from in with one line on out, until in ends.
 * A notification is read and answers nothing.
 **/
int mcp_serve(FILE *in, FILE *out);

/**
 * Write the tools/list result: the tool table, and nothing else.
 **/
void mcp_write_tools(FILE *out);

#endif /* ARIEL_MCP_H */
