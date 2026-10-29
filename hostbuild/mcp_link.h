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

#include <stdint.h>
#include <stdio.h>

#define MCP_LINK_WHY_MAX 256

struct mcp_console {
  const char *host;
  int port;
  const char *token;
  int timeout_s;
};

/**
 * The console's answer to one command: the text before the exit line, owned by
 * the caller and freed with free, and the exit status that ended it.
 **/
struct mcp_answer {
  char *text;
  size_t len;
  int status;
};

/**
 * Send the token and one command to the agent and read its whole answer. It
 * returns 0 with the answer, whatever the exit status. Otherwise it returns -1
 * and writes one line to why that names the failure and never the token.
 **/
int mcp_exchange(const struct mcp_console *console, const char *command,
                 struct mcp_answer *answer, char *why, size_t why_len);

/**
 * As mcp_exchange, for a command whose answer may be a bytes frame: the frame's
 * body is taken by its length, so binary bytes may hold no newline before exit.
 **/
int mcp_exchange_frame(const struct mcp_console *console, const char *command,
                       struct mcp_answer *answer, char *why, size_t why_len);

/**
 * Send the token, one command and then exactly size bytes read from body, and
 * read the console's answer. The console's cut or refusal is its answer, so a
 * body that stops sending early still returns the answer. Otherwise it returns
 * -1 with one line in why, as mcp_exchange does.
 **/
int mcp_upload(const struct mcp_console *console, const char *command, FILE *body,
               uint64_t size, struct mcp_answer *answer, char *why, size_t why_len);

/**
 * Prove the console accepts the token with pwd. It returns 0 when the console
 * answers exit 0, and otherwise -1 with one line in why.
 **/
int mcp_probe(const struct mcp_console *console, char *why, size_t why_len);

#endif /* ARIEL_MCP_LINK_H */
