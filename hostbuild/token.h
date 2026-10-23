/* Ariel host build: the access token.

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

#ifndef ARIEL_TOKEN_H
#define ARIEL_TOKEN_H

/** The token is 32 lowercase hex digits. **/
#define TOKEN_HEX_LEN 32
#define TOKEN_LEN (TOKEN_HEX_LEN + 1)

/**
 * Load the token from dir/token, or create it on first start. A new token
 * comes from the system's cryptographic random source, its file is created
 * exclusively with owner-only permissions through an atomic rename, and it
 * holds the 32 hex digits followed by a newline. On success token holds the
 * hex digits and a terminating NUL. Returns 0 on success, -1 on error.
 **/
int token_load_or_create(const char *dir, char token[TOKEN_LEN]);

/** Compare two tokens in constant time. Returns 1 when they are equal. **/
int token_equal(const char *a, const char *b);

#endif /* ARIEL_TOKEN_H */
