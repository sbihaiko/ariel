/* Ariel: the download allowlist, which names what an install may fetch.

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

#ifndef ARIEL_ALLOWLIST_H
#define ARIEL_ALLOWLIST_H

#include <stddef.h>

#include "platform.h"

/**
 * The allowlist file holds one directive per line:
 *   host <authority>   a host:port an install may talk to; the first is the API
 *   cdn <suffix>       the host suffix a redirect may land on
 *   repo <owner/name>  a repository an install may fetch from
 *   pin <name> <sha256>  the hash a payload must match, set by an approved install
 * Blank lines and lines starting with '#' are ignored. Anything else is refused.
 **/

#define ALLOWLIST_TEXT_MAX 16384
#define ALLOWLIST_HOSTS_MAX 8
#define ALLOWLIST_REPOS_MAX 8
#define ALLOWLIST_PINS_MAX 64
#define ALLOWLIST_TOKEN_MAX 260

typedef struct {
  char hosts[ALLOWLIST_HOSTS_MAX][ALLOWLIST_TOKEN_MAX];
  size_t nhosts;
  char cdn[ALLOWLIST_TOKEN_MAX];
  char repos[ALLOWLIST_REPOS_MAX][ALLOWLIST_TOKEN_MAX];
  size_t nrepos;
  char pin_names[ALLOWLIST_PINS_MAX][PAYLOAD_NAME_MAX + 1];
  char pin_hashes[ALLOWLIST_PINS_MAX][65];
  size_t npins;
} allowlist_t;

/** Read text into list. Returns 0, or -1 for any directive it does not accept. **/
int allowlist_parse(const char *text, allowlist_t *list);

/** The API host, or NULL when the allowlist names no host. **/
const char *allowlist_api_host(const allowlist_t *list);

/** Whether authority (host:port) is a host the allowlist names. Returns 1 when it is. **/
int allowlist_has_host(const allowlist_t *list, const char *authority);

/** Whether repo is a repository the allowlist names. Returns 1 when it is. **/
int allowlist_has_repo(const allowlist_t *list, const char *repo);

/**
 * Whether authority's host is the CDN suffix or one of its subdomains. Returns
 * 1 when it is, and 0 when the allowlist names no CDN suffix.
 **/
int allowlist_cdn_host(const allowlist_t *list, const char *authority);

/** The hash pinned for name, or NULL when none is pinned. **/
const char *allowlist_pin(const allowlist_t *list, const char *name);

/**
 * Write text with a pin line for name and sha256 appended. Returns the length
 * written to out, or -1 when it does not fit.
 **/
int allowlist_with_pin(const char *text, const char *name, const char *sha256,
                       char *out, size_t size);

#endif /* ARIEL_ALLOWLIST_H */
