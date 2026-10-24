/* Ariel: a plain HTTP GET that reports each reply instead of following it.

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

#ifndef ARIEL_HTTP_H
#define ARIEL_HTTP_H

#include <stddef.h>

#include "platform.h"

/** The longest host name a URL may carry. **/
#define HTTP_HOST_MAX 253

/**
 * Fetch an http:// URL and report the status and, for a redirect, the
 * Location. The body is passed to sink in order; a body over max bytes fails
 * the fetch. Only plain HTTP is spoken, so an https:// URL fails here. Returns
 * 0 when a reply arrived, or -1.
 **/
int http_fetch(const char *url, size_t max, http_sink_t sink, void *ctx,
               int *status, char *location, size_t size);

/**
 * Split an http:// URL into its host and port text. Returns 0, or -1 when the
 * URL is not plain HTTP or its host is not a plain host name.
 **/
int http_url_host(const char *url, char *host, size_t size);

#endif /* ARIEL_HTTP_H */
