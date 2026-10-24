/* Ariel: the release document a release API answers with.

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

#ifndef ARIEL_RELEASE_H
#define ARIEL_RELEASE_H

#include <stdint.h>

#define RELEASE_TAG_MAX 64
#define RELEASE_URL_MAX 512

/** The release and the one asset an install asked for. **/
typedef struct {
  uint64_t id;
  char tag[RELEASE_TAG_MAX + 1];
  uint64_t asset_id;
  uint64_t asset_size;
  char asset_url[RELEASE_URL_MAX + 1];
} release_t;

/** Read the release document in json, which is NUL-terminated. **/
#define RELEASE_OK       0
#define RELEASE_NO_ASSET 1

/**
 * Read the release in json and the asset named asset. Returns RELEASE_OK,
 * RELEASE_NO_ASSET when the release has no asset of that name, or -1 when the
 * document is not a release this scanner reads.
 **/
int release_parse(const char *json, const char *asset, release_t *out);

#endif /* ARIEL_RELEASE_H */
