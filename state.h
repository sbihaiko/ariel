/* Ariel: the state file, the single record of installed payloads.

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

#ifndef ARIEL_STATE_H
#define ARIEL_STATE_H

#include <stddef.h>
#include <stdint.h>

#include "platform.h"

/** At most this many payloads fit in the state file. **/
#define STATE_PAYLOADS_MAX 64

/**
 * One installed payload, as the state file records it. A push has no release,
 * so release and asset are 0 and version is empty; running is 1 only while a
 * background run of it is alive, which Stage 2's later slices add. previous is
 * the hash of the build the last commit replaced, or "-" when there is none.
 **/
typedef struct {
  char name[PAYLOAD_NAME_MAX + 1];
  char source[16];
  char version[64];
  uint64_t release;
  uint64_t asset;
  char sha256[65];
  char path[256];
  int running;
  char previous[65];
  uint64_t timeout;
  int failed;
} state_payload_t;

/**
 * Read the state file under dir, or build it once from Stage 1's current
 * records when no state file exists yet. Returns 0, or -1 when the record
 * cannot be read or built.
 **/
int state_open(const char *dir);

/**
 * Record that name now points at hash and that previous is the build it
 * replaced, or "-". Recording the same values again changes nothing, so a
 * recovery that repeats a commit is harmless. Returns 0, or -1.
 **/
int state_record(const char *name, const char *hash, const char *previous);

/**
 * Copy the previous hash of name into previous, or "-" when name has none.
 * Returns 0, or -1 before state_open has loaded the record.
 **/
int state_previous(const char *name, char *previous, size_t size);

/**
 * Whether the record names hash, as the current or the previous build, under
 * a name other than name. Returns 1 when it does.
 **/
int state_referenced(const char *hash, const char *name);

/**
 * Copy the installed payloads into entries, at most max of them, and set
 * count. Returns 0, or -1 before state_open has loaded the record.
 **/
int state_list(state_payload_t *entries, size_t max, size_t *count);

/**
 * Set the one-shot health timeout of name, in seconds; 0 keeps the default.
 * Returns 0, or -1 when name is not installed or the record cannot be saved.
 **/
int state_health_set(const char *name, uint64_t timeout);

/**
 * Copy the health timeout and failed flag of name. Returns 0, or -1 when name
 * is not installed.
 **/
int state_health_get(const char *name, uint64_t *timeout, int *failed);

/** Set the failed flag of name, the current build having failed its check. **/
int state_failed_set(const char *name, int failed);

#endif /* ARIEL_STATE_H */
