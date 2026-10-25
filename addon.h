/* Ariel: the addon directory and the refusal of an addon by name.

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

#ifndef ARIEL_ADDON_H
#define ARIEL_ADDON_H

#include <stddef.h>

#include "platform.h"

typedef enum {
  ADDON_RAN,
  ADDON_TIMED_OUT,
  ADDON_TOO_LARGE,
  ADDON_SPAWN_FAILED,
  ADDON_PROTECTED,
  ADDON_BAD_PATH,
  ADDON_FAILED
} addon_run_t;

/** Set the state directory whose addons directory the checks read. **/
void addon_init(const char *state_dir);

/** Answer `addon check <name>`: the verdict on one addon, asked of nobody. **/
void addon_check(int fd, const char *name);

/** Answer `addon list`: one verdict line per addon, then exit 0. **/
void addon_list(int fd);

/**
 * Judge the addon named name for a run with argc arguments. Returns 1 and its
 * manifest digest in hex and its server in server when it may be asked for.
 * Otherwise returns 0 and puts the refusal and its exit line in refusal, for
 * the caller to audit.
 **/
int addon_accept(const char *name, int argc, char hex[65], char server[65],
                 char *refusal, size_t size);

/**
 * Run the addon named name with args in a process of its own, bounded. On
 * ADDON_RAN its output is in the file named by result; any other outcome
 * leaves no file. An addon that exits 3 refused a path, and one that exits 87
 * named protected state.
 **/
addon_run_t addon_run(platform_t *platform, const char *name, int argc,
                      char *const args[], char *result, size_t size);

#endif /* ARIEL_ADDON_H */
