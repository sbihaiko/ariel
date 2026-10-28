/* Ariel: the readers that need the platform.

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

#ifndef ARIEL_READERS_H
#define ARIEL_READERS_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/** The most bytes of a mount's target or source a reader keeps. **/
#define READER_TEXT 256

/** One mount: its target, with the root stripped, and its source. **/
typedef struct {
  char target[READER_TEXT];
  char source[READER_TEXT];
} reader_mount_t;

/**
 * Copy a mount target that lies at or under root into rooted, with root
 * stripped, so the root "/" is what a console's own paths are. Returns 1 when
 * the target lies under root and rooted holds it, 0 when it does not.
 **/
static inline int
readers_mount_rooted(const char *root, const char *target, char *rooted,
                     size_t size) {
  size_t n = strlen(root);

  if(n && strncmp(target, root, n)) {
    return 0;
  }
  if(n && target[n] && target[n] != '/') {
    return 0;
  }
  snprintf(rooted, size, "%s", target[n] ? target + n : "/");
  return 1;
}

/** The time the machine booted, in seconds since the epoch. Returns 0 or -1. **/
int readers_boot_time(time_t *boot);

/**
 * The mounts whose target lies under root, in the order the system lists
 * them: total is their number, and the first max are stored in out. Returns
 * 0 or -1.
 **/
int readers_mounts(const char *root, reader_mount_t *out, size_t max,
                   size_t *total);

/**
 * Run one platform reader of the agent port: ps, procstat, sysctl, authid,
 * dmesg, sysinfo, ifconfig and ping. The arguments are as for runner_run, and json
 * is 1 for the --json form, which ps, sysinfo and ifconfig answer. Returns 0
 * and the reader's status when argv[0]
 * is a reader, or -1 when it is not one, or when the arguments ask for
 * something a reader does not do, such as a sysctl write.
 **/
int readers_run(int json, int argc, char *const argv[], int outfd, int errfd,
                int *status);

#endif /* ARIEL_READERS_H */
