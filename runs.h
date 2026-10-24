/* Ariel: payloads that run in the background.

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

#ifndef ARIEL_RUNS_H
#define ARIEL_RUNS_H

#include <stddef.h>
#include <sys/types.h>

#include "platform.h"

/** A background run is cut this long after it starts. **/
#define RUN_TIMEOUT_MS 30000ULL

/** At most this many payloads run in the background at once. **/
#define RUNS_MAX 8

/** What starting a background run ended in. **/
#define RUNS_STARTED 0
#define RUNS_ALREADY 1
#define RUNS_FULL    2
#define RUNS_FAILED  3
#define RUNS_AUDIT   4

/** Start verified bytes as name in the background, setting pid on success. **/
int runs_start(platform_t *platform, const char *name, const char *sha256,
               const unsigned char *bytes, size_t size, pid_t *pid);

/** Whether a background run of name is still going. Returns 1 or 0. **/
int runs_running(const char *name);

#endif /* ARIEL_RUNS_H */
