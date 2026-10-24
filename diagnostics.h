/* Ariel: the answers of the diagnostic commands that both builds share.

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

#ifndef ARIEL_DIAGNOSTICS_H
#define ARIEL_DIAGNOSTICS_H

#include <stddef.h>

/**
 * Write the sysinfo answer: three lines, or one JSON object with the same
 * facts. The platform reads its own uname, uptime and memory figures; the
 * shape is written once, here, so the two builds cannot drift.
 **/
void diagnostics_say_sysinfo(int json, int fd, const char *sysname,
                             const char *release, const char *machine,
                             unsigned long long uptime_seconds,
                             unsigned long long memory_total,
                             unsigned long long memory_free);

/**
 * Write a kernel log, given as len bytes of lines, as a bounded answer: at
 * most the output cap, then `truncated <shown> of <total>`. A NUL byte
 * ends the log.
 **/
void diagnostics_say_log(int fd, const char *data, size_t len);

#endif /* ARIEL_DIAGNOSTICS_H */
