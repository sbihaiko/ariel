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

/* IFNAMSIZ, spelled out because the host build's POSIX level hides it. */
#define INTERFACE_NAME_SIZE 16

/** One interface address, or an interface with no IPv4 address. **/
typedef struct {
  char name[INTERFACE_NAME_SIZE];
  int up;
  int has_address;
  unsigned char address[4];
  unsigned char mask[4];
} interface_row_t;

/**
 * Write the ifconfig answer: one line per row, or one JSON object per row,
 * sorted by name and then by address, under the output cap. A row with no
 * address writes `-` for the address and the mask. The rows are sorted in
 * place.
 **/
void diagnostics_say_interfaces(int json, int fd, interface_row_t *rows,
                                size_t count);

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
