/* Ariel: the payloads the loader runs at boot.

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

#ifndef ARIEL_AUTOLOAD_H
#define ARIEL_AUTOLOAD_H

#include <stddef.h>

#define AUTOLOAD_SELF        "ariel"
#define AUTOLOAD_ENTRIES_MAX 16
#define AUTOLOAD_TEXT_MAX    1024
#define AUTOLOAD_DEFAULT     AUTOLOAD_SELF "\n"

/** What one edit of the list ended in. **/
#define AUTOLOAD_OK        0
#define AUTOLOAD_PINNED    1
#define AUTOLOAD_PRESENT   2
#define AUTOLOAD_ABSENT    3
#define AUTOLOAD_FULL      4
#define AUTOLOAD_MALFORMED 5

/**
 * Apply one edit to a list text: one payload name per line, Ariel first. A
 * list that does not begin with Ariel, repeats a name or holds more than
 * AUTOLOAD_ENTRIES_MAX entries is malformed. Ariel can not be removed. On
 * AUTOLOAD_OK the new text is written to out, NUL-terminated, and an
 * AUTOLOAD_TEXT_MAX buffer always holds it. Returns one of AUTOLOAD_*.
 **/
int autoload_edit(const char *text, int add, const char *name, char *out,
                  size_t size);

#endif /* ARIEL_AUTOLOAD_H */
