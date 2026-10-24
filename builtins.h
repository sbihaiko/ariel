/* Ariel: the PS5 built-ins that the agent port gates behind the owner's signature.

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

#ifndef ARIEL_BUILTINS_H
#define ARIEL_BUILTINS_H

#include <string.h>

static inline int
builtin_gated(const char *name) {
  static const char *const names[] = {
    "launch", "pkg_install", "hbldr", "hbdbg", "suspend", "notify", "reptyr"
  };
  size_t i;

  for(i=0; i<sizeof(names)/sizeof(names[0]); i++) {
    if(!strcmp(name, names[i])) {
      return 1;
    }
  }
  return 0;
}

#endif
