/* Ariel: JSON text for the --json output of the table commands.

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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "json.h"


static void
put(int fd, const char *buf, size_t len) {
  while(len > 0) {
    ssize_t n = write(fd, buf, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return;
    }
    buf += n;
    len -= (size_t)n;
  }
}


void
json_say_string(int fd, const char *text) {
  const unsigned char *p = (const unsigned char *)text;
  char escape[8];

  put(fd, "\"", 1);
  for(; *p; p++) {
    if(*p == '"') {
      put(fd, "\\\"", 2);
    } else if(*p == '\\') {
      put(fd, "\\\\", 2);
    } else if(*p < 0x20) {
      snprintf(escape, sizeof(escape), "\\u%04x", (unsigned)*p);
      put(fd, escape, 6);
    } else {
      put(fd, (const char *)p, 1);
    }
  }
  put(fd, "\"", 1);
}
