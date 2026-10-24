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

#include <stdio.h>
#include <string.h>

#include "autoload.h"
#include "platform.h"

static int
parse(const char *text, char names[][PAYLOAD_NAME_MAX + 1], size_t *count) {
  const char *p = text;
  size_t n = 0;
  size_t i;

  while(*p) {
    const char *nl = strchr(p, '\n');
    size_t len;

    if(!nl || n == AUTOLOAD_ENTRIES_MAX) {
      return -1;
    }

    len = (size_t)(nl - p);
    if(len == 0 || len > PAYLOAD_NAME_MAX) {
      return -1;
    }

    memcpy(names[n], p, len);
    names[n][len] = '\0';
    for(i=0; i<n; i++) {
      if(!strcmp(names[i], names[n])) {
        return -1;
      }
    }

    n++;
    p = nl + 1;
  }

  if(n == 0 || strcmp(names[0], AUTOLOAD_SELF)) {
    return -1;
  }

  *count = n;
  return 0;
}


int
autoload_edit(const char *text, int add, const char *name, char *out,
              size_t size) {
  char names[AUTOLOAD_ENTRIES_MAX][PAYLOAD_NAME_MAX + 1];
  size_t count = 0;
  size_t found;
  size_t i;
  size_t len = 0;

  if(strlen(name) > PAYLOAD_NAME_MAX || parse(text, names, &count)) {
    return AUTOLOAD_MALFORMED;
  }

  for(found=0; found<count; found++) {
    if(!strcmp(names[found], name)) {
      break;
    }
  }

  if(add) {
    if(found < count) {
      return AUTOLOAD_PRESENT;
    }
    if(count == AUTOLOAD_ENTRIES_MAX) {
      return AUTOLOAD_FULL;
    }
    strcpy(names[count], name);
    count++;
  } else {
    if(!strcmp(name, AUTOLOAD_SELF)) {
      return AUTOLOAD_PINNED;
    }
    if(found == count) {
      return AUTOLOAD_ABSENT;
    }
    for(i=found; i+1<count; i++) {
      strcpy(names[i], names[i + 1]);
    }
    count--;
  }

  for(i=0; i<count; i++) {
    int w = snprintf(out + len, size - len, "%s\n", names[i]);

    if(w < 0 || (size_t)w >= size - len) {
      return AUTOLOAD_MALFORMED;
    }
    len += (size_t)w;
  }

  return AUTOLOAD_OK;
}
