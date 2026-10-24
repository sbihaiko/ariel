/* Ariel: the zip archives unzip reads.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <stdint.h>
#include <string.h>

#include "zip.h"

#define ZIP_EOCD_SIG    0x06054b50UL
#define ZIP_CEN_SIG     0x02014b50UL
#define ZIP_LOC_SIG     0x04034b50UL
#define ZIP_EOCD_LEN    22
#define ZIP_CEN_LEN     46
#define ZIP_LOC_LEN     30
#define ZIP_COMMENT_MAX 65535


static uint32_t
u16(const unsigned char *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}


static uint32_t
u32(const unsigned char *p) {
  return u16(p) | (u16(p + 2) << 16);
}


static int
eocd_find(const unsigned char *buf, size_t len, size_t *at) {
  size_t low = len > ZIP_EOCD_LEN + ZIP_COMMENT_MAX ?
               len - ZIP_EOCD_LEN - ZIP_COMMENT_MAX : 0;
  size_t i;

  if(len < ZIP_EOCD_LEN) {
    return ZIP_BAD;
  }
  for(i = len - ZIP_EOCD_LEN + 1; i-- > low;) {
    if(u32(buf + i) == ZIP_EOCD_SIG) {
      *at = i;
      return ZIP_OK;
    }
  }
  return ZIP_BAD;
}


static size_t
key_len(const zip_member_t *m) {
  size_t n = strlen(m->name);

  return m->dir ? n - 1 : n;
}


/** Whether two members cannot both be extracted: the same name, or one below a file. **/
static int
clash(const zip_member_t *a, const zip_member_t *b) {
  size_t la = key_len(a);
  size_t lb = key_len(b);

  if(la == lb && !strncmp(a->name, b->name, la)) {
    return 1;
  }
  return !b->dir && la > lb && !strncmp(a->name, b->name, lb) &&
         a->name[lb] == '/';
}


int
zip_name_safe(const char *name) {
  const char *seg = name;
  size_t n;

  if(name[0] == '/' || name[0] == '\0') {
    return 0;
  }
  for(;;) {
    n = strcspn(seg, "/\\");
    if(n == 0 || (n == 1 && seg[0] == '.') ||
       (n == 2 && !strncmp(seg, "..", 2))) {
      return 0;
    }
    if(seg[n] == '\\') {
      return 0;
    }
    if(seg[n] == '\0') {
      return 1;
    }
    seg += n + 1;
    if(*seg == '\0') {
      return 1;
    }
  }
}


int
zip_members(const unsigned char *buf, size_t len, zip_member_t *members,
            size_t max, size_t *count) {
  size_t eocd;
  size_t cen_off;
  size_t cen_end;
  size_t p;
  uint32_t cen_size;
  uint32_t n;
  uint32_t i;
  size_t j;
  size_t k;

  *count = 0;
  if(eocd_find(buf, len, &eocd)) {
    return ZIP_BAD;
  }
  if(u16(buf + eocd + 4) || u16(buf + eocd + 6)) {
    return ZIP_BAD;
  }

  n = u16(buf + eocd + 10);
  cen_size = u32(buf + eocd + 12);
  cen_off = u32(buf + eocd + 16);
  if(n == 0xFFFFu || cen_off == 0xFFFFFFFFu || n > max) {
    return ZIP_BAD;
  }
  if(cen_size > eocd || cen_off > eocd - cen_size) {
    return ZIP_BAD;
  }
  cen_end = cen_off + cen_size;

  p = cen_off;
  for(i = 0; i < n; i++) {
    const unsigned char *h;
    size_t nlen;
    size_t xlen;
    size_t clen;
    size_t loc;
    size_t data;
    size_t size;

    if(cen_end - p < ZIP_CEN_LEN) {
      return ZIP_BAD;
    }
    h = buf + p;
    if(u32(h) != ZIP_CEN_SIG || (u16(h + 8) & 1) || u16(h + 10)) {
      return ZIP_BAD;
    }

    size = u32(h + 24);
    nlen = u16(h + 28);
    xlen = u16(h + 30);
    clen = u16(h + 32);
    loc = u32(h + 42);
    if(u32(h + 20) != size || nlen == 0 || nlen > ZIP_NAME_MAX) {
      return ZIP_BAD;
    }
    if(cen_end - p - ZIP_CEN_LEN < nlen + xlen + clen) {
      return ZIP_BAD;
    }

    if(loc > cen_off || cen_off - loc < ZIP_LOC_LEN ||
       u32(buf + loc) != ZIP_LOC_SIG) {
      return ZIP_BAD;
    }
    data = loc + ZIP_LOC_LEN + u16(buf + loc + 26) + u16(buf + loc + 28);
    if(data > cen_off || cen_off - data < size) {
      return ZIP_BAD;
    }

    for(k = 0; k < nlen; k++) {
      unsigned char c = h[ZIP_CEN_LEN + k];

      if(c < 0x20 || c == 0x7f) {
        return ZIP_BAD;
      }
    }
    memcpy(members[i].name, h + ZIP_CEN_LEN, nlen);
    members[i].name[nlen] = '\0';
    members[i].dir = members[i].name[nlen - 1] == '/';
    members[i].data = buf + data;
    members[i].size = size;

    p += ZIP_CEN_LEN + nlen + xlen + clen;
  }
  if(p != cen_end) {
    return ZIP_BAD;
  }

  for(i = 0; i < n; i++) {
    for(j = 0; j < n; j++) {
      if(i != j && clash(&members[i], &members[j])) {
        return ZIP_BAD;
      }
    }
  }

  *count = n;
  return ZIP_OK;
}
