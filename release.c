/* Ariel: the release document a release API answers with.

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

#include "release.h"

#define KEY_MAX 64
#define NAME_MAX_ASSET 128
#define DEPTH_MAX 16

static const char *
skip_ws(const char *p) {
  while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
    p++;
  }
  return p;
}


/* Reads a string into out when out is not NULL, otherwise only skips it. */
static const char *
string_read(const char *p, char *out, size_t size) {
  size_t n = 0;

  if(*p != '"') {
    return NULL;
  }

  for(p++; *p != '"'; p++) {
    char c = *p;

    if(!c || (unsigned char)c < 0x20) {
      return NULL;
    }

    if(c == '\\') {
      p++;
      c = *p;
      if(c != '"' && c != '\\' && c != '/') {
        return NULL;
      }
    }

    if(out) {
      if(n + 1 >= size) {
        return NULL;
      }
      out[n++] = c;
    }
  }

  if(out) {
    out[n] = '\0';
  }

  return p + 1;
}


static const char *
number_read(const char *p, uint64_t *out) {
  uint64_t value = 0;
  int digits = 0;

  while(*p >= '0' && *p <= '9') {
    if(digits == 18) {
      return NULL;
    }
    value = value * 10 + (uint64_t)(*p - '0');
    digits++;
    p++;
  }

  if(!digits) {
    return NULL;
  }

  *out = value;
  return p;
}


static const char *
value_skip(const char *p, int depth) {
  uint64_t ignored;

  if(depth > DEPTH_MAX) {
    return NULL;
  }

  p = skip_ws(p);

  if(*p == '"') {
    return string_read(p, NULL, 0);
  }

  if(*p == '{' || *p == '[') {
    char close = *p == '{' ? '}' : ']';

    p = skip_ws(p + 1);
    if(*p == close) {
      return p + 1;
    }

    for(;;) {
      if(close == '}') {
        p = string_read(skip_ws(p), NULL, 0);
        if(!p) {
          return NULL;
        }
        p = skip_ws(p);
        if(*p != ':') {
          return NULL;
        }
        p++;
      }

      p = value_skip(p, depth + 1);
      if(!p) {
        return NULL;
      }

      p = skip_ws(p);
      if(*p == ',') {
        p++;
        continue;
      }
      if(*p == close) {
        return p + 1;
      }
      return NULL;
    }
  }

  if(!strncmp(p, "true", 4)) {
    return p + 4;
  }
  if(!strncmp(p, "false", 5)) {
    return p + 5;
  }
  if(!strncmp(p, "null", 4)) {
    return p + 4;
  }

  return number_read(p, &ignored);
}


static const char *
asset_object(const char *p, const char *asset, release_t *out, int *found) {
  char key[KEY_MAX];
  char name[NAME_MAX_ASSET];
  char url[RELEASE_URL_MAX + 1];
  uint64_t id = 0;
  uint64_t size = 0;
  int have_id = 0;
  int have_name = 0;
  int have_url = 0;
  int have_size = 0;

  p = skip_ws(p);
  if(*p != '{') {
    return NULL;
  }

  p = skip_ws(p + 1);
  if(*p == '}') {
    return p + 1;
  }

  for(;;) {
    p = string_read(skip_ws(p), key, sizeof(key));
    if(!p) {
      return NULL;
    }

    p = skip_ws(p);
    if(*p != ':') {
      return NULL;
    }
    p = skip_ws(p + 1);

    if(!strcmp(key, "id")) {
      p = number_read(p, &id);
      have_id = 1;
    } else if(!strcmp(key, "name")) {
      p = string_read(p, name, sizeof(name));
      have_name = 1;
    } else if(!strcmp(key, "url")) {
      p = string_read(p, url, sizeof(url));
      have_url = 1;
    } else if(!strcmp(key, "size")) {
      p = number_read(p, &size);
      have_size = 1;
    } else {
      p = value_skip(p, 2);
    }

    if(!p) {
      return NULL;
    }

    p = skip_ws(p);
    if(*p == ',') {
      p = skip_ws(p + 1);
      continue;
    }
    if(*p == '}') {
      break;
    }
    return NULL;
  }

  if(!*found && have_id && have_name && have_url && have_size &&
     !strcmp(name, asset)) {
    out->asset_id = id;
    out->asset_size = size;
    snprintf(out->asset_url, sizeof(out->asset_url), "%s", url);
    *found = 1;
  }

  return p + 1;
}


static const char *
assets_read(const char *p, const char *asset, release_t *out, int *found) {
  p = skip_ws(p);
  if(*p != '[') {
    return NULL;
  }

  p = skip_ws(p + 1);
  if(*p == ']') {
    return p + 1;
  }

  for(;;) {
    p = asset_object(p, asset, out, found);
    if(!p) {
      return NULL;
    }

    p = skip_ws(p);
    if(*p == ',') {
      p = skip_ws(p + 1);
      continue;
    }
    if(*p == ']') {
      return p + 1;
    }
    return NULL;
  }
}


int
release_parse(const char *json, const char *asset, release_t *out) {
  const char *p = skip_ws(json);
  int have_id = 0;
  int have_tag = 0;
  int found = 0;

  memset(out, 0, sizeof(*out));

  if(*p != '{') {
    return -1;
  }

  p = skip_ws(p + 1);
  if(*p == '}') {
    return -1;
  }

  for(;;) {
    char key[KEY_MAX];

    p = string_read(skip_ws(p), key, sizeof(key));
    if(!p) {
      return -1;
    }

    p = skip_ws(p);
    if(*p != ':') {
      return -1;
    }
    p = skip_ws(p + 1);

    if(!strcmp(key, "id")) {
      p = number_read(p, &out->id);
      have_id = 1;
    } else if(!strcmp(key, "tag_name")) {
      p = string_read(p, out->tag, sizeof(out->tag));
      have_tag = 1;
    } else if(!strcmp(key, "assets")) {
      p = assets_read(p, asset, out, &found);
    } else {
      p = value_skip(p, 1);
    }

    if(!p) {
      return -1;
    }

    p = skip_ws(p);
    if(*p == ',') {
      p = skip_ws(p + 1);
      continue;
    }
    if(*p == '}') {
      break;
    }
    return -1;
  }

  if(!have_id || !have_tag) {
    return -1;
  }

  return found ? RELEASE_OK : RELEASE_NO_ASSET;
}
