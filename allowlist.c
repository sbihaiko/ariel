/* Ariel: the download allowlist, which names what an install may fetch.

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

#include "allowlist.h"

#define LINE_MAX 512

static int
token_ok(const char *text, const char *extra) {
  size_t i;

  if(!text[0] || strlen(text) >= ALLOWLIST_TOKEN_MAX) {
    return 0;
  }

  for(i=0; text[i]; i++) {
    char c = text[i];
    if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
         (c && strchr(extra, c)))) {
      return 0;
    }
  }

  return 1;
}


static int
hash_ok(const char *text) {
  size_t i;

  if(strlen(text) != 64) {
    return 0;
  }

  for(i=0; i<64; i++) {
    if(!((text[i] >= '0' && text[i] <= '9') ||
         (text[i] >= 'a' && text[i] <= 'f'))) {
      return 0;
    }
  }

  return 1;
}


static int
split_line(char *line, char *tok[], int max) {
  int n = 0;
  char *s = line;

  for(;;) {
    while(*s == ' ') {
      s++;
    }
    if(!*s) {
      break;
    }
    if(n == max) {
      return -1;
    }
    tok[n++] = s;
    while(*s && *s != ' ') {
      s++;
    }
    if(*s) {
      *s++ = '\0';
    }
  }

  return n;
}


static int
add_pin(allowlist_t *list, const char *name, const char *sha256) {
  size_t i;

  if(list->npins == ALLOWLIST_PINS_MAX || strlen(name) > PAYLOAD_NAME_MAX ||
     !hash_ok(sha256)) {
    return -1;
  }

  for(i=0; i<list->npins; i++) {
    if(!strcmp(list->pin_names[i], name)) {
      return -1;
    }
  }

  snprintf(list->pin_names[list->npins], sizeof(list->pin_names[0]), "%s", name);
  snprintf(list->pin_hashes[list->npins], sizeof(list->pin_hashes[0]), "%s",
           sha256);
  list->npins++;
  return 0;
}


static int
directive(allowlist_t *list, char *tok[], int n) {
  if(n == 2 && !strcmp(tok[0], "host") && token_ok(tok[1], ":") &&
     list->nhosts < ALLOWLIST_HOSTS_MAX) {
    snprintf(list->hosts[list->nhosts++], ALLOWLIST_TOKEN_MAX, "%s", tok[1]);
    return 0;
  }

  if(n == 2 && !strcmp(tok[0], "cdn") && token_ok(tok[1], "") &&
     !list->cdn[0]) {
    snprintf(list->cdn, sizeof(list->cdn), "%s", tok[1]);
    return 0;
  }

  if(n == 2 && !strcmp(tok[0], "repo") && token_ok(tok[1], "/") &&
     list->nrepos < ALLOWLIST_REPOS_MAX) {
    snprintf(list->repos[list->nrepos++], ALLOWLIST_TOKEN_MAX, "%s", tok[1]);
    return 0;
  }

  if(n == 3 && !strcmp(tok[0], "pin")) {
    return add_pin(list, tok[1], tok[2]);
  }

  return -1;
}


int
allowlist_parse(const char *text, allowlist_t *list) {
  const char *p = text;

  memset(list, 0, sizeof(*list));

  while(*p) {
    const char *eol = strchr(p, '\n');
    size_t len = eol ? (size_t)(eol - p) : strlen(p);
    char line[LINE_MAX];
    char *tok[3];
    int n;

    if(len > 0 && p[len-1] == '\r') {
      len--;
    }

    if(len >= sizeof(line)) {
      return -1;
    }

    memcpy(line, p, len);
    line[len] = '\0';
    p = eol ? eol + 1 : p + len;

    if(!line[0] || line[0] == '#') {
      continue;
    }

    n = split_line(line, tok, 3);
    if(n < 0 || n == 0 || directive(list, tok, n)) {
      return -1;
    }
  }

  return 0;
}


const char *
allowlist_api_host(const allowlist_t *list) {
  return list->nhosts ? list->hosts[0] : NULL;
}


int
allowlist_has_host(const allowlist_t *list, const char *authority) {
  size_t i;

  for(i=0; i<list->nhosts; i++) {
    if(!strcmp(list->hosts[i], authority)) {
      return 1;
    }
  }

  return 0;
}


int
allowlist_has_repo(const allowlist_t *list, const char *repo) {
  size_t i;

  for(i=0; i<list->nrepos; i++) {
    if(!strcmp(list->repos[i], repo)) {
      return 1;
    }
  }

  return 0;
}


int
allowlist_cdn_host(const allowlist_t *list, const char *authority) {
  size_t hlen;
  size_t clen = strlen(list->cdn);
  const char *colon = strchr(authority, ':');

  if(!clen) {
    return 0;
  }

  hlen = colon ? (size_t)(colon - authority) : strlen(authority);

  if(hlen == clen) {
    return !strncmp(authority, list->cdn, clen);
  }

  return hlen > clen + 1 && authority[hlen - clen - 1] == '.' &&
         !strncmp(authority + hlen - clen, list->cdn, clen);
}


const char *
allowlist_pin(const allowlist_t *list, const char *name) {
  size_t i;

  for(i=0; i<list->npins; i++) {
    if(!strcmp(list->pin_names[i], name)) {
      return list->pin_hashes[i];
    }
  }

  return NULL;
}


int
allowlist_with_pin(const char *text, const char *name, const char *sha256,
                   char *out, size_t size) {
  size_t len = strlen(text);
  int newline = len && text[len-1] != '\n';
  int n = snprintf(out, size, "%s%spin %s %s\n", text, newline ? "\n" : "",
                   name, sha256);

  if(n < 0 || (size_t)n >= size) {
    return -1;
  }

  return n;
}
