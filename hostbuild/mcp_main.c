/* Ariel host build: the MCP server, a host process that never signs.

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

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "mcp.h"
#include "mcp_link.h"

#define DEFAULT_PORT "2324"
#define DEFAULT_TIMEOUT "65"
#define PORT_MAX 65535
#define TIMEOUT_MAX 3600
#define TOKEN_HEX_LEN 32
#define ENV_VALUE_MAX 512

enum origin {
  FROM_NONE,
  FROM_DEFAULT,
  FROM_FLAG,
  FROM_FILE,
  FROM_ENV
};

struct setting {
  const char *text;
  enum origin from;
};

struct settings {
  struct setting host;
  struct setting port;
  struct setting token;
  struct setting env_file;
  struct setting timeout;
  int check;
  int list;
};

struct envfile {
  char host[ENV_VALUE_MAX];
  char token[ENV_VALUE_MAX];
  int has_host;
  int has_token;
};

struct config {
  struct envfile file;
  const char *host;
  const char *token;
  long port;
  long timeout;
};


static int
usable(const struct setting *value) {
  return value->text && value->text[0];
}


static struct setting
from_environment(const char *name) {
  struct setting value = { NULL, FROM_NONE };
  const char *text = getenv(name);

  if(text && text[0]) {
    value.text = text;
    value.from = FROM_ENV;
  }
  return value;
}


static struct setting
choose(const struct setting *flag, const struct setting *file,
       const struct setting *env) {
  if(usable(flag)) {
    return *flag;
  }
  if(usable(file)) {
    return *file;
  }
  return *env;
}


static void
name_source(char *out, size_t len, const struct setting *value,
            const char *flag, const char *key, const char *path) {
  if(value->from == FROM_FLAG) {
    snprintf(out, len, "%s", flag);
  } else if(value->from == FROM_FILE) {
    snprintf(out, len, "%s in %s", key, path);
  } else {
    snprintf(out, len, "%s in the environment", key);
  }
}


static int
whole_number(const char *text, long low, long high, long *out) {
  char *end = NULL;
  long value;

  if(!isdigit((unsigned char)text[0])) {
    return 0;
  }
  errno = 0;
  value = strtol(text, &end, 10);
  if(errno || *end || value < low || value > high) {
    return 0;
  }
  *out = value;
  return 1;
}


static int
valid_token(const char *text) {
  size_t i;

  if(strlen(text) != TOKEN_HEX_LEN) {
    return 0;
  }
  for(i = 0; i < TOKEN_HEX_LEN; i++) {
    char c = text[i];

    if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  return 1;
}


static char *
trim(char *text) {
  char *end;

  while(*text == ' ' || *text == '\t') {
    text++;
  }
  end = text + strlen(text);
  while(end > text && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n')) {
    end--;
  }
  *end = '\0';
  return text;
}


static int
store(char *dest, int *has, const char *value, const char *path, const char *key) {
  if(strlen(value) >= ENV_VALUE_MAX) {
    fprintf(stderr, "ariel-mcp: %s in %s is too long\n", key, path);
    return -1;
  }
  snprintf(dest, ENV_VALUE_MAX, "%s", value);
  *has = value[0] != '\0';
  return 0;
}


static int
read_env_file(const char *path, struct envfile *file) {
  FILE *in = fopen(path, "r");
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int rc = 0;

  if(!in) {
    fprintf(stderr, "ariel-mcp: cannot read env file %s: %s\n", path, strerror(errno));
    return -1;
  }
  while((n = getline(&line, &cap, in)) >= 0) {
    char *text = trim(line);
    char *eq = strchr(text, '=');
    char *value;
    size_t len;

    if(text[0] == '#' || !eq) {
      continue;
    }
    *eq = '\0';
    value = trim(eq + 1);
    len = strlen(value);
    if(len >= 2 && (value[0] == '"' || value[0] == '\'') && value[len - 1] == value[0]) {
      value[len - 1] = '\0';
      value++;
    }
    if(!strcmp(text, "PS5_HOST")) {
      rc = store(file->host, &file->has_host, value, path, "PS5_HOST");
    } else if(!strcmp(text, "ARIEL_TOKEN")) {
      rc = store(file->token, &file->has_token, value, path, "ARIEL_TOKEN");
    }
    if(rc) {
      break;
    }
  }

  free(line);
  fclose(in);
  return rc;
}


static struct setting *
flag_slot(struct settings *s, const char *name) {
  if(!strcmp(name, "--host")) {
    return &s->host;
  }
  if(!strcmp(name, "--port")) {
    return &s->port;
  }
  if(!strcmp(name, "--token")) {
    return &s->token;
  }
  if(!strcmp(name, "--env-file")) {
    return &s->env_file;
  }
  if(!strcmp(name, "--timeout")) {
    return &s->timeout;
  }
  return NULL;
}


static int
parse_args(int argc, char **argv, struct settings *s) {
  int i;

  for(i = 1; i < argc; i++) {
    struct setting *slot = flag_slot(s, argv[i]);

    if(!strcmp(argv[i], "--check")) {
      s->check = 1;
    } else if(!strcmp(argv[i], "--list-tools")) {
      s->list = 1;
    } else if(slot) {
      if(i + 1 >= argc) {
        fprintf(stderr, "ariel-mcp: %s needs a value\n", argv[i]);
        return -1;
      }
      slot->text = argv[++i];
      slot->from = FROM_FLAG;
    } else {
      fprintf(stderr, "ariel-mcp: refused %.*s; the server takes no key and never signs\n",
              (int)strcspn(argv[i], "="), argv[i]);
      return -1;
    }
  }
  return 0;
}


static void
refuse_missing(const char *what, const char *flag, const char *key,
               const struct settings *s) {
  if(usable(&s->env_file)) {
    fprintf(stderr, "ariel-mcp: missing %s: pass %s, or set %s in %s or the environment\n",
            what, flag, key, s->env_file.text);
  } else {
    fprintf(stderr, "ariel-mcp: missing %s: pass %s, or set %s in an env file or the environment\n",
            what, flag, key);
  }
}


static int
configure(struct settings *s, struct config *c) {
  struct setting none = { NULL, FROM_NONE };
  struct setting file_host = { NULL, FROM_FILE };
  struct setting file_token = { NULL, FROM_FILE };
  struct setting host;
  struct setting token;
  struct setting port;
  struct setting timeout;
  char source[ENV_VALUE_MAX + 64];

  memset(c, 0, sizeof(*c));
  if(!usable(&s->env_file)) {
    s->env_file = from_environment("ARIEL_ENV_FILE");
  }
  if(usable(&s->env_file) && read_env_file(s->env_file.text, &c->file)) {
    return -1;
  }

  file_host.text = c->file.has_host ? c->file.host : NULL;
  file_token.text = c->file.has_token ? c->file.token : NULL;
  host = choose(&s->host, &file_host, &none);
  if(!usable(&host)) {
    host = from_environment("PS5_HOST");
  }
  token = choose(&s->token, &file_token, &none);
  if(!usable(&token)) {
    token = from_environment("ARIEL_TOKEN");
  }
  port = s->port;
  if(!usable(&port)) {
    port = from_environment("ARIEL_PORT");
  }
  if(!usable(&port)) {
    port.text = DEFAULT_PORT;
    port.from = FROM_DEFAULT;
  }
  timeout = s->timeout;
  if(!usable(&timeout)) {
    timeout = from_environment("ARIEL_TIMEOUT");
  }
  if(!usable(&timeout)) {
    timeout.text = DEFAULT_TIMEOUT;
    timeout.from = FROM_DEFAULT;
  }

  if(!usable(&host)) {
    refuse_missing("console host", "--host", "PS5_HOST", s);
    return -1;
  }
  if(!usable(&token)) {
    refuse_missing("access token", "--token", "ARIEL_TOKEN", s);
    return -1;
  }
  if(!valid_token(token.text)) {
    name_source(source, sizeof(source), &token, "--token", "ARIEL_TOKEN",
                s->env_file.text);
    fprintf(stderr, "ariel-mcp: %s is not %d lowercase hex digits\n",
            source, TOKEN_HEX_LEN);
    return -1;
  }
  if(!whole_number(port.text, 1, PORT_MAX, &c->port)) {
    name_source(source, sizeof(source), &port, "--port", "ARIEL_PORT", NULL);
    fprintf(stderr, "ariel-mcp: %s must be a port number from 1 to %d\n",
            source, PORT_MAX);
    return -1;
  }
  if(!whole_number(timeout.text, 1, TIMEOUT_MAX, &c->timeout)) {
    name_source(source, sizeof(source), &timeout, "--timeout", "ARIEL_TIMEOUT", NULL);
    fprintf(stderr, "ariel-mcp: %s must be a whole number of seconds from 1 to %d\n",
            source, TIMEOUT_MAX);
    return -1;
  }

  c->host = host.text;
  c->token = token.text;
  return 0;
}


int
main(int argc, char **argv) {
  struct settings s;
  struct config c;
  struct mcp_console console;
  char why[MCP_LINK_WHY_MAX];

  memset(&s, 0, sizeof(s));
  if(parse_args(argc, argv, &s)) {
    return 2;
  }
  if(s.check && s.list) {
    fputs("ariel-mcp: --check and --list-tools cannot be given together\n", stderr);
    return 2;
  }

  if(s.list) {
    fprintf(stderr, "protocol %s\n", MCP_PROTOCOL_REVISION);
    mcp_write_tools(stdout);
    putchar('\n');
    return 0;
  }

  if(configure(&s, &c)) {
    return 2;
  }

  console.host = c.host;
  console.port = (int)c.port;
  console.token = c.token;
  console.timeout_s = (int)c.timeout;

  signal(SIGPIPE, SIG_IGN);
  if(mcp_probe(&console, why, sizeof(why))) {
    fprintf(stderr, "ariel-mcp: %s\n", why);
    return 1;
  }
  if(s.check) {
    printf("ariel-mcp: console %s:%ld accepted the token\n", c.host, c.port);
    return 0;
  }

  return mcp_serve(stdin, stdout, &console);
}
