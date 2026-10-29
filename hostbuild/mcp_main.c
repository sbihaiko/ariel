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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcp.h"
#include "mcp_check.h"

#define PORT_DEFAULT "2324"
#define TIMEOUT_DEFAULT 65
#define TIMEOUT_MAX 3600
#define PORT_MAX 65535
#define TOKEN_HEX_LEN 32
#define VALUE_MAX 256
#define ENV_LINE_MAX 1024
#define SOURCE_MAX 512

typedef struct {
  const char *host;
  const char *port;
  const char *token;
  const char *env_file;
  const char *timeout;
  int check;
  int list;
} options_t;

typedef struct {
  char host[VALUE_MAX];
  char token[VALUE_MAX];
} env_file_t;


static int
take_value(int argc, char **argv, int *i, const char **value) {
  if(*i + 1 >= argc) {
    fprintf(stderr, "ariel-mcp: %s needs a value\n", argv[*i]);
    return -1;
  }
  *value = argv[++*i];
  return 0;
}


static int
parse_args(int argc, char **argv, options_t *opt) {
  int i;

  for(i=1; i<argc; i++) {
    if(!strcmp(argv[i], "--list-tools")) {
      opt->list = 1;
    } else if(!strcmp(argv[i], "--check")) {
      opt->check = 1;
    } else if(!strcmp(argv[i], "--host")) {
      if(take_value(argc, argv, &i, &opt->host)) return -1;
    } else if(!strcmp(argv[i], "--port")) {
      if(take_value(argc, argv, &i, &opt->port)) return -1;
    } else if(!strcmp(argv[i], "--token")) {
      if(take_value(argc, argv, &i, &opt->token)) return -1;
    } else if(!strcmp(argv[i], "--env-file")) {
      if(take_value(argc, argv, &i, &opt->env_file)) return -1;
    } else if(!strcmp(argv[i], "--timeout")) {
      if(take_value(argc, argv, &i, &opt->timeout)) return -1;
    } else {
      fprintf(stderr, "%s: refused %s; the server takes no key and never signs\n",
              argv[0], argv[i]);
      return -1;
    }
  }

  return 0;
}


static int
copy_value(char *dst, size_t cap, const char *src) {
  size_t n = strcspn(src, "\r\n");

  if(n >= cap) {
    return -1;
  }
  memcpy(dst, src, n);
  dst[n] = '\0';
  return 0;
}


static int
read_env_file(const char *path, env_file_t *env) {
  char line[ENV_LINE_MAX];
  int bad = 0;
  FILE *f;

  f = fopen(path, "r");
  if(!f) {
    fprintf(stderr, "ariel-mcp: cannot read --env-file %s: %s\n", path,
            strerror(errno));
    return -1;
  }
  while(!bad && fgets(line, sizeof(line), f)) {
    if(!strncmp(line, "PS5_HOST=", 9)) {
      bad = copy_value(env->host, sizeof(env->host), line + 9);
    } else if(!strncmp(line, "ARIEL_TOKEN=", 12)) {
      bad = copy_value(env->token, sizeof(env->token), line + 12);
    }
  }
  fclose(f);

  if(bad) {
    fprintf(stderr, "ariel-mcp: a value in --env-file %s is too long\n", path);
    return -1;
  }
  return 0;
}


static const char *
pick(const char *flag, const char *file, const char *env) {
  if(flag) {
    return flag;
  }
  if(file && file[0]) {
    return file;
  }
  if(env && env[0]) {
    return env;
  }
  return NULL;
}


static const char *
token_source(const options_t *opt, const env_file_t *env, char *buf, size_t cap) {
  if(opt->token) {
    return "--token";
  }
  if(env->token[0]) {
    snprintf(buf, cap, "ARIEL_TOKEN in %s", opt->env_file);
    return buf;
  }
  return "ARIEL_TOKEN in the environment";
}


static int
token_is_hex(const char *token) {
  size_t i;

  if(strlen(token) != TOKEN_HEX_LEN) {
    return 0;
  }
  for(i=0; i<TOKEN_HEX_LEN; i++) {
    if(!isdigit((unsigned char)token[i]) &&
       !(token[i] >= 'a' && token[i] <= 'f')) {
      return 0;
    }
  }
  return 1;
}


static int
parse_bounded(const char *text, long max, long *value) {
  char *end = NULL;

  errno = 0;
  *value = strtol(text, &end, 10);
  if(errno || end == text || *end || *value < 1 || *value > max) {
    return -1;
  }
  return 0;
}


int
main(int argc, char **argv) {
  char source[SOURCE_MAX];
  options_t opt;
  env_file_t env;
  const char *where;
  const char *host;
  const char *token;
  const char *port;
  long value;
  int timeout = TIMEOUT_DEFAULT;

  memset(&opt, 0, sizeof(opt));
  memset(&env, 0, sizeof(env));

  if(parse_args(argc, argv, &opt)) {
    return 2;
  }
  if(opt.env_file && read_env_file(opt.env_file, &env)) {
    return 2;
  }

  port = opt.port ? opt.port : PORT_DEFAULT;
  if(parse_bounded(port, PORT_MAX, &value)) {
    fprintf(stderr, "ariel-mcp: --port must be a number from 1 to %d\n", PORT_MAX);
    return 2;
  }
  if(opt.timeout) {
    if(parse_bounded(opt.timeout, TIMEOUT_MAX, &value)) {
      fprintf(stderr, "ariel-mcp: --timeout must be a number of seconds from 1 to %d\n",
              TIMEOUT_MAX);
      return 2;
    }
    timeout = (int)value;
  }

  host = pick(opt.host, env.host, getenv("PS5_HOST"));
  token = pick(opt.token, env.token, getenv("ARIEL_TOKEN"));
  if(token && !token_is_hex(token)) {
    fprintf(stderr, "ariel-mcp: the access token from %s is not %d lowercase hex digits\n",
            token_source(&opt, &env, source, sizeof(source)), TOKEN_HEX_LEN);
    return 2;
  }

  if(opt.check) {
    where = opt.env_file ? opt.env_file : "--env-file";
    if(!host) {
      fprintf(stderr, "ariel-mcp: no console address: give --host, or PS5_HOST in %s or the environment\n",
              where);
      return 2;
    }
    if(!token) {
      fprintf(stderr, "ariel-mcp: no access token: give --token, or ARIEL_TOKEN in %s or the environment\n",
              where);
      return 2;
    }
    return mcp_check(host, port, token, timeout, stdout, stderr) ? 1 : 0;
  }

  if(opt.list) {
    fprintf(stderr, "protocol %s\n", MCP_PROTOCOL_REVISION);
    mcp_write_tools(stdout);
    putchar('\n');
    return 0;
  }

  return mcp_serve(stdin, stdout);
}
