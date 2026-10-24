/* Ariel host build: the agent port server.

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
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "agent_server.h"
#include "platform.h"
#include "store.h"
#include "token.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_PORT 2324


static int
ensure_dir(const char *path) {
  if(mkdir(path, 0700) && errno != EEXIST) {
    perror(path);
    return -1;
  }
  return 0;
}


static int
parse_args(int argc, char **argv, uint16_t *port, const char **root) {
  int i;

  for(i=1; i<argc; i++) {
    if(!strcmp(argv[i], "--port") && i + 1 < argc) {
      char *end = NULL;
      long value = strtol(argv[++i], &end, 10);

      if(!end || *end || value < 1 || value > 65535) {
        fprintf(stderr, "invalid port: %s\n", argv[i]);
        return -1;
      }
      *port = (uint16_t)value;
    } else if(!strcmp(argv[i], "--root") && i + 1 < argc) {
      *root = argv[++i];
    } else {
      fprintf(stderr, "usage: %s [--port PORT] [--root DIR]\n", argv[0]);
      return -1;
    }
  }

  return 0;
}


int
main(int argc, char **argv) {
  char staging_dir[PATH_MAX];
  char state_dir[PATH_MAX];
  char data_dir[PATH_MAX];
  char run_dir[PATH_MAX];
  char agent_token[TOKEN_LEN];
  agent_t agent;
  platform_t *platform;
  const char *root;
  uint16_t port = DEFAULT_PORT;
  int srvfd;

  root = getenv("ARIEL_HOST_ROOT");
  if(!root) {
    root = ".";
  }

  if(parse_args(argc, argv, &port, &root)) {
    return EXIT_FAILURE;
  }

  signal(SIGPIPE, SIG_IGN);

  // Ariel's state lives in /data/ariel under the platform's root.
  if(snprintf(data_dir, sizeof(data_dir), "%s/data", root) >=
     (int)sizeof(data_dir) ||
     snprintf(state_dir, sizeof(state_dir), "%s/ariel", data_dir) >=
     (int)sizeof(state_dir) ||
     snprintf(staging_dir, sizeof(staging_dir), "%s/staging", state_dir) >=
     (int)sizeof(staging_dir) ||
     snprintf(run_dir, sizeof(run_dir), "%s/run", state_dir) >=
     (int)sizeof(run_dir)) {
    fprintf(stderr, "root path is too long\n");
    return EXIT_FAILURE;
  }

  if(ensure_dir(root) || ensure_dir(data_dir) || ensure_dir(state_dir) ||
     ensure_dir(staging_dir) || ensure_dir(run_dir)) {
    return EXIT_FAILURE;
  }

  platform = platform_host(run_dir, root);

  // The store needs the platform's clock: approvals and staging objects
  // expire against it.
  if(store_init(state_dir, platform)) {
    fprintf(stderr, "cannot prepare Ariel's state in %s\n", state_dir);
    return EXIT_FAILURE;
  }

  if(token_load_or_create(state_dir, agent_token)) {
    fprintf(stderr, "cannot load or create the access token in %s\n",
            state_dir);
    return EXIT_FAILURE;
  }

  if((srvfd=platform->listen(platform, port)) < 0) {
    return EXIT_FAILURE;
  }

  // The harness reads the token from standard output. Print it only once
  // the listener is ready, so the line also announces that the port is up.
  printf("token %s\n", agent_token);
  fflush(stdout);

  // Every connection is served by a thread of this process, until the
  // listener fails. The agent outlives the call: a connection may still be
  // running when the listener fails.
  agent.platform = platform;
  agent.token = agent_token;
  agent_server_serve(&agent, srvfd);

  close(srvfd);
  return EXIT_FAILURE;
}
