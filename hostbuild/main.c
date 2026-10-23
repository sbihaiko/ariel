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
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "agent.h"
#include "platform.h"
#include "store.h"
#include "token.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_PORT 2324

/** At most this many agent connections are served at once. **/
#define CONNECTION_MAX 4

/** At most this many refused connections are answered at once. **/
#define REFUSED_MAX 4

/** Past every refusal slot, at most this many closes wait for one drain. **/
#define DRAIN_MAX 16


struct connection {
  agent_t *agent;
  int fd;
  int wake;
};

static char agent_token[TOKEN_LEN];

/** Served connections, under one mutex: a fifth is refused, not queued. **/
static pthread_mutex_t connection_lock = PTHREAD_MUTEX_INITIALIZER;
static int connection_count;
static int refused_count;

/** Refusals past every slot, closed one at a time by a single drain thread. **/
static int drain_fds[DRAIN_MAX];
static int drain_count;
static int drain_running;


/** Take a serving slot. Returns 1 when the slot was free. **/
static int
connection_take(void) {
  int taken = 0;

  pthread_mutex_lock(&connection_lock);
  if(connection_count < CONNECTION_MAX) {
    connection_count++;
    taken = 1;
  }
  pthread_mutex_unlock(&connection_lock);

  return taken;
}


static void
connection_drop(void) {
  pthread_mutex_lock(&connection_lock);
  connection_count--;
  pthread_mutex_unlock(&connection_lock);
}


/** Take a refusal slot. Returns 1 when the slot was free. **/
static int
refused_take(void) {
  int taken = 0;

  pthread_mutex_lock(&connection_lock);
  if(refused_count < REFUSED_MAX) {
    refused_count++;
    taken = 1;
  }
  pthread_mutex_unlock(&connection_lock);

  return taken;
}


static void
refused_drop(void) {
  pthread_mutex_lock(&connection_lock);
  refused_count--;
  pthread_mutex_unlock(&connection_lock);
}


static int
write_all(int fd, const char *buf, size_t len) {
  while(len > 0) {
    ssize_t n = write(fd, buf, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    buf += n;
    len -= (size_t)n;
  }
  return 0;
}


/**
 * Answer busy and close. It is the same close as every other reply: the
 * client may already have sent its auth line. It runs off the accept loop,
 * so a refused client cannot hold up the next accept.
 **/
static void *
refuse_busy(void *arg) {
  static const char busy[] = "busy\nexit 82\n";
  struct connection *conn = arg;
  platform_t *platform = conn->agent->platform;

  write_all(conn->fd, busy, sizeof(busy) - 1);
  agent_close(platform, conn->fd, conn->wake);
  refused_drop();
  if(conn->wake >= 0 && platform->wake_close) {
    platform->wake_close(platform, conn->wake);
  }
  free(conn);

  return NULL;
}


/**
 * Answer busy from the accept loop without waiting: the reply is far
 * smaller than a fresh socket's send buffer, so one nonblocking write
 * either sends it whole or the client is not reading and gets nothing.
 **/
static void
busy_inline(int fd) {
  static const char busy[] = "busy\nexit 82\n";
  int flags = fcntl(fd, F_GETFL);

  if(flags >= 0 && !fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
    ssize_t n = write(fd, busy, sizeof(busy) - 1);

    (void)n;
    fcntl(fd, F_SETFL, flags);
  }
}


/**
 * Close the refusals past every slot, one after another, each with the
 * same drain as any other close, so the client sees EOF and not a reset.
 * The thread ends when the queue is empty.
 **/
static void *
drain_refused(void *arg) {
  platform_t *platform = arg;
  int wake = platform->wake_new ? platform->wake_new(platform) : -1;
  int fd;

  for(;;) {
    pthread_mutex_lock(&connection_lock);
    if(!drain_count) {
      drain_running = 0;
      pthread_mutex_unlock(&connection_lock);
      break;
    }
    fd = drain_fds[0];
    memmove(drain_fds, drain_fds + 1, (size_t)(drain_count - 1) * sizeof(int));
    drain_count--;
    pthread_mutex_unlock(&connection_lock);

    agent_close(platform, fd, wake);
  }

  if(wake >= 0 && platform->wake_close) {
    platform->wake_close(platform, wake);
  }

  return NULL;
}


/**
 * Answer busy without a refusal slot, then hand the close to the drain
 * thread. Only when the drain queue is full, or no drain thread can start,
 * is the socket closed at once.
 **/
static void
refuse_inline(platform_t *platform, int fd) {
  pthread_t thread;
  int queued = 0;
  int start = 0;

  busy_inline(fd);

  pthread_mutex_lock(&connection_lock);
  if(drain_count < DRAIN_MAX) {
    drain_fds[drain_count++] = fd;
    queued = 1;
    if(!drain_running) {
      drain_running = 1;
      start = 1;
    }
  }
  pthread_mutex_unlock(&connection_lock);

  if(start) {
    if(pthread_create(&thread, NULL, drain_refused, platform)) {
      pthread_mutex_lock(&connection_lock);
      drain_running = 0;
      drain_count--;
      pthread_mutex_unlock(&connection_lock);
      queued = 0;
    } else {
      pthread_detach(thread);
    }
  }

  if(!queued) {
    shutdown(fd, SHUT_WR);
    close(fd);
  }
}


/**
 * Hand a connection past the limit to a thread of its own. Past
 * REFUSED_MAX refusals at once, or when no thread can start, it is
 * answered inline and closed.
 **/
static void
refuse(agent_t *agent, int fd) {
  platform_t *platform = agent->platform;
  struct connection *conn;
  pthread_t thread;

  if(!refused_take()) {
    refuse_inline(platform, fd);
    return;
  }

  if(!(conn=malloc(sizeof(*conn)))) {
    refuse_inline(platform, fd);
    refused_drop();
    return;
  }

  conn->agent = agent;
  conn->fd = fd;
  conn->wake = platform->wake_new ? platform->wake_new(platform) : -1;

  if(pthread_create(&thread, NULL, refuse_busy, conn)) {
    refuse_inline(platform, fd);
    if(conn->wake >= 0 && platform->wake_close) {
      platform->wake_close(platform, conn->wake);
    }
    free(conn);
    refused_drop();
    return;
  }

  pthread_detach(thread);
}


static int
ensure_dir(const char *path) {
  if(mkdir(path, 0700) && errno != EEXIST) {
    perror(path);
    return -1;
  }
  return 0;
}


static void *
serve_connection(void *arg) {
  struct connection *conn = arg;
  int fd = conn->fd;
  int wake = conn->wake;

  agent_serve(conn->agent, fd, wake);
  agent_close(conn->agent->platform, fd, wake);

  // The slot goes before the wake pipe, so a test clock that sees no pipe
  // left also sees every slot free.
  connection_drop();
  if(wake >= 0 && conn->agent->platform->wake_close) {
    conn->agent->platform->wake_close(conn->agent->platform, wake);
  }
  free(conn);

  return NULL;
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
  platform_t *platform;
  agent_t agent;
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

  platform = platform_host(run_dir);

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

  agent.platform = platform;
  agent.token = agent_token;

  // The harness reads the token from standard output. Print it only once
  // the listener is ready, so the line also announces that the port is up.
  printf("token %s\n", agent_token);
  fflush(stdout);

  while(1) {
    struct connection *conn;
    pthread_t thread;
    int connfd;
    int rc;

    if((connfd=platform->accept(platform, srvfd)) < 0) {
      perror("accept");
      close(srvfd);
      return EXIT_FAILURE;
    }

    if(!connection_take()) {
      refuse(&agent, connfd);
      continue;
    }

    if(!(conn=malloc(sizeof(*conn)))) {
      perror("malloc");
      close(connfd);
      connection_drop();
      continue;
    }

    conn->agent = &agent;
    conn->fd = connfd;
    conn->wake = platform->wake_new ? platform->wake_new(platform) : -1;

    rc = pthread_create(&thread, NULL, serve_connection, conn);
    if(rc) {
      fprintf(stderr, "pthread_create: %s\n", strerror(rc));
      close(connfd);
      if(conn->wake >= 0 && platform->wake_close) {
        platform->wake_close(platform, conn->wake);
      }
      free(conn);
      connection_drop();
      continue;
    }

    pthread_detach(thread);
  }
}
