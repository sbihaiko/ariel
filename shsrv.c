/* Copyright (C) 2024 John Törnblom

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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "agent_server.h"
#include "elfldr.h"
#include "notify.h"
#include "platform.h"
#include "platform_ps5.h"
#include "sh.elf.inc"
#include "store.h"
#include "token.h"

/** The telnet shell keeps its port and its behavior. **/
#define TELNET_PORT 2323

/** The raw agent port next to it. **/
#define AGENT_PORT  2324

/** Ariel's state: the token, the store and staging. **/
#define STATE_DIR   "/data/ariel"

/** The agent access token, loaded or created at start. **/
static char agent_token[TOKEN_LEN];


/**
 * Reap one telnet shell process. SIGCHLD is no longer ignored, so an
 * exited child stays a zombie until someone waits for it. Each child is
 * waited for by its own thread and never by waitpid(-1): a wildcard wait
 * would also take the exit status of a payload that `payload run --wait`
 * is waiting for.
 **/
static void *
reap_shell(void *arg) {
  pid_t pid = (pid_t)(intptr_t)arg;
  int status;

  while(waitpid(pid, &status, 0) < 0) {
    if(errno != EINTR) {
      break;
    }
  }

  return NULL;
}


static void
reap_later(pid_t pid) {
  pthread_t thread;
  int status;

  if(pid <= 0) {
    return;
  }

  if(!pthread_create(&thread, NULL, reap_shell, (void*)(intptr_t)pid)) {
    pthread_detach(thread);
    return;
  }

  // No thread can wait for this child, and SIGCHLD is no longer ignored.
  // Wait here rather than leave a zombie. The shell is already spawned, so
  // this only holds back the next accept until it exits.
  klog_perror("pthread_create");
  while(waitpid(pid, &status, 0) < 0) {
    if(errno != EINTR) {
      break;
    }
  }
}


/**
 * Serve the agent port from a thread of this process, next to the telnet
 * shell. Auth, staging and approvals live in this process's memory under
 * the store's mutexes.
 **/
static void *
serve_agent(void *arg) {
  platform_t *platform = arg;
  int notified = 0;
  int srvfd;

  while(1) {
    if((srvfd=platform->listen(platform, AGENT_PORT)) < 0) {
      klog_printf("cannot listen on the agent port %d\n", AGENT_PORT);
      if(!notified) {
        notify("Ariel: cannot serve the agent port %d", AGENT_PORT);
        notified = 1;
      }
      sleep(3);
      continue;
    }

    klog_printf("Serving the agent port on %d\n", AGENT_PORT);
    agent_server_serve(platform, agent_token, srvfd);
    close(srvfd);
    sleep(3);
  }

  return NULL;
}


/**
 * Serve access to sh.elf.
 **/
static int
serve_sh(uint16_t port, int notify_user) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;

  char ip[INET_ADDRSTRLEN];
  char* argv[] = {"sh", 0};
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t addr_len;
  int optval;
  int connfd;
  int srvfd;
  pid_t pid;

  if(getifaddrs(&ifaddr) == -1) {
    klog_perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
    ifaddr_wait = 0;
    if(notify_user) {
      notify("Serving shell on %s:%d (%s)", ip, port, ifa->ifa_name);
    }
    klog_printf("Serving shell on %s:%d (%s)\n", ip, port, ifa->ifa_name);
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    klog_perror("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    klog_perror("setsockopt");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    klog_perror("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    klog_perror("listen");
    return -1;
  }

  while(1) {
    addr_len = sizeof(client_addr);
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      klog_perror("accept");
      break;
    }

    optval = 1;
    if(setsockopt(connfd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval,
		  sizeof (optval))) {
      klog_perror("setsockopt");
      break;
    }

    optval = 1;
    if(setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, (char *)&optval,
		  sizeof (optval))) {
      klog_perror("setsockopt");
      break;
    }

    // The shell is a spawn through the same ELF loader as a payload run,
    // so it takes the loader's lock; the wait is not under it. The shell
    // is not waited for here: its own thread reaps it.
    platform_ps5_loader_lock();
    pid = elfldr_spawn(connfd, connfd, -1, sh_elf, argv);
    platform_ps5_loader_unlock();
    reap_later(pid);
    close(connfd);
  }

  return close(srvfd);
}


/**
 * Get the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    klog_perror("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    klog_perror("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    klog_perror("sysctl");
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && mypid != ki_pid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


/**
 * Initialize stdio to /dev/console
 **/
static void
init_stdio(void) {
  int fd = open("/dev/console", O_RDWR);

  close(STDERR_FILENO);
  close(STDOUT_FILENO);
  close(STDIN_FILENO);

  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);

  close(fd);
}


static int
ensure_dir(const char *path) {
  if(mkdir(path, 0700) && errno != EEXIST) {
    klog_perror(path);
    return -1;
  }
  return 0;
}


/**
 * Launch shsrv.elf.
 **/
int
main(void) {
  int notify_user = 1;
  platform_t *platform;
  pthread_t agent;
  pid_t pid;

  syscall(SYS_thr_set_name, -1, "shsrv.elf");
  init_stdio();

  klog_printf("Shell server was compiled at %s %s\n", __DATE__, __TIME__);

  while((pid=find_pid("shsrv.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      klog_perror("kill");
    }
    sleep(1);
  }

  signal(SIGPIPE, SIG_IGN);

  // SIGCHLD keeps its default handling: a payload run with --wait needs
  // its exit status, and the telnet shell's processes are reaped by
  // threads of their own.
  signal(SIGCHLD, SIG_DFL);

  if(ensure_dir(STATE_DIR) || ensure_dir(STATE_DIR "/staging")) {
    notify("Ariel: cannot prepare %s", STATE_DIR);
    return EXIT_FAILURE;
  }

  if(token_load_or_create(STATE_DIR, agent_token)) {
    notify("Ariel: cannot load or create the access token in %s", STATE_DIR);
    return EXIT_FAILURE;
  }

  platform = platform_ps5(agent_token);

  if(store_init(STATE_DIR, platform)) {
    notify("Ariel: cannot prepare the store in %s", STATE_DIR);
    return EXIT_FAILURE;
  }

  // The token is shown at start and with every approval prompt, so the
  // owner can always hand it to the agent.
  notify("Ariel agent port %d\ntoken %s", AGENT_PORT, agent_token);

  if(pthread_create(&agent, NULL, serve_agent, platform)) {
    klog_perror("pthread_create");
    notify("Ariel: cannot start the agent port %d", AGENT_PORT);
  } else {
    pthread_detach(agent);
  }

  while(1) {
    serve_sh(TELNET_PORT, notify_user);
    notify_user = 0;
    sleep(3);
  }

  return 0;
}
