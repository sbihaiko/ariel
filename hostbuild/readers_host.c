/* Ariel: the platform readers of the host build.

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
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "builtins.h"
#include "readers.h"

extern char **environ;

#define PS_HEADER "PID PPID PGID SID UID STATE COMMAND\n"
#define PS_FORMAT "pid=,ppid=,pgid=,sess=,uid=,stat=,comm="


static void
say_bytes(int fd, const void *data, size_t len) {
  const char *text = data;

  while(len > 0) {
    ssize_t n = write(fd, text, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return;
    }
    text += n;
    len -= (size_t)n;
  }
}


static void
say(int fd, const char *text) {
  say_bytes(fd, text, strlen(text));
}


/* Run a host tool and copy its standard output to outfd. Returns its exit
   status, or 1 when it cannot run. */
static int
capture(const char *file, char *const argv[], int outfd, int errfd) {
  posix_spawn_file_actions_t actions;
  char buf[4096];
  int fds[2];
  int status = 1;
  pid_t pid;
  ssize_t n;
  int rc;

  if(pipe(fds)) {
    return 1;
  }

  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, fds[1], 1);
  posix_spawn_file_actions_adddup2(&actions, errfd, 2);
  posix_spawn_file_actions_addclose(&actions, fds[0]);
  rc = posix_spawnp(&pid, file, &actions, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&actions);
  close(fds[1]);

  if(rc) {
    close(fds[0]);
    return 1;
  }

  while((n = read(fds[0], buf, sizeof(buf))) != 0) {
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      break;
    }
    say_bytes(outfd, buf, (size_t)n);
  }
  close(fds[0]);

  while(waitpid(pid, &status, 0) < 0) {
    if(errno != EINTR) {
      return 1;
    }
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}


static int
parse_pid(const char *text, pid_t *pid) {
  char *end;
  long value;

  if(!isdigit((unsigned char)text[0])) {
    return -1;
  }
  errno = 0;
  value = strtol(text, &end, 10);
  if(*end || errno || value > 0x7fffffff) {
    return -1;
  }
  *pid = (pid_t)value;
  return 0;
}


static int
run_ps(int outfd, int errfd, int *status) {
  char *const argv[] = {"ps", "-axo", PS_FORMAT, NULL};

  say(outfd, PS_HEADER);
  *status = capture("ps", argv, outfd, errfd);
  return 0;
}


static int
run_procstat(int argc, char *const argv[], int outfd, int errfd, int *status) {
  char pid_text[16];
  pid_t pid;

  if(argc < 2) {
    say(errfd, "missing_operand\n");
    *status = 1;
    return 0;
  }
  if(parse_pid(argv[1], &pid)) {
    say(errfd, "not_a_pid\n");
    *status = 1;
    return 0;
  }
  if(kill(pid, 0) && errno == ESRCH) {
    say(errfd, "no_such_process\n");
    *status = 1;
    return 0;
  }

  snprintf(pid_text, sizeof(pid_text), "%ld", (long)pid);
  {
    char *const ps_argv[] = {"ps", "-p", pid_text, "-o", PS_FORMAT, NULL};

    say(outfd, PS_HEADER);
    *status = capture("ps", ps_argv, outfd, errfd);
  }
  return 0;
}


static int
run_sysctl(int argc, char *const argv[], int outfd, int errfd, int *status) {
  if(argc < 2) {
    say(errfd, "missing_operand\n");
    *status = 1;
    return 0;
  }
  if(strchr(argv[1], '=')) {
    return -1;
  }

  {
    char *const sysctl_argv[] = {"sysctl", "-n", argv[1], NULL};

    *status = capture("sysctl", sysctl_argv, outfd, errfd);
  }
  return 0;
}


int
readers_run(int argc, char *const argv[], int outfd, int errfd, int *status) {
  if(argc < 1) {
    return -1;
  }

  if(argc == 1 && !strcmp(argv[0], "ps")) {
    return run_ps(outfd, errfd, status);
  }

  if(!strcmp(argv[0], "procstat")) {
    return run_procstat(argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "sysctl")) {
    return run_sysctl(argc, argv, outfd, errfd, status);
  }

  if((argc == 1 && !strcmp(argv[0], "authid")) || builtin_gated(argv[0])) {
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }

  return -1;
}
