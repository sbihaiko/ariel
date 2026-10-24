/* Ariel: the platform readers of the PS5 build.

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
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "builtins.h"
#include "elfldr.h"
#include "json.h"
#include "readers.h"

extern unsigned char sh_elf[];


#define PS_HEADER "PID PPID PGID SID UID STATE COMMAND\n"
#define PS_STATES 8


static const char *state_names[PS_STATES] = {
  "", "START", "RUN", "SLEEP", "STOP", "ZOMB", "WAIT", "LOCK"
};


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


static void
say_failure(int errfd, const char *command, const char *operand, int err) {
  say(errfd, command);
  say(errfd, ": ");
  say(errfd, operand);
  say(errfd, ": ");
  say(errfd, strerror(err));
  say(errfd, "\n");
}


static int
parse_pid(const char *text, long *pid) {
  char *end;

  if(!isdigit((unsigned char)text[0])) {
    return -1;
  }
  errno = 0;
  *pid = strtol(text, &end, 10);
  if(*end || errno || *pid > 0x7fffffff) {
    return -1;
  }
  return 0;
}


/* Print the processes whose pid is only, or all of them when only is negative,
   as text or as JSON objects. Sets found to the number printed. */
static int
print_procs(int json, int outfd, int errfd, long only, int *found) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  char *buf;
  char *end;
  char *p;
  size_t size = 0;
  char line[256];

  *found = 0;

  if(sysctl(mib, 4, NULL, &size, NULL, 0)) {
    say_failure(errfd, "ps", "kern.proc.proc", errno);
    return 1;
  }
  if(!(buf = malloc(size ? size : 1))) {
    say(errfd, "ps: out of memory\n");
    return 1;
  }
  if(sysctl(mib, 4, buf, &size, NULL, 0)) {
    say_failure(errfd, "ps", "kern.proc.proc", errno);
    free(buf);
    return 1;
  }

  end = buf + size;
  for(p=buf; p<end; ) {
    struct kinfo_proc *ki = (struct kinfo_proc *)p;
    size_t step = (size_t)ki->ki_structsize;
    const char *state;

    if(step == 0 || step > (size_t)(end - p)) {
      break;
    }
    p += step;

    if(only >= 0 && ki->ki_pid != only) {
      continue;
    }

    state = (ki->ki_stat >= 0 && ki->ki_stat < PS_STATES) ?
            state_names[(int)ki->ki_stat] : "?";
    if(json) {
      snprintf(line, sizeof(line),
               "{\"pid\":%d,\"ppid\":%d,\"pgid\":%d,\"sid\":%d,\"uid\":%u,"
               "\"state\":\"%s\",\"command\":",
               ki->ki_pid, ki->ki_ppid, ki->ki_pgid, ki->ki_sid,
               (unsigned)ki->ki_uid, state);
      say(outfd, line);
      json_say_string(outfd, ki->ki_comm);
      say(outfd, "}\n");
    } else {
      snprintf(line, sizeof(line), "%d %d %d %d %u %s %s\n",
               ki->ki_pid, ki->ki_ppid, ki->ki_pgid, ki->ki_sid,
               (unsigned)ki->ki_uid, state, ki->ki_comm);
      say(outfd, line);
    }
    (*found)++;
  }

  free(buf);
  return 0;
}


static int
run_ps(int json, int outfd, int errfd, int *status) {
  int found;

  if(!json) {
    say(outfd, PS_HEADER);
  }
  *status = print_procs(json, outfd, errfd, -1, &found);
  return 0;
}


static int
run_procstat(int argc, char *const argv[], int outfd, int errfd, int *status) {
  long pid;
  int found;

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

  say(outfd, PS_HEADER);
  if(print_procs(0, outfd, errfd, pid, &found)) {
    *status = 1;
  } else if(!found) {
    say(errfd, "no_such_process\n");
    *status = 1;
  } else {
    *status = 0;
  }
  return 0;
}


static void
hexdump(int fd, const unsigned char *data, size_t size) {
  char line[128];
  size_t i;
  size_t j;

  for(i=0; i<size; i+=16) {
    size_t n = size - i < 16 ? size - i : 16;
    int len = snprintf(line, sizeof(line), "%08x  ", (unsigned)i);

    for(j=0; j<16; j++) {
      if(j < n) {
        len += snprintf(line + len, sizeof(line) - len, "%02x ", data[i+j]);
      } else {
        len += snprintf(line + len, sizeof(line) - len, "   ");
      }
    }

    len += snprintf(line + len, sizeof(line) - len, "| ");
    for(j=0; j<n; j++) {
      unsigned char c = data[i+j];

      if(isblank(c)) {
        line[len++] = ' ';
      } else if(!isprint(c)) {
        line[len++] = '.';
      } else {
        line[len++] = (char)c;
      }
    }
    line[len++] = '\n';
    line[len] = '\0';
    say(fd, line);
  }
}


static int
run_sysctl(int argc, char *const argv[], int outfd, int errfd, int *status) {
  unsigned char *buf;
  size_t size = 0;

  if(argc < 2) {
    say(errfd, "missing_operand\n");
    *status = 1;
    return 0;
  }
  if(strchr(argv[1], '=')) {
    return -1;
  }

  if(sysctlbyname(argv[1], NULL, &size, NULL, 0)) {
    say_failure(errfd, "sysctl", argv[1], errno);
    *status = 1;
    return 0;
  }
  if(!(buf = malloc(size ? size : 1))) {
    say(errfd, "sysctl: out of memory\n");
    *status = 1;
    return 0;
  }
  if(sysctlbyname(argv[1], buf, &size, NULL, 0)) {
    say_failure(errfd, "sysctl", argv[1], errno);
    free(buf);
    *status = 1;
    return 0;
  }

  hexdump(outfd, buf, size);
  free(buf);
  *status = 0;
  return 0;
}


static int
run_authid(int outfd, int *status) {
  uint64_t authid = kernel_get_ucred_authid(getpid());
  char line[32];

  snprintf(line, sizeof(line), "0x%llx\n", (unsigned long long)authid);
  say(outfd, line);
  *status = authid ? 0 : 1;
  return 0;
}


/** A gated built-in runs in its own shell, once, as sh.elf --run NAME ARGS. **/
static int
run_builtin(int argc, char *const argv[], int outfd, int errfd, int *status) {
  char **child;
  pid_t pid;
  int st = 0;
  int i;

  child = calloc((size_t)argc + 3, sizeof(*child));
  if(!child) {
    return -1;
  }
  child[0] = "sh.elf";
  child[1] = "--run";
  for(i=0; i<argc; i++) {
    child[i + 2] = argv[i];
  }

  pid = elfldr_spawn(-1, outfd, errfd, sh_elf, child);
  free(child);
  if(pid < 0 || waitpid(pid, &st, 0) < 0) {
    return -1;
  }

  *status = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
  return 0;
}


int
readers_run(int json, int argc, char *const argv[], int outfd, int errfd,
             int *status) {
  if(argc < 1) {
    return -1;
  }

  if(argc == 1 && !strcmp(argv[0], "ps")) {
    return run_ps(json, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "procstat")) {
    return run_procstat(argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "sysctl")) {
    return run_sysctl(argc, argv, outfd, errfd, status);
  }

  if(argc == 1 && !strcmp(argv[0], "authid")) {
    return run_authid(outfd, status);
  }

  if(builtin_gated(argv[0])) {
    return run_builtin(argc, argv, outfd, errfd, status);
  }

  return -1;
}
