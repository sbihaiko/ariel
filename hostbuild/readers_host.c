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

/* The uptime figures need the BSD and sysconf names the strict POSIX level
   hides: kern.boottime on the Mac, the free page count on Linux. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#else
#define _DEFAULT_SOURCE 1
#endif

#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#endif

#include "builtins.h"
#include "diagnostics.h"
#include "json.h"
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


/* Start a host tool with its standard output on a pipe. Returns its pid and
   sets readfd to the pipe, or -1 when it cannot run. */
static pid_t
spawn_tool(const char *file, char *const argv[], int errfd, int *readfd) {
  posix_spawn_file_actions_t actions;
  int fds[2];
  pid_t pid;
  int rc;

  if(pipe(fds)) {
    return -1;
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
    return -1;
  }
  *readfd = fds[0];
  return pid;
}


/* Wait for a host tool. Returns its exit status, or 1 when it did not exit. */
static int
reap(pid_t pid) {
  int status = 1;

  while(waitpid(pid, &status, 0) < 0) {
    if(errno != EINTR) {
      return 1;
    }
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}


/* Run a host tool and copy its standard output to outfd. Returns its exit
   status, or 1 when it cannot run. */
static int
capture(const char *file, char *const argv[], int outfd, int errfd) {
  char buf[4096];
  ssize_t n;
  int fd;
  pid_t pid = spawn_tool(file, argv, errfd, &fd);

  if(pid < 0) {
    return 1;
  }

  while((n = read(fd, buf, sizeof(buf))) != 0) {
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      break;
    }
    say_bytes(outfd, buf, (size_t)n);
  }
  close(fd);
  return reap(pid);
}


/* Write one line of host ps output as a JSON object. Returns 0 when the line
   has the fields of PS_FORMAT, or -1 when it does not. */
static int
say_ps_object(int outfd, char *line) {
  char head[128];
  char state[16];
  int pid;
  int ppid;
  int pgid;
  int sid;
  unsigned uid;
  int used = 0;

  if(sscanf(line, " %d %d %d %d %u %15s %n", &pid, &ppid, &pgid, &sid, &uid,
            state, &used) != 6) {
    return -1;
  }
  line[used + strcspn(line + used, "\n")] = '\0';

  snprintf(head, sizeof(head),
           "{\"pid\":%d,\"ppid\":%d,\"pgid\":%d,\"sid\":%d,\"uid\":%u,"
           "\"state\":",
           pid, ppid, pgid, sid, uid);
  say(outfd, head);
  json_say_string(outfd, state);
  say(outfd, ",\"command\":");
  json_say_string(outfd, line + used);
  say(outfd, "}\n");
  return 0;
}


static int
capture_ps_objects(char *const argv[], int outfd, int errfd) {
  char *line = NULL;
  size_t cap = 0;
  int failed = 0;
  ssize_t len;
  int fd;
  FILE *in;
  pid_t pid = spawn_tool("ps", argv, errfd, &fd);

  if(pid < 0) {
    return 1;
  }
  if(!(in = fdopen(fd, "r"))) {
    close(fd);
    reap(pid);
    return 1;
  }

  while((len = getline(&line, &cap, in)) >= 0) {
    if(say_ps_object(outfd, line)) {
      failed = 1;
    }
  }
  free(line);
  fclose(in);

  if(reap(pid) || failed) {
    say(errfd, "operation_failed\n");
    return 1;
  }
  return 0;
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
run_ps(int json, int outfd, int errfd, int *status) {
  char *const argv[] = {"ps", "-axo", PS_FORMAT, NULL};

  if(json) {
    *status = capture_ps_objects(argv, outfd, errfd);
    return 0;
  }
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


/* The host has no kernel log an unprivileged process may read, so dmesg
   names the refusal instead of answering an empty success. */
static int
run_dmesg(int argc, char *const argv[], int outfd, int errfd, int *status) {
  (void)outfd;

  if(argc > 1) {
    if(argv[1][0] == '-') {
      say(errfd, "bad_option\n");
    } else {
      say(errfd, "bad_argument\n");
    }
    *status = 1;
    return 0;
  }

  say(errfd, "not available on this platform\n");
  *status = 1;
  return 0;
}


/* The host's uptime, in whole seconds. */
static int
host_uptime_seconds(unsigned long long *uptime) {
#if defined(__APPLE__)
  struct timeval boot;
  size_t size = sizeof(boot);
  time_t now;

  if(sysctlbyname("kern.boottime", &boot, &size, NULL, 0)) {
    return -1;
  }
  if((now = time(NULL)) == (time_t)-1 || now < boot.tv_sec) {
    return -1;
  }
  *uptime = (unsigned long long)(now - boot.tv_sec);
  return 0;
#else
  double seconds;
  FILE *file;

  if(!(file = fopen("/proc/uptime", "r"))) {
    return -1;
  }
  if(fscanf(file, "%lf", &seconds) != 1 || seconds < 0) {
    fclose(file);
    return -1;
  }
  fclose(file);
  *uptime = (unsigned long long)seconds;
  return 0;
#endif
}


/* The host's total and free memory, in bytes. */
static int
host_memory(unsigned long long *total, unsigned long long *free_bytes) {
  long pages = sysconf(_SC_PHYS_PAGES);
  long size = sysconf(_SC_PAGE_SIZE);

  if(pages <= 0 || size <= 0) {
    return -1;
  }
  *total = (unsigned long long)pages * (unsigned long long)size;

#if defined(__APPLE__)
  {
    vm_statistics64_data_t stats;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;

    if(host_statistics64(mach_host_self(), HOST_VM_INFO64,
                         (host_info64_t)&stats, &count) != KERN_SUCCESS) {
      return -1;
    }
    *free_bytes = ((unsigned long long)stats.free_count +
                   (unsigned long long)stats.speculative_count) *
                  (unsigned long long)size;
  }
#else
  {
    long available = sysconf(_SC_AVPHYS_PAGES);

    if(available < 0) {
      return -1;
    }
    *free_bytes = (unsigned long long)available * (unsigned long long)size;
  }
#endif
  return 0;
}


static int
run_sysinfo(int json, int argc, char *const argv[], int outfd, int errfd,
            int *status) {
  unsigned long long total;
  unsigned long long free_bytes;
  unsigned long long uptime;
  struct utsname name;

  if(argc > 1) {
    if(argv[1][0] == '-') {
      say(errfd, "bad_option\n");
    } else {
      say(errfd, "bad_argument\n");
    }
    *status = 1;
    return 0;
  }
  if(uname(&name)) {
    say(errfd, "operation_failed\n");
    *status = 1;
    return 0;
  }
  if(host_uptime_seconds(&uptime) || host_memory(&total, &free_bytes)) {
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }

  diagnostics_say_sysinfo(json, outfd, name.sysname, name.release,
                          name.machine, uptime, total, free_bytes);
  *status = 0;
  return 0;
}


/* The host's interfaces and their IPv4 addresses. Each IPv4 address is a row;
   an interface with no IPv4 address gets one row with no address. */
static int
host_interfaces(interface_row_t **rows, size_t *count) {
  struct ifaddrs *list;
  struct ifaddrs *ifa;
  size_t entries = 0;
  size_t n = 0;

  if(getifaddrs(&list)) {
    return -1;
  }
  for(ifa=list; ifa; ifa=ifa->ifa_next) {
    entries++;
  }
  *rows = calloc(entries ? entries : 1, sizeof(**rows));
  if(!*rows) {
    freeifaddrs(list);
    return -1;
  }

  for(ifa=list; ifa; ifa=ifa->ifa_next) {
    interface_row_t *row = &(*rows)[n];
    struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;

    if(!addr || addr->sin_family != AF_INET) {
      continue;
    }
    snprintf(row->name, sizeof(row->name), "%s", ifa->ifa_name);
    row->up = (ifa->ifa_flags & IFF_UP) != 0;
    row->has_address = 1;
    memcpy(row->address, &addr->sin_addr, sizeof(row->address));
    if(ifa->ifa_netmask) {
      struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

      memcpy(row->mask, &mask->sin_addr, sizeof(row->mask));
    }
    n++;
  }

  for(ifa=list; ifa; ifa=ifa->ifa_next) {
    struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
    interface_row_t *row;
    int known = 0;
    size_t i;

    if(addr && addr->sin_family == AF_INET) {
      continue;
    }
    for(i=0; i<n; i++) {
      if(!strcmp((*rows)[i].name, ifa->ifa_name)) {
        known = 1;
        break;
      }
    }
    if(known) {
      continue;
    }
    row = &(*rows)[n++];
    snprintf(row->name, sizeof(row->name), "%s", ifa->ifa_name);
    row->up = (ifa->ifa_flags & IFF_UP) != 0;
  }

  freeifaddrs(list);
  *count = n;
  return 0;
}


static int
run_ifconfig(int json, int argc, char *const argv[], int outfd, int errfd,
             int *status) {
  interface_row_t *rows;
  size_t count;

  if(argc > 1) {
    if(argv[1][0] == '-') {
      say(errfd, "bad_option\n");
    } else {
      say(errfd, "bad_argument\n");
    }
    *status = 1;
    return 0;
  }
  if(host_interfaces(&rows, &count)) {
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }

  diagnostics_say_interfaces(json, outfd, rows, count);
  free(rows);
  *status = 0;
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

  if(!strcmp(argv[0], "dmesg")) {
    return run_dmesg(argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "sysinfo")) {
    return run_sysinfo(json, argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "ifconfig")) {
    return run_ifconfig(json, argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "ping")) {
    diagnostics_run_ping(argc, argv, outfd, errfd, status);
    return 0;
  }

  if(!strcmp(argv[0], "procstat")) {
    return run_procstat(argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "sysctl")) {
    return run_sysctl(argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "pkg_install")) {
    // The host has no installer. The console's call returns once the
    // install is accepted, so the virtual platform does the same and
    // installs nothing: whether the app directory appeared is what the
    // test root holds, and the agent reads that itself.
    *status = 0;
    return 0;
  }

  if((argc == 1 && !strcmp(argv[0], "authid")) || builtin_gated(argv[0])) {
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }

  return -1;
}
