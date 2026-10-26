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
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "builtins.h"
#include "diagnostics.h"
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


/* The console's uptime, in whole seconds. */
static int
ps5_uptime_seconds(unsigned long long *uptime) {
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
}


/* The console's total and free memory, in bytes. */
static int
ps5_memory(unsigned long long *total, unsigned long long *free_bytes) {
  unsigned long physical;
  unsigned int free_pages;
  size_t size = sizeof(physical);
  long page = sysconf(_SC_PAGE_SIZE);

  if(sysctlbyname("hw.physmem", &physical, &size, NULL, 0)) {
    return -1;
  }
  size = sizeof(free_pages);
  if(sysctlbyname("vm.stats.vm.v_free_count", &free_pages, &size, NULL, 0)) {
    return -1;
  }
  if(page <= 0) {
    return -1;
  }
  *total = (unsigned long long)physical;
  *free_bytes = (unsigned long long)free_pages * (unsigned long long)page;
  return 0;
}


struct ps5_iface {
  unsigned index;
  int addressed;
  interface_row_t row;
};


/* The sockaddrs that follow a routing header, one per RTAX bit, in bit order.
   Returns -1 when they run past end. */
static int
iflist_addrs(unsigned char *at, unsigned char *end, int addrs,
             struct sockaddr *out[RTAX_MAX]) {
  int bit;

  for(bit=0; bit<RTAX_MAX; bit++) {
    out[bit] = NULL;
    if(!(addrs & (1 << bit))) {
      continue;
    }
    if(end - at < 2) {
      return -1;
    }
    out[bit] = (struct sockaddr *)at;
    if(SA_SIZE(at) > (size_t)(end - at)) {
      return -1;
    }
    at += SA_SIZE(at);
  }
  return 0;
}


static int
iflist_name(const struct sockaddr *sa, char *name) {
  const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)sa;

  if(!sdl->sdl_nlen || sdl->sdl_nlen >= INTERFACE_NAME_SIZE ||
     offsetof(struct sockaddr_dl, sdl_data) + sdl->sdl_nlen >
     (size_t)sdl->sdl_len) {
    return -1;
  }
  memcpy(name, sdl->sdl_data, sdl->sdl_nlen);
  name[sdl->sdl_nlen] = '\0';
  return 0;
}


static int
iflist_ipv4(const struct sockaddr *sa, unsigned char *out) {
  if(sa->sa_family != AF_INET || sa->sa_len < 8) {
    return -1;
  }
  memcpy(out, (const unsigned char *)sa + 4, 4);
  return 0;
}


/* A mask is written with its trailing zero bytes left out, so the bytes the
   sockaddr does not reach are zero. */
static void
iflist_mask(const struct sockaddr *sa, unsigned char *out) {
  size_t i;

  memset(out, 0, 4);
  if(!sa) {
    return;
  }
  for(i=0; i<4; i++) {
    if(4 + i < (size_t)sa->sa_len) {
      out[i] = ((const unsigned char *)sa)[4 + i];
    }
  }
}


static int
iflist_next(unsigned char *at, unsigned char *end, size_t *len) {
  const struct ifa_msghdr *hdr = (const struct ifa_msghdr *)at;

  if((size_t)(end - at) < sizeof(*hdr)) {
    return -1;
  }
  *len = hdr->ifam_msglen;
  if(*len < sizeof(*hdr) || *len > (size_t)(end - at)) {
    return -1;
  }
  return 0;
}


/* The interfaces and their IPv4 addresses, from the routing socket's interface
   list: an interface message, then one message per address. An interface with
   no IPv4 address gets one row with no address. */
static int
ps5_interfaces(interface_row_t **rows, size_t *count) {
  int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0};
  struct ps5_iface *slots = NULL;
  unsigned char *buf = NULL;
  unsigned char *end;
  unsigned char *at;
  size_t size = 0;
  size_t cap;
  size_t nslots = 0;
  size_t n = 0;
  size_t len = 0;
  size_t i;
  int rc = -1;

  *rows = NULL;
  if(sysctl(mib, 6, NULL, &size, NULL, 0)) {
    return -1;
  }
  cap = size / sizeof(struct ifa_msghdr) + 1;
  buf = malloc(size ? size : 1);
  slots = calloc(cap, sizeof(*slots));
  *rows = calloc(cap, sizeof(**rows));
  if(!buf || !slots || !*rows || sysctl(mib, 6, buf, &size, NULL, 0)) {
    goto out;
  }

  end = buf + size;
  for(at=buf; at<end; at+=len) {
    struct sockaddr *sa[RTAX_MAX];
    const struct if_msghdr *ifm;
    struct ps5_iface *slot;

    if(iflist_next(at, end, &len)) {
      goto out;
    }
    ifm = (const struct if_msghdr *)at;
    if(ifm->ifm_type != RTM_IFINFO) {
      continue;
    }
    if(len < sizeof(*ifm) || nslots == cap ||
       iflist_addrs(at + sizeof(*ifm), at + len, ifm->ifm_addrs, sa) ||
       !sa[RTAX_IFP]) {
      goto out;
    }
    slot = &slots[nslots++];
    slot->index = ifm->ifm_index;
    slot->row.up = (ifm->ifm_flags & IFF_UP) != 0;
    if(iflist_name(sa[RTAX_IFP], slot->row.name)) {
      goto out;
    }
  }

  for(at=buf; at<end; at+=len) {
    struct sockaddr *sa[RTAX_MAX];
    const struct ifa_msghdr *ifam;
    unsigned char ip[4];
    struct ps5_iface *slot = NULL;
    size_t k;

    if(iflist_next(at, end, &len)) {
      goto out;
    }
    ifam = (const struct ifa_msghdr *)at;
    if(ifam->ifam_type != RTM_NEWADDR) {
      continue;
    }
    if(iflist_addrs(at + sizeof(*ifam), at + len, ifam->ifam_addrs, sa)) {
      goto out;
    }
    if(!sa[RTAX_IFA] || iflist_ipv4(sa[RTAX_IFA], ip)) {
      continue;
    }
    for(k=0; k<nslots; k++) {
      if(slots[k].index == ifam->ifam_index) {
        slot = &slots[k];
        break;
      }
    }
    if(!slot) {
      continue;
    }
    (*rows)[n] = slot->row;
    (*rows)[n].has_address = 1;
    memcpy((*rows)[n].address, ip, sizeof(ip));
    iflist_mask(sa[RTAX_NETMASK], (*rows)[n].mask);
    slot->addressed = 1;
    n++;
  }

  for(i=0; i<nslots; i++) {
    if(!slots[i].addressed) {
      (*rows)[n++] = slots[i].row;
    }
  }

  *count = n;
  rc = 0;

out:
  free(buf);
  free(slots);
  if(rc) {
    free(*rows);
    *rows = NULL;
  }
  return rc;
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
  if(ps5_interfaces(&rows, &count)) {
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }

  diagnostics_say_interfaces(json, outfd, rows, count);
  free(rows);
  *status = 0;
  return 0;
}


/* The kernel log. The console keeps it in kern.msgbuf; when the kernel does
   not expose it, the refusal is named rather than answered as empty. */
static int
run_dmesg(int argc, char *const argv[], int outfd, int errfd, int *status) {
  size_t size = 0;
  char *buf;

  if(argc > 1) {
    if(argv[1][0] == '-') {
      say(errfd, "bad_option\n");
    } else {
      say(errfd, "bad_argument\n");
    }
    *status = 1;
    return 0;
  }

  if(sysctlbyname("kern.msgbuf", NULL, &size, NULL, 0) || !size ||
     !(buf = malloc(size))) {
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }
  if(sysctlbyname("kern.msgbuf", buf, &size, NULL, 0)) {
    free(buf);
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }

  diagnostics_say_log(outfd, buf, size);
  free(buf);
  *status = 0;
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
  if(ps5_uptime_seconds(&uptime) || ps5_memory(&total, &free_bytes)) {
    say(errfd, "not available on this platform\n");
    *status = 1;
    return 0;
  }

  diagnostics_say_sysinfo(json, outfd, name.sysname, name.release,
                          name.machine, uptime, total, free_bytes);
  *status = 0;
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

  if(!strcmp(argv[0], "dmesg")) {
    return run_dmesg(argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "sysinfo")) {
    return run_sysinfo(json, argc, argv, outfd, errfd, status);
  }

  if(!strcmp(argv[0], "ifconfig")) {
    return run_ifconfig(json, argc, argv, outfd, errfd, status);
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
