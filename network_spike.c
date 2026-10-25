/* Copyright (C) 2026 the ariel contributors

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

/**
 * Network spike payload (issue #112).
 *
 * Answers whether three network facts can be read at all on this console, in
 * order from the least to the most risky: the interface list, the socket
 * tables, and one ICMP echo round-trip to the loopback address. The selector
 * in /data/network-spike.select runs one probe alone (interfaces, sockets or
 * echo) or all three (all, which is also the default when the file is absent).
 *
 * Each step appends what it is about to do to /data/network-spike.log before
 * the step, and what it read back after it, flushed to disk each time, so a
 * step that freezes the console is the last intent in the log. It changes no
 * product code and is never linked into ariel-ps5.elf.
 **/

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "notify.h"


#define SPIKE_LOG          "/data/network-spike.log"
#define SPIKE_SELECT       "/data/network-spike.select"
#define SPIKE_TCP_TABLE    "net.inet.tcp.pcblist"
#define SPIKE_UDP_TABLE    "net.inet.udp.pcblist"
#define SPIKE_WAIT_MS      2000
#define SPIKE_TRIES        8
#define SPIKE_PAYLOAD_LEN  8
#define SPIKE_IP_MIN       20

enum spike_probe {
  PROBE_INTERFACES,
  PROBE_SOCKETS,
  PROBE_ECHO,
  PROBE_COUNT
};

static const char *probe_names[PROBE_COUNT] = {
  "interfaces", "sockets", "echo",
};

/** One ICMP echo request: the eight-byte header of RFC 792, then a fixed
    payload. Multi-byte fields are held in network order. **/
typedef struct echo_packet {
  uint8_t  type;
  uint8_t  code;
  uint16_t checksum;
  uint16_t id;
  uint16_t seq;
  uint8_t  payload[SPIKE_PAYLOAD_LEN];
} echo_packet_t;


static int logfd = -1;


static void
log_line(const char *fmt, ...) {
  char    line[512];
  va_list ap;
  int     n;
  time_t  now;
  struct tm tm;

  if(logfd < 0) {
    return;
  }

  now = time(0);
  localtime_r(&now, &tm);
  n = snprintf(line, sizeof(line), "%02d:%02d:%02d ", tm.tm_hour, tm.tm_min,
               tm.tm_sec);
  if(n < 0) {
    return;
  }

  va_start(ap, fmt);
  n += vsnprintf(line + n, sizeof(line) - n, fmt, ap);
  va_end(ap);

  if(n > (int)sizeof(line) - 2) {
    n = sizeof(line) - 2;
  }
  line[n++] = '\n';
  if(write(logfd, line, n) < 0) {
    // Nothing to say to a log that will not take the line.
  }
  fsync(logfd);
  if(write(STDOUT_FILENO, line, n) < 0) {
    // The loader connection may be gone; the log already has the line.
  }
}


static void
log_identity(const char *who) {
  log_line("%s: effective user euid %u (uid %u, gid %u, egid %u)", who,
           (unsigned)geteuid(), (unsigned)getuid(), (unsigned)getgid(),
           (unsigned)getegid());
}


static int
refused(const char *probe, const char *call, int err) {
  log_line("%s: result refused, %s errno %d (%s)", probe, call, err,
           strerror(err));
  return 1;
}


static int
read_selector(int run[PROBE_COUNT]) {
  char text[32];
  ssize_t n;
  int fd;
  int i;
  int j;

  for(i=0; i<PROBE_COUNT; i++) {
    run[i] = 1;
  }

  fd = open(SPIKE_SELECT, O_RDONLY);
  if(fd < 0) {
    log_line("selector: %s absent, running all probes", SPIKE_SELECT);
    return 0;
  }
  n = read(fd, text, sizeof(text) - 1);
  close(fd);
  text[n < 0 ? 0 : n] = '\0';
  text[strcspn(text, " \t\r\n")] = '\0';

  if(!strcmp(text, "all")) {
    log_line("selector: all probes, in order");
    return 0;
  }
  for(i=0; i<PROBE_COUNT; i++) {
    if(!strcmp(text, probe_names[i])) {
      for(j=0; j<PROBE_COUNT; j++) {
        run[j] = (j == i);
      }
      log_line("selector: %s alone", text);
      return 0;
    }
  }

  log_line("selector refused: \"%s\", expected interfaces, sockets, echo or all",
           text);
  return -1;
}


/**
 * The interface list, read as the routing socket's sysctl gives it: one
 * message per interface and one per address, counted, not parsed further.
 **/
static int
probe_interfaces(void) {
  int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0};
  size_t size = 0;
  unsigned char *buf;
  unsigned char *end;
  unsigned char *at;
  int interfaces = 0;
  int addresses = 0;

  log_identity("interfaces");
  log_line("interfaces: intent sysctl mib %d.%d.%d.%d.%d.%d, family PF_ROUTE (%d), size query",
           mib[0], mib[1], mib[2], mib[3], mib[4], mib[5], PF_ROUTE);
  if(sysctl(mib, 6, NULL, &size, NULL, 0)) {
    return refused("interfaces", "size query", errno);
  }

  buf = malloc(size ? size : 1);
  if(!buf) {
    log_line("interfaces: result refused, no memory for %zu bytes", size);
    return 1;
  }

  log_line("interfaces: intent sysctl mib %d.%d.%d.%d.%d.%d, read %zu bytes",
           mib[0], mib[1], mib[2], mib[3], mib[4], mib[5], size);
  if(sysctl(mib, 6, buf, &size, NULL, 0)) {
    int err = errno;

    free(buf);
    return refused("interfaces", "read", err);
  }

  end = buf + size;
  at = buf;
  while(at + sizeof(struct if_msghdr) <= end) {
    struct if_msghdr *ifm = (struct if_msghdr*)at;

    if(ifm->ifm_msglen == 0 || (size_t)ifm->ifm_msglen > (size_t)(end - at)) {
      break;
    }
    if(ifm->ifm_type == RTM_IFINFO) {
      interfaces++;
      log_line("interfaces: interface index %u flags %#x",
               (unsigned)ifm->ifm_index, (unsigned)ifm->ifm_flags);
    } else if(ifm->ifm_type == RTM_NEWADDR) {
      addresses++;
    }
    at += ifm->ifm_msglen;
  }

  log_line("interfaces: result read, %zu bytes, %d interfaces, %d addresses",
           size, interfaces, addresses);
  free(buf);
  return 0;
}


static int
read_table(const char *name) {
  size_t size = 0;
  char *buf;

  log_line("sockets: intent sysctlbyname(%s), family AF_INET (%d), size query",
           name, AF_INET);
  if(sysctlbyname(name, NULL, &size, NULL, 0)) {
    return refused("sockets", name, errno);
  }

  buf = malloc(size ? size : 1);
  if(!buf) {
    log_line("sockets: result refused, no memory for %zu bytes", size);
    return 1;
  }

  log_line("sockets: intent sysctlbyname(%s), family AF_INET (%d), read %zu bytes",
           name, AF_INET, size);
  if(sysctlbyname(name, buf, &size, NULL, 0)) {
    int err = errno;

    free(buf);
    return refused("sockets", name, err);
  }

  log_line("sockets: result read, %s, %zu bytes", name, size);
  free(buf);
  return 0;
}


static int
probe_sockets(void) {
  int failures;

  log_identity("sockets");
  failures = read_table(SPIKE_TCP_TABLE);
  failures += read_table(SPIKE_UDP_TABLE);
  return failures;
}


static uint16_t
icmp_checksum(const void *data, size_t len) {
  const uint8_t *p = data;
  uint32_t sum = 0;
  size_t i;

  for(i=0; i+1<len; i+=2) {
    sum += (uint32_t)((p[i] << 8) | p[i+1]);
  }
  if(len % 2) {
    sum += (uint32_t)(p[len-1] << 8);
  }
  while(sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (uint16_t)~sum;
}


/**
 * One ICMP echo to the loopback address, with a receive deadline on every
 * read so the probe cannot wait without bound. The reply's bytes are not
 * logged; only its type, id and source.
 **/
static int
probe_echo(void) {
  struct sockaddr_in to;
  struct sockaddr_in from;
  socklen_t from_len;
  struct timeval deadline;
  echo_packet_t out;
  unsigned char in[256];
  unsigned id;
  unsigned reply_id;
  ssize_t n;
  int fd;
  int ihl;
  int tries;

  log_identity("echo");
  log_line("echo: intent socket(AF_INET %d, SOCK_RAW %d, IPPROTO_ICMP %d)",
           AF_INET, SOCK_RAW, IPPROTO_ICMP);
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(fd < 0) {
    return refused("echo", "socket", errno);
  }
  log_line("echo: result read, socket fd %d", fd);

  // A receive without a deadline could hold the console; refuse to run the
  // echo at all if the deadline cannot be set.
  deadline.tv_sec = SPIKE_WAIT_MS / 1000;
  deadline.tv_usec = (SPIKE_WAIT_MS % 1000) * 1000;
  if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline))) {
    int err = errno;

    close(fd);
    return refused("echo", "setsockopt SO_RCVTIMEO", err);
  }

  memset(&out, 0, sizeof(out));
  out.type = ICMP_ECHO;
  out.id = htons((uint16_t)getpid());
  out.seq = htons(1);
  memcpy(out.payload, "ariel", 5);
  out.checksum = htons(icmp_checksum(&out, sizeof(out)));

  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  log_line("echo: intent sendto %s, ICMP echo request id %u seq %u, %zu bytes",
           inet_ntoa(to.sin_addr), ntohs(out.id), ntohs(out.seq), sizeof(out));
  n = sendto(fd, &out, sizeof(out), 0, (struct sockaddr*)&to, sizeof(to));
  if(n < 0) {
    int err = errno;

    close(fd);
    return refused("echo", "sendto", err);
  }
  log_line("echo: result read, sendto %zd bytes", n);

  id = ntohs(out.id);
  for(tries=0; tries<SPIKE_TRIES; tries++) {
    log_line("echo: intent recvfrom, wait %d ms, read %d of %d",
             SPIKE_WAIT_MS, tries + 1, SPIKE_TRIES);
    from_len = sizeof(from);
    n = recvfrom(fd, in, sizeof(in), 0, (struct sockaddr*)&from, &from_len);
    if(n < 0) {
      int err = errno;

      close(fd);
      return refused("echo", "recvfrom", err);
    }
    if(n < SPIKE_IP_MIN) {
      log_line("echo: result other, %zd bytes is shorter than an IP header", n);
      continue;
    }

    ihl = (in[0] & 0x0f) * 4;
    if(n < ihl + 8) {
      log_line("echo: result other, %zd bytes is shorter than IP and ICMP", n);
      continue;
    }

    reply_id = (unsigned)((in[ihl+4] << 8) | in[ihl+5]);
    if(in[ihl] == ICMP_ECHOREPLY && reply_id == id) {
      log_line("echo: result read, echo reply from %s, icmp type %u id %u, %zd bytes",
               inet_ntoa(from.sin_addr), (unsigned)in[ihl], reply_id, n);
      close(fd);
      return 0;
    }
    log_line("echo: result other, from %s icmp type %u id %u, %zd bytes",
             inet_ntoa(from.sin_addr), (unsigned)in[ihl], reply_id, n);
  }

  close(fd);
  log_line("echo: result refused, no echo reply in %d reads", SPIKE_TRIES);
  return 1;
}


static int (*const probe_fns[PROBE_COUNT])(void) = {
  probe_interfaces, probe_sockets, probe_echo,
};


int
main(void) {
  int run[PROBE_COUNT];
  int failures = 0;
  int i;

  // A dropped loader connection must not end the payload before its log is written.
  signal(SIGPIPE, SIG_IGN);

  logfd = open(SPIKE_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if(logfd < 0) {
    notify("Network spike: cannot open %s", SPIKE_LOG);
    return 1;
  }

  log_line("network spike start, pid %d", (int)getpid());
  log_identity("start");

  if(read_selector(run)) {
    close(logfd);
    return 2;
  }

  for(i=0; i<PROBE_COUNT; i++) {
    if(run[i]) {
      notify("Network spike: probe %s", probe_names[i]);
      failures += probe_fns[i]();
    }
  }

  log_line("network spike end, failures %d", failures);
  close(logfd);
  return failures ? 1 : 0;
}
