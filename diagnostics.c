/* Ariel: the answers of the diagnostic commands that both builds share.

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
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "answer.h"
#include "diagnostics.h"
#include "json.h"


static void
put(int fd, const char *buf, size_t len) {
  while(len > 0) {
    ssize_t n = write(fd, buf, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return;
    }
    buf += n;
    len -= (size_t)n;
  }
}


static void
say(int fd, const char *text) {
  put(fd, text, strlen(text));
}


void
diagnostics_say_sysinfo(int json, int fd, const char *sysname,
                        const char *release, const char *machine,
                        unsigned long long uptime_seconds,
                        unsigned long long memory_total,
                        unsigned long long memory_free) {
  char line[192];

  if(json) {
    say(fd, "{\"sysname\":");
    json_say_string(fd, sysname);
    say(fd, ",\"release\":");
    json_say_string(fd, release);
    say(fd, ",\"machine\":");
    json_say_string(fd, machine);
    snprintf(line, sizeof(line),
             ",\"uptime_seconds\":%llu,\"memory_total_bytes\":%llu,"
             "\"memory_free_bytes\":%llu}\n",
             uptime_seconds, memory_total, memory_free);
    say(fd, line);
    return;
  }

  say(fd, "uname ");
  say(fd, sysname);
  say(fd, " ");
  say(fd, release);
  say(fd, " ");
  say(fd, machine);
  say(fd, "\n");

  snprintf(line, sizeof(line), "uptime %llu\n", uptime_seconds);
  say(fd, line);
  snprintf(line, sizeof(line), "memory %llu %llu\n", memory_total, memory_free);
  say(fd, line);
}


static int
interface_order(const void *a, const void *b) {
  const interface_row_t *x = a;
  const interface_row_t *y = b;
  int order = strcmp(x->name, y->name);

  if(order) {
    return order;
  }
  if(x->has_address != y->has_address) {
    return x->has_address < y->has_address ? -1 : 1;
  }
  return memcmp(x->address, y->address, sizeof(x->address));
}


static void
format_address(char *out, size_t cap, const unsigned char *bytes, int present) {
  if(!present) {
    snprintf(out, cap, "-");
    return;
  }
  snprintf(out, cap, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}


void
diagnostics_say_interfaces(int json, int fd, interface_row_t *rows,
                           size_t count) {
  answer_t answer;
  char address[16];
  char mask[16];
  char quoted[128];
  char line[256];
  size_t i;

  qsort(rows, count, sizeof(*rows), interface_order);
  answer_init(&answer, fd, SIZE_MAX);
  for(i=0; i<count; i++) {
    const interface_row_t *row = &rows[i];
    const char *state = row->up ? "up" : "down";

    format_address(address, sizeof(address), row->address, row->has_address);
    format_address(mask, sizeof(mask), row->mask, row->has_address);
    if(json) {
      size_t quoted_len = json_format_string(quoted, sizeof(quoted), row->name);

      snprintf(line, sizeof(line),
               "{\"name\":%.*s,\"state\":\"%s\",\"address\":\"%s\",\"mask\":\"%s\"}",
               (int)quoted_len, quoted, state, address, mask);
    } else {
      snprintf(line, sizeof(line), "%s %s %s %s", row->name, state, address,
               mask);
    }
    answer_line(&answer, line, strlen(line));
  }
  answer_done(&answer);
}


void
diagnostics_say_log(int fd, const char *data, size_t len) {
  answer_t answer;
  const char *end = data + len;
  const char *nul = memchr(data, '\0', len);
  const char *line = data;

  // A kernel log may arrive NUL padded; the text ends at the first NUL.
  if(nul) {
    end = nul;
  }

  answer_init(&answer, fd, SIZE_MAX);
  while(line < end) {
    const char *newline = memchr(line, '\n', (size_t)(end - line));
    const char *stop = newline ? newline : end;

    // The kernel ends its lines with a carriage return on some consoles.
    while(stop > line && stop[-1] == '\r') {
      stop--;
    }
    answer_line(&answer, line, (size_t)(stop - line));
    line = newline ? newline + 1 : end;
  }
  answer_done(&answer);
}


#define PING_ECHO 8
#define PING_ECHO_REPLY 0
#define PING_HEADER 8
#define PING_PAYLOAD 16
#define PING_DEFAULT_COUNT 4
#define PING_MAX_COUNT 10
#define PING_DEFAULT_WAIT_MS 1000
#define PING_MAX_WAIT_MS 5000


static int
ping_number(const char *text, int low, int high, int *out) {
  int value = 0;

  if(!*text) {
    return -1;
  }
  for(; *text; text++) {
    if(!isdigit((unsigned char)*text) || value > high / 10) {
      return -1;
    }
    value = value * 10 + (*text - '0');
  }
  if(value < low || value > high) {
    return -1;
  }
  *out = value;
  return 0;
}


/* The first refusal in the ping arguments, or NULL when they are well formed. */
static const char *
ping_parse(int argc, char *const argv[], int *count, int *wait_ms,
           const char **operand) {
  int count_seen = 0;
  int wait_seen = 0;
  int i;

  for(i=1; i<argc; i++) {
    if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "-W")) {
      int counting = argv[i][1] == 'c';
      int *seen = counting ? &count_seen : &wait_seen;
      int *value = counting ? count : wait_ms;
      int high = counting ? PING_MAX_COUNT : PING_MAX_WAIT_MS;

      if(*seen) {
        return "bad_option";
      }
      *seen = 1;
      if(++i >= argc || ping_number(argv[i], 1, high, value)) {
        return "bad_argument";
      }
    } else if(argv[i][0] == '-') {
      return "bad_option";
    } else if(*operand) {
      return "bad_argument";
    } else {
      *operand = argv[i];
    }
  }
  return *operand ? NULL : "missing_operand";
}


static uint16_t
ping_checksum(const unsigned char *data, size_t len) {
  uint32_t sum = 0;
  size_t i;

  for(i=0; i+1<len; i+=2) {
    sum += (uint32_t)((data[i] << 8) | data[i+1]);
  }
  if(len % 2) {
    sum += (uint32_t)(data[len-1] << 8);
  }
  while(sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (uint16_t)~sum;
}


static void
ping_build(unsigned char *packet, uint16_t id, uint16_t seq) {
  uint16_t sum;
  size_t i;

  packet[0] = PING_ECHO;
  packet[1] = 0;
  packet[2] = 0;
  packet[3] = 0;
  packet[4] = (unsigned char)(id >> 8);
  packet[5] = (unsigned char)id;
  packet[6] = (unsigned char)(seq >> 8);
  packet[7] = (unsigned char)seq;
  for(i=0; i<PING_PAYLOAD; i++) {
    packet[PING_HEADER + i] = (unsigned char)('a' + i % 26);
  }
  sum = ping_checksum(packet, PING_HEADER + PING_PAYLOAD);
  packet[2] = (unsigned char)(sum >> 8);
  packet[3] = (unsigned char)sum;
}


/* A raw socket delivers the IPv4 header in front of the ICMP message. */
static int
ping_is_reply(const unsigned char *in, size_t len, const struct in_addr *target,
              uint16_t id, uint16_t seq) {
  size_t header;

  if(len < 20) {
    return 0;
  }
  header = (size_t)(in[0] & 0x0f) * 4;
  if(header < 20 || len < header + PING_HEADER) {
    return 0;
  }
  if(memcmp(in + 12, &target->s_addr, sizeof(target->s_addr))) {
    return 0;
  }
  return in[header] == PING_ECHO_REPLY &&
         in[header+4] == (id >> 8) && in[header+5] == (id & 0xff) &&
         in[header+6] == (seq >> 8) && in[header+7] == (seq & 0xff);
}


static long long
ping_now_us(void) {
  struct timespec now;

  clock_gettime(CLOCK_MONOTONIC, &now);
  return (long long)now.tv_sec * 1000000LL + now.tv_nsec / 1000;
}


/* Wait for the echo reply to one probe until the deadline. Returns 1 and its
   round trip in microseconds when it came back, or 0 when it did not. */
static int
ping_wait(int fd, const struct in_addr *target, uint16_t id, uint16_t seq,
          long long sent_at, long long deadline, long long *rtt_us) {
  unsigned char in[1024];

  for(;;) {
    long long left = deadline - ping_now_us();
    struct pollfd pfd;
    ssize_t n;
    int rc;

    if(left <= 0) {
      return 0;
    }
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    rc = poll(&pfd, 1, (int)((left + 999) / 1000));
    if(rc < 0 && errno == EINTR) {
      continue;
    }
    if(rc <= 0) {
      return 0;
    }
    n = recv(fd, in, sizeof(in), 0);
    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return 0;
    }
    if(ping_is_reply(in, (size_t)n, target, id, seq)) {
      *rtt_us = ping_now_us() - sent_at;
      return 1;
    }
  }
}


static void
ping_refuse(int errfd, const char *word, int *status) {
  say(errfd, word);
  say(errfd, "\n");
  *status = 1;
}


void
diagnostics_run_ping(int argc, char *const argv[], int outfd, int errfd,
                     int *status) {
  int count = PING_DEFAULT_COUNT;
  int wait_ms = PING_DEFAULT_WAIT_MS;
  const char *operand = NULL;
  const char *refusal = ping_parse(argc, argv, &count, &wait_ms, &operand);
  struct in_addr target;
  struct sockaddr_in to;
  char address[INET_ADDRSTRLEN];
  char line[128];
  long long min_us = 0;
  long long max_us = 0;
  long long sum_us = 0;
  uint16_t id;
  int sent = 0;
  int received = 0;
  int seq;
  int fd;

  if(refusal) {
    ping_refuse(errfd, refusal, status);
    return;
  }
  if(inet_pton(AF_INET, operand, &target) != 1) {
    ping_refuse(errfd, "bad_argument", status);
    return;
  }
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(fd < 0) {
    ping_refuse(errfd, "not available on this platform", status);
    return;
  }

  id = (uint16_t)getpid();
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr = target;
  for(seq=1; seq<=count; seq++) {
    unsigned char packet[PING_HEADER + PING_PAYLOAD];
    long long sent_at;
    long long rtt_us;

    ping_build(packet, id, (uint16_t)seq);
    sent_at = ping_now_us();
    if(sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)&to,
              sizeof(to)) < 0) {
      continue;
    }
    sent++;
    if(!ping_wait(fd, &target, id, (uint16_t)seq, sent_at,
                  sent_at + (long long)wait_ms * 1000, &rtt_us)) {
      continue;
    }
    if(!received || rtt_us < min_us) {
      min_us = rtt_us;
    }
    if(!received || rtt_us > max_us) {
      max_us = rtt_us;
    }
    sum_us += rtt_us;
    received++;
  }
  close(fd);

  if(!received) {
    ping_refuse(errfd, "no_reply", status);
    return;
  }
  inet_ntop(AF_INET, &target, address, sizeof(address));
  snprintf(line, sizeof(line), "ping %s %d %d %lld %lld %lld\n", address, sent,
           received, min_us / 1000, sum_us / received / 1000, max_us / 1000);
  say(outfd, line);
  *status = 0;
}
