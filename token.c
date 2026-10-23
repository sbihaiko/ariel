/* Ariel: the access token.

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "token.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TOKEN_FILE  "token"
#define TOKEN_BYTES (TOKEN_HEX_LEN / 2)

static const char hex_digits[] = "0123456789abcdef";


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


static int
read_all(int fd, char *buf, size_t cap) {
  size_t total = 0;

  while(total < cap) {
    ssize_t n = read(fd, buf + total, cap - total);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(n == 0) {
      break;
    }
    total += (size_t)n;
  }
  return (int)total;
}


static int
random_bytes(unsigned char *buf, size_t len) {
#if defined(__FreeBSD__)
  // A console has no /dev/urandom to open. FreeBSD libc's arc4random is
  // seeded from the kernel's cryptographic random source.
  arc4random_buf(buf, len);
  return 0;
#else
  size_t total = 0;
  int fd;

  if((fd=open("/dev/urandom", O_RDONLY | O_CLOEXEC)) < 0) {
    return -1;
  }

  while(total < len) {
    ssize_t n = read(fd, buf + total, len - total);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      close(fd);
      return -1;
    }
    if(n == 0) {
      close(fd);
      return -1;
    }
    total += (size_t)n;
  }

  return close(fd);
#endif
}


static int
hex_value(char c) {
  if(c >= '0' && c <= '9') {
    return c - '0';
  }
  if(c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}


static int
token_valid(const char *token) {
  int i;

  for(i=0; i<TOKEN_HEX_LEN; i++) {
    if(hex_value(token[i]) < 0) {
      return 0;
    }
  }
  return token[TOKEN_HEX_LEN] == '\0';
}


static int
read_token_file(const char *path, char token[TOKEN_LEN]) {
  char buf[128];
  int len;
  int fd;

  if((fd=open(path, O_RDONLY | O_CLOEXEC)) < 0) {
    return -1;
  }

  len = read_all(fd, buf, sizeof(buf));
  close(fd);

  if(len < 0) {
    return -1;
  }

  // The file holds the 32 hex digits and a newline.
  if(len > 0 && buf[len - 1] == '\n') {
    len--;
  }
  if(len > 0 && buf[len - 1] == '\r') {
    len--;
  }
  if(len != TOKEN_HEX_LEN) {
    return -1;
  }

  memcpy(token, buf, TOKEN_HEX_LEN);
  token[TOKEN_HEX_LEN] = '\0';

  return token_valid(token) ? 0 : -1;
}


static int
create_token_file(const char *dir, char token[TOKEN_LEN]) {
  unsigned char raw[TOKEN_BYTES];
  char path[PATH_MAX];
  char tmp[PATH_MAX];
  int fd = -1;
  int i;

  if(random_bytes(raw, sizeof(raw))) {
    return -1;
  }

  for(i=0; i<TOKEN_BYTES; i++) {
    token[2*i] = hex_digits[raw[i] >> 4];
    token[2*i + 1] = hex_digits[raw[i] & 0x0f];
  }
  token[TOKEN_HEX_LEN] = '\0';

  if(snprintf(path, sizeof(path), "%s/" TOKEN_FILE, dir) >= (int)sizeof(path)) {
    return -1;
  }

  // Create the new token beside the old one, exclusively, then rename it
  // into place so a reader never sees a partial token.
  for(i=0; i<8 && fd < 0; i++) {
    if(snprintf(tmp, sizeof(tmp), "%s/" TOKEN_FILE ".tmp.%ld.%d",
                dir, (long)getpid(), i) >= (int)sizeof(tmp)) {
      return -1;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if(fd < 0 && errno != EEXIST) {
      return -1;
    }
  }

  if(fd < 0) {
    return -1;
  }

  if(write_all(fd, token, TOKEN_HEX_LEN) ||
     write_all(fd, "\n", 1) ||
     fsync(fd)) {
    close(fd);
    unlink(tmp);
    return -1;
  }

  if(close(fd)) {
    unlink(tmp);
    return -1;
  }

  if(rename(tmp, path)) {
    unlink(tmp);
    return -1;
  }

  return 0;
}


int
token_load_or_create(const char *dir, char token[TOKEN_LEN]) {
  char path[PATH_MAX];

  if(snprintf(path, sizeof(path), "%s/" TOKEN_FILE, dir) >= (int)sizeof(path)) {
    return -1;
  }

  if(read_token_file(path, token) == 0) {
    return 0;
  }

  return create_token_file(dir, token);
}


int
token_equal(const char *a, const char *b) {
  unsigned char diff = 0;
  int i;

  if(strlen(a) != (size_t)TOKEN_HEX_LEN ||
     strlen(b) != (size_t)TOKEN_HEX_LEN) {
    return 0;
  }

  for(i=0; i<TOKEN_HEX_LEN; i++) {
    diff |= (unsigned char)(a[i] ^ b[i]);
  }

  return diff == 0;
}
