/* Ariel: the ftp addon, which moves files through the console's ftpsrv.

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
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "protected.h"

#ifndef ARIEL_FS_ROOT
#define ARIEL_FS_ROOT ""
#endif

#define FS_ROOT ARIEL_FS_ROOT
#define STATE_DIR "/data/ariel"
#define LINE_TEXT 512
#define SERVER_TEXT 64
#define FTP_FAILED 1
#define FTP_BAD_PATH 3
#define FTP_PROTECTED 87

static int
resolve(char *full, size_t size, const char *prefix, const char *path) {
  return snprintf(full, size, "%s%s%s", FS_ROOT, prefix, path) < (int)size;
}


static int
printable(const char *path) {
  size_t i;

  for(i=0; path[i]; i++) {
    if(path[i] < ' ' || path[i] == 0x7f) {
      return 0;
    }
  }
  return 1;
}


static int
dotdot(const char *path) {
  const char *at = path;

  while((at = strstr(at, "..")) != NULL) {
    if((at == path || at[-1] == '/') && (at[2] == '/' || at[2] == '\0')) {
      return 1;
    }
    at += 2;
  }
  return 0;
}


static int
check_remote(const char *remote) {
  char full[PATH_MAX];

  if(remote[0] != '/' || strlen(remote) >= 256 || !printable(remote) ||
     dotdot(remote)) {
    return FTP_BAD_PATH;
  }
  if(!resolve(full, sizeof(full), "", remote) || protected_path(full)) {
    return FTP_PROTECTED;
  }
  if(!resolve(full, sizeof(full), "/data", remote) || protected_path(full)) {
    return FTP_PROTECTED;
  }
  return 0;
}


static int
plain_directories(const char *local) {
  char path[PATH_MAX];
  const char *slash;
  int fd;

  for(slash=strchr(local + 1, '/'); slash; slash=strchr(slash + 1, '/')) {
    if(snprintf(path, sizeof(path), "%s%.*s", FS_ROOT, (int)(slash - local),
                local) >= (int)sizeof(path)) {
      return 0;
    }
    fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if(fd < 0) {
      return 0;
    }
    close(fd);
  }
  return 1;
}


static int
check_local(const char *local, char *full, size_t size) {
  int inside = !strncmp(local, "/data/", 6) || !strncmp(local, "/user/", 6) ||
               !strncmp(local, "/mnt/usb", 8);

  if(!inside || !printable(local) || dotdot(local)) {
    return FTP_BAD_PATH;
  }
  if(!resolve(full, size, "", local) || protected_path(full)) {
    return FTP_PROTECTED;
  }
  if(!plain_directories(local)) {
    return FTP_BAD_PATH;
  }
  return 0;
}


static int
server_address(const char *name, const char *signed_server,
               struct sockaddr_in *peer) {
  char path[PATH_MAX];
  char text[SERVER_TEXT + 1];
  char host[SERVER_TEXT];
  char *colon;
  char *end;
  long port;
  ssize_t n;
  int fd;

  if(snprintf(path, sizeof(path), "%s%s/addons/%s/server", FS_ROOT, STATE_DIR,
              name) >= (int)sizeof(path)) {
    return -1;
  }
  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if(fd < 0) {
    return -1;
  }
  n = read(fd, text, sizeof(text) - 1);
  close(fd);
  if(n <= 0) {
    return -1;
  }
  if(text[n - 1] == '\n') {
    n--;
  }
  text[n] = '\0';
  if(strcmp(text, signed_server)) {
    return -1;
  }

  colon = strrchr(text, ':');
  if(!colon || (size_t)(colon - text) >= sizeof(host)) {
    return -1;
  }
  memcpy(host, text, (size_t)(colon - text));
  host[colon - text] = '\0';
  port = strtol(colon + 1, &end, 10);
  if(*end != '\0' || port < 1 || port > 65535) {
    return -1;
  }

  memset(peer, 0, sizeof(*peer));
  peer->sin_family = AF_INET;
  peer->sin_port = htons((uint16_t)port);
  return inet_pton(AF_INET, host, &peer->sin_addr) == 1 ? 0 : -1;
}


static int
connect_peer(const struct sockaddr_in *peer) {
  int fd;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) {
    return -1;
  }
  if(connect(fd, (const struct sockaddr *)peer, sizeof(*peer))) {
    close(fd);
    return -1;
  }
  return fd;
}


static int
send_text(int fd, const char *text) {
  size_t len = strlen(text);
  size_t done = 0;
  ssize_t n;

  while(done < len) {
    n = send(fd, text + done, len - done, 0);
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      return -1;
    }
    done += (size_t)n;
  }
  return 0;
}


static int
read_line(int fd, char *line, size_t size) {
  size_t n = 0;
  ssize_t got;
  char c;

  for(;;) {
    got = recv(fd, &c, 1, 0);
    if(got < 0 && errno == EINTR) {
      continue;
    }
    if(got <= 0) {
      return -1;
    }
    if(c == '\n') {
      break;
    }
    if(n + 1 >= size) {
      return -1;
    }
    line[n++] = c;
  }
  if(n > 0 && line[n - 1] == '\r') {
    n--;
  }
  line[n] = '\0';
  return 0;
}


static int
reply_code(const char *line) {
  if(strlen(line) < 4 || line[0] < '1' || line[0] > '5' ||
     line[1] < '0' || line[1] > '9' || line[2] < '0' || line[2] > '9' ||
     line[3] != ' ') {
    return -1;
  }
  return (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
}


static int
reply(int fd, char *line, size_t size) {
  int code;

  do {
    if(read_line(fd, line, size)) {
      return -1;
    }
    code = reply_code(line);
  } while(code < 0);
  return code;
}


static int
command(int fd, const char *text, char *line, size_t size) {
  char out[LINE_TEXT];

  if(snprintf(out, sizeof(out), "%s\r\n", text) >= (int)sizeof(out) ||
     send_text(fd, out)) {
    return -1;
  }
  return reply(fd, line, size);
}


static int
open_session(const struct sockaddr_in *peer, char *line, size_t size) {
  int code;
  int fd;

  fd = connect_peer(peer);
  if(fd < 0) {
    return -1;
  }
  if(reply(fd, line, size) != 220) {
    close(fd);
    return -1;
  }
  code = command(fd, "USER anonymous", line, size);
  if(code == 331) {
    code = command(fd, "PASS ariel@", line, size);
  }
  if(code != 230 || command(fd, "TYPE I", line, size) != 200) {
    close(fd);
    return -1;
  }
  return fd;
}


static int
passive_connect(int ctrl, const struct sockaddr_in *peer, char *line,
                size_t size) {
  struct sockaddr_in data;
  unsigned int h1, h2, h3, h4, p1, p2;
  const char *paren;
  int fd;

  if(command(ctrl, "PASV", line, size) != 227) {
    return -1;
  }
  paren = strchr(line, '(');
  if(!paren || sscanf(paren, "(%u,%u,%u,%u,%u,%u)", &h1, &h2, &h3, &h4, &p1,
                      &p2) != 6 || p1 > 255 || p2 > 255) {
    return -1;
  }
  data = *peer;
  data.sin_port = htons((uint16_t)(p1 * 256 + p2));
  fd = connect_peer(&data);
  return fd;
}


static int
transfer_start(int ctrl, const struct sockaddr_in *peer, const char *verb,
               const char *remote, char *line, size_t size) {
  char text[LINE_TEXT];
  int code;
  int fd;

  fd = passive_connect(ctrl, peer, line, size);
  if(fd < 0) {
    return -1;
  }
  if(snprintf(text, sizeof(text), "%s %s", verb, remote) >= (int)sizeof(text)) {
    close(fd);
    return -1;
  }
  code = command(ctrl, text, line, size);
  if(code != 150 && code != 125) {
    close(fd);
    return -1;
  }
  return fd;
}


static int
copy_fd(int from, int to) {
  char buf[4096];
  ssize_t n;
  ssize_t w;
  size_t done;

  for(;;) {
    n = read(from, buf, sizeof(buf));
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n < 0) {
      return -1;
    }
    if(n == 0) {
      return 0;
    }
    for(done=0; done<(size_t)n;) {
      w = write(to, buf + done, (size_t)n - done);
      if(w < 0 && errno == EINTR) {
        continue;
      }
      if(w <= 0) {
        return -1;
      }
      done += (size_t)w;
    }
  }
}


static int
run_transfer(const char *name, const char *server, const char *verb,
             const char *remote, int local, int download) {
  struct sockaddr_in peer;
  char line[LINE_TEXT];
  int copied;
  int rc = FTP_FAILED;
  int data;
  int ctrl;

  if(server_address(name, server, &peer)) {
    return FTP_FAILED;
  }
  ctrl = open_session(&peer, line, sizeof(line));
  if(ctrl < 0) {
    return FTP_FAILED;
  }
  data = transfer_start(ctrl, &peer, verb, remote, line, sizeof(line));
  if(data >= 0) {
    copied = download ? copy_fd(data, local) : copy_fd(local, data);
    close(data);
    if(!copied && reply(ctrl, line, sizeof(line)) == 226) {
      rc = 0;
    }
  }
  (void)command(ctrl, "QUIT", line, sizeof(line));
  close(ctrl);
  return rc;
}


static int
do_ls(const char *name, const char *server, const char *remote) {
  int rc = check_remote(remote);

  if(rc) {
    return rc;
  }
  return run_transfer(name, server, "LIST", remote, STDOUT_FILENO, 1);
}


static int
do_get(const char *name, const char *server, const char *remote,
       const char *local) {
  char full[PATH_MAX];
  int rc;
  int fd;

  rc = check_remote(remote);
  if(!rc) {
    rc = check_local(local, full, sizeof(full));
  }
  if(rc) {
    return rc;
  }
  fd = open(full, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if(fd < 0) {
    return FTP_FAILED;
  }
  rc = run_transfer(name, server, "RETR", remote, fd, 1);
  close(fd);
  if(rc) {
    unlink(full);
  }
  return rc;
}


static int
do_put(const char *name, const char *server, const char *remote,
       const char *local) {
  char full[PATH_MAX];
  struct stat st;
  int rc;
  int fd;

  rc = check_remote(remote);
  if(!rc) {
    rc = check_local(local, full, sizeof(full));
  }
  if(rc) {
    return rc;
  }
  fd = open(full, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if(fd < 0) {
    return FTP_FAILED;
  }
  if(fstat(fd, &st) || !S_ISREG(st.st_mode)) {
    close(fd);
    return FTP_FAILED;
  }
  rc = protected_object(fd);
  if(rc) {
    close(fd);
    return rc < 0 ? FTP_FAILED : FTP_PROTECTED;
  }
  rc = run_transfer(name, server, "STOR", remote, fd, 0);
  close(fd);
  return rc;
}


static int
do_rm(const char *name, const char *server, const char *remote) {
  struct sockaddr_in peer;
  char line[LINE_TEXT];
  char text[LINE_TEXT];
  int rc = check_remote(remote);
  int ctrl;

  if(rc) {
    return rc;
  }
  if(server_address(name, server, &peer)) {
    return FTP_FAILED;
  }
  ctrl = open_session(&peer, line, sizeof(line));
  if(ctrl < 0) {
    return FTP_FAILED;
  }
  if(snprintf(text, sizeof(text), "DELE %s", remote) < (int)sizeof(text) &&
     command(ctrl, text, line, sizeof(line)) == 250) {
    rc = 0;
  } else {
    rc = FTP_FAILED;
  }
  (void)command(ctrl, "QUIT", line, sizeof(line));
  close(ctrl);
  return rc;
}


int
main(int argc, char *argv[]) {
  protected_init(FS_ROOT STATE_DIR);

  if(argc < 3) {
    return FTP_FAILED;
  }
  if(argc == 3 && !strcmp(argv[0], "ftp-ls")) {
    return do_ls(argv[0], argv[1], argv[2]);
  }
  if(argc == 3 && !strcmp(argv[0], "ftp-rm")) {
    return do_rm(argv[0], argv[1], argv[2]);
  }
  if(argc == 4 && !strcmp(argv[0], "ftp-get")) {
    return do_get(argv[0], argv[1], argv[2], argv[3]);
  }
  if(argc == 4 && !strcmp(argv[0], "ftp-put")) {
    return do_put(argv[0], argv[1], argv[2], argv[3]);
  }
  return FTP_FAILED;
}
