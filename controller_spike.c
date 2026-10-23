/* Copyright (C) 2026 the ariel contributors

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

/**
 * Controller spike payload.
 *
 * Opens the controller from a process started through the ELF loader,
 * reads its state for a fixed time, and reports button presses and error
 * codes as console notifications and on a TCP port. The payload stops on
 * its own and closes the controller and the sockets.
 *
 * Build the runbook: docs/controller-spike.md
 **/

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "notify.h"
#include "pad.h"


#define SPIKE_PORT        9150
#define SPIKE_SECONDS     120
#define SPIKE_FRAME_MS    16
#define SPIKE_MAX_CLIENTS 4
#define SPIKE_TRANSCRIPT  4096
#define SPIKE_LINE        512


/**
 * The buttons field of ScePadData, as documented by the reimplementations
 * of the pad library.
 **/
typedef struct pad_buttons {
  unsigned int bit;
  const char*  name;
} pad_buttons_t;


static const pad_buttons_t pad_buttons[] = {
  {0x00000002, "L3"},
  {0x00000004, "R3"},
  {0x00000008, "OPTIONS"},
  {0x00000010, "UP"},
  {0x00000020, "RIGHT"},
  {0x00000040, "DOWN"},
  {0x00000080, "LEFT"},
  {0x00000100, "L2"},
  {0x00000200, "R2"},
  {0x00000400, "L1"},
  {0x00000800, "R1"},
  {0x00001000, "TRIANGLE"},
  {0x00002000, "CIRCLE"},
  {0x00004000, "CROSS"},
  {0x00008000, "SQUARE"},
  {0x00100000, "TOUCHPAD"},
};

#define PAD_BUTTON_COUNT (sizeof(pad_buttons) / sizeof(pad_buttons[0]))


static int      client_fds[SPIKE_MAX_CLIENTS];
static char     transcript[SPIKE_TRANSCRIPT];
static size_t   transcript_len;

static unsigned int user_error;
static unsigned int init_error;
static unsigned int open_error;


/**
 * Append text to a line without overflowing it.
 **/
static void
append(char* line, size_t size, size_t* len, const char* text) {
  while(*text && *len + 1 < size) {
    line[(*len)++] = *text++;
  }
  line[*len] = '\0';
}


/**
 * Append a code as eight hexadecimal digits.
 **/
static void
append_code(char* line, size_t size, size_t* len, unsigned int code) {
  char tmp[16];

  snprintf(tmp, sizeof tmp, " 0x%08x", code);
  append(line, size, len, tmp);
}


/**
 * Remember a line so that a client which connects later sees the history.
 **/
static void
transcript_append(const char* line, size_t len) {
  size_t drop;

  if(len > SPIKE_TRANSCRIPT) {
    line += len - SPIKE_TRANSCRIPT;
    len = SPIKE_TRANSCRIPT;
  }

  while(transcript_len + len > SPIKE_TRANSCRIPT) {
    drop = SPIKE_TRANSCRIPT / 2;
    while(drop < transcript_len && transcript[drop] != '\n') {
      drop++;
    }
    if(drop < transcript_len) {
      drop++;
    }

    memmove(transcript, transcript + drop, transcript_len - drop);
    transcript_len -= drop;
  }

  memcpy(transcript + transcript_len, line, len);
  transcript_len += len;
}


/**
 * Write every byte to a client, or fail.
 **/
static int
send_all(int fd, const char* buf, size_t len) {
  ssize_t written;
  size_t sent = 0;

  while(sent < len) {
    written = send(fd, buf + sent, len - sent, 0);
    if(written < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    sent += (size_t)written;
  }

  return 0;
}


/**
 * Write a line to every connected client, and drop the ones that are gone.
 **/
static void
broadcast(const char* line, size_t len) {
  for(int i=0; i<SPIKE_MAX_CLIENTS; i++) {
    if(client_fds[i] < 0) {
      continue;
    }

    if(send_all(client_fds[i], line, len)) {
      close(client_fds[i]);
      client_fds[i] = -1;
    }
  }
}


/**
 * Report one line as a console notification and to every client.
 **/
static void
report(const char* fmt, ...) {
  char body[SPIKE_LINE - 32];
  char line[SPIKE_LINE];
  va_list args;
  size_t len;

  va_start(args, fmt);
  vsnprintf(body, sizeof body, fmt, args);
  va_end(args);

  len = (size_t)snprintf(line, sizeof line, "controller spike: %s\n", body);
  if(len >= sizeof line) {
    len = sizeof line - 1;
    line[len] = '\0';
  }

  transcript_append(line, len);
  broadcast(line, len);
  notify("%.*s", (int)len - 1, line);
}


/**
 * Report an error code the first time it is seen.
 **/
static void
report_error(const char* what, unsigned int code, unsigned int* last) {
  if(code == *last) {
    return;
  }

  *last = code;
  report("%s error 0x%08x", what, code);
}


/**
 * Open the controller for the console's user, retrying later on failure.
 **/
static int
pad_attempt(int* user_id) {
  int handle;
  int err;
  int id;

  err = scePadInit();
  if(err) {
    report_error("init", (unsigned int)err, &init_error);
  } else if(init_error) {
    init_error = 0;
    report("init ok");
  }

  if(*user_id < 0) {
    id = -1;
    err = sceUserServiceGetInitialUser(&id);
    if(!err && id >= 0) {
      *user_id = id;
      user_error = 0;
      report("user %d (initial)", id);
    } else {
      report_error("user initial", err ? (unsigned int)err : ~0u, &user_error);
      id = -1;
      err = sceUserServiceGetForegroundUser(&id);
      if(!err && id >= 0) {
        *user_id = id;
        user_error = 0;
        report("user %d (foreground)", id);
      } else {
        report_error("user foreground", err ? (unsigned int)err : ~0u,
                     &user_error);
        return -1;
      }
    }
  }

  handle = scePadOpen(*user_id, PAD_PORT_TYPE_STANDARD, 0, NULL);
  if(handle < 0) {
    report_error("open", (unsigned int)handle, &open_error);
    return -1;
  }

  open_error = 0;
  report("open ok user %d handle %d", *user_id, handle);

  return handle;
}


/**
 * Report the buttons that went down since the previous read.
 **/
static void
read_buttons(unsigned int state, unsigned int* buttons, int* intercepted,
             int* presses) {
  char line[SPIKE_LINE];
  size_t len = 0;
  unsigned int pressed;
  unsigned int unknown;
  int intercepted_now;

  intercepted_now = (state & PAD_BUTTON_INTERCEPTED) != 0;
  if(intercepted_now != *intercepted) {
    *intercepted = intercepted_now;
    if(intercepted_now) {
      report("input intercepted by the system");
    } else {
      report("input no longer intercepted");
    }
  }

  pressed = state & ~*buttons & ~PAD_BUTTON_INTERCEPTED;
  *buttons = state;

  if(!pressed) {
    return;
  }

  append(line, sizeof line, &len, "press");
  unknown = pressed;
  for(size_t i=0; i<PAD_BUTTON_COUNT; i++) {
    if(pressed & pad_buttons[i].bit) {
      append(line, sizeof line, &len, " ");
      append(line, sizeof line, &len, pad_buttons[i].name);
      unknown &= ~pad_buttons[i].bit;
    }
  }
  if(unknown) {
    append_code(line, sizeof line, &len, unknown);
  }

  (*presses)++;
  report("%s", line);
}


/**
 * Read the controller once and report what changed.
 **/
static void
read_pad(int handle, pad_data_t* data, unsigned int* buttons,
         unsigned int* last_err, int* intercepted, int* presses, int* errors) {
  int err;

  memset(data, 0, sizeof *data);
  err = scePadReadState(handle, data);

  if(err < 0) {
    if((unsigned int)err != *last_err) {
      *last_err = (unsigned int)err;
      (*errors)++;
      report("read error 0x%08x", *last_err);
    }
    *buttons = 0;
    return;
  }

  if(*last_err) {
    *last_err = 0;
    report("read ok");
  }

  read_buttons(data->buttons, buttons, intercepted, presses);
}


/**
 * Create the listening socket and serve at most one client per call.
 **/
static int
listen_socket(int port) {
  struct sockaddr_in addr;
  int flags;
  int fd;

  if((fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return -1;
  }

  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    close(fd);
    return -1;
  }

  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if(bind(fd, (struct sockaddr*)&addr, sizeof addr) < 0 ||
     listen(fd, SPIKE_MAX_CLIENTS) < 0 ||
     (flags=fcntl(fd, F_GETFL)) < 0 ||
     fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}


/**
 * Accept every pending client and give it the transcript so far.
 **/
static void
accept_clients(int srvfd, long elapsed) {
  struct sockaddr_in addr;
  char line[SPIKE_LINE];
  socklen_t addr_len;
  long left;
  int flags;
  int slot;
  int fd;

  while(1) {
    addr_len = sizeof addr;
    if((fd=accept(srvfd, (struct sockaddr*)&addr, &addr_len)) < 0) {
      return;
    }

    flags = fcntl(fd, F_GETFL);
    if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      close(fd);
      continue;
    }

    slot = -1;
    for(int i=0; i<SPIKE_MAX_CLIENTS; i++) {
      if(client_fds[i] < 0) {
        slot = i;
        break;
      }
    }
    if(slot < 0) {
      slot = 0;
      close(client_fds[slot]);
    }
    client_fds[slot] = fd;

    left = SPIKE_SECONDS - elapsed / 1000;
    snprintf(line, sizeof line,
             "controller spike: connected, %ld s elapsed, %ld s left\n",
             elapsed / 1000, left > 0 ? left : 0);
    if(send_all(fd, line, strlen(line)) ||
       send_all(fd, transcript, transcript_len)) {
      close(fd);
      client_fds[slot] = -1;
    }
  }
}


/**
 * Run the spike for its fixed time.
 **/
static int
spike_run(void) {
  struct timespec start;
  struct timespec now;
  pad_data_t data;
  unsigned int buttons = 0;
  unsigned int last_err = 0;
  long elapsed;
  long next_open = 0;
  int intercepted = 0;
  int presses = 0;
  int errors = 0;
  int user_id = -1;
  int handle = -1;
  int srvfd;
  int err;

  for(int i=0; i<SPIKE_MAX_CLIENTS; i++) {
    client_fds[i] = -1;
  }

  signal(SIGPIPE, SIG_IGN);

  if((srvfd=listen_socket(SPIKE_PORT)) < 0) {
    notify("controller spike: cannot listen on port %d", SPIKE_PORT);
    return 1;
  }

  clock_gettime(CLOCK_MONOTONIC, &start);

  err = sceUserServiceInitialize(NULL);
  if(err) {
    report("user service init error 0x%08x", (unsigned int)err);
  }
  report("listening on port %d for %d s, connect with nc", SPIKE_PORT,
         SPIKE_SECONDS);

  while(1) {
    struct pollfd pfd = {.fd = srvfd, .events = POLLIN};

    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - start.tv_sec) * 1000L +
              (now.tv_nsec - start.tv_nsec) / 1000000L;
    if(elapsed >= SPIKE_SECONDS * 1000L) {
      break;
    }

    poll(&pfd, 1, SPIKE_FRAME_MS);
    if(pfd.revents & POLLIN) {
      accept_clients(srvfd, elapsed);
    }

    if(handle < 0) {
      if(elapsed >= next_open) {
        next_open = elapsed + 2000;
        handle = pad_attempt(&user_id);
      }
    } else {
      read_pad(handle, &data, &buttons, &last_err, &intercepted,
               &presses, &errors);
    }
  }

  if(handle >= 0) {
    scePadClose(handle);
    handle = -1;
    report("stop after %d s, presses %d, errors %d, controller released",
           SPIKE_SECONDS, presses, errors);
  } else {
    report("stop after %d s, presses %d, errors %d, controller never opened",
           SPIKE_SECONDS, presses, errors);
  }

  for(int i=0; i<SPIKE_MAX_CLIENTS; i++) {
    if(client_fds[i] >= 0) {
      close(client_fds[i]);
      client_fds[i] = -1;
    }
  }

  close(srvfd);
  sceUserServiceTerminate();

  return 0;
}


/**
 * Entry point.
 **/
int
main(void) {
  return spike_run();
}
