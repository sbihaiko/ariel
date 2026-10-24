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
 * While a title is in the foreground, attaches to its eboot.bin and reads
 * the controller there. Reports button presses and error codes as console
 * notifications and on a TCP port. The payload stops on its own and closes
 * its sockets. The title's pad handle is left open.
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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "notify.h"
#include "pad.h"
#include "pt.h"


#define SPIKE_PORT        9150
#define SPIKE_SECONDS     30

/**
 * Marks the process as a fully privileged system app for every credential
 * check. GhostControl reads the pad with this authid.
 **/
#define SPIKE_AUTHID 0x3800000000010003ULL
#define SPIKE_FRAME_MS    16
#define SPIKE_MAX_CLIENTS 4
#define SPIKE_TRANSCRIPT  4096
#define SPIKE_LINE        512

/** Name ids of the pad functions inside the process that holds the pad. **/
#define SPIKE_NID_GETHANDLE "u1GRHp+oWoY"
#define SPIKE_NID_READSTATE "YndgXqQVV7c"

/** Thread or command name of a launched title. **/
#define SPIKE_TITLE_NAME    "eboot.bin"
#define SPIKE_TITLES        16
#define SPIKE_APPINFO       128


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

/** The title the last successful probe attached to. **/
static pid_t    title_pid = -1;
static intptr_t title_read_state = 0;
static int      title_local_ok = 0;
static pad_data_t title_sample;
static int      title_sample_err = 0;
static int      title_sample_ready = 0;

int sceKernelGetAppInfo(pid_t pid, void* info);
int sceSystemServiceGetAppIdOfRunningBigApp(void);


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
 * One launched title. app_id is the first word sceKernelGetAppInfo writes.
 * title_off is where a title id string sits in that buffer, or -1.
 **/
typedef struct title_proc {
  pid_t    pid;
  uint32_t app_id;
  int      title_off;
  char     title_id[16];
} title_proc_t;


/**
 * True when the process entry contains name as its own string.
 *
 * The pid sits at byte 72, as in find_pid in shsrv.c. The name is not taken
 * from a fixed offset: a title's thread name and its command name are not
 * the same field, and either one may be eboot.bin.
 **/
static int
entry_named(const uint8_t* entry, int size, const char* name) {
  size_t len = strlen(name);

  if(size <= (int)len) {
    return 0;
  }

  for(int i=0; i + (int)len < size; i++) {
    if(!memcmp(entry + i, name, len) && entry[i + len] == '\0') {
      return 1;
    }
  }

  return 0;
}


/**
 * Offset of a title id (four letters and five digits) in an app-info buffer.
 **/
static int
title_id_offset(const uint8_t* raw, size_t size) {
  if(size < 10) {
    return -1;
  }

  for(size_t i=0; i + 10 <= size; i++) {
    int letters = 1;
    int digits = 1;

    for(int c=0; c<4; c++) {
      if(raw[i + c] < 'A' || raw[i + c] > 'Z') {
        letters = 0;
      }
    }
    for(int c=4; c<9; c++) {
      if(raw[i + c] < '0' || raw[i + c] > '9') {
        digits = 0;
      }
    }
    if(letters && digits && raw[i + 9] == '\0') {
      return (int)i;
    }
  }

  return -1;
}


/**
 * Every eboot.bin except this payload. The same pid is kept once.
 **/
static int
find_titles(title_proc_t* out, int cap) {
  int mib[4] = {1, 14, 8, 0};
  size_t buf_size;
  uint8_t* buf;
  int count = 0;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    report("process list error %d", errno);
    return -1;
  }
  if(!(buf = malloc(buf_size))) {
    return -1;
  }
  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    free(buf);
    report("process list error %d", errno);
    return -1;
  }

  for(uint8_t* ptr=buf; ptr + 8 < buf + buf_size;) {
    int size = *(int*)ptr;
    pid_t pid;
    int seen = 0;

    if(size < 80 || ptr + size > buf + buf_size) {
      break;
    }

    pid = *(pid_t*)&ptr[72];
    if(entry_named(ptr, size, SPIKE_TITLE_NAME) &&
       pid > 0 && pid != getpid()) {
      for(int i=0; i<count; i++) {
        if(out[i].pid == pid) {
          seen = 1;
        }
      }
      if(!seen && count < cap) {
        uint8_t raw[SPIKE_APPINFO];
        int off;

        memset(&out[count], 0, sizeof out[count]);
        memset(raw, 0, sizeof raw);
        out[count].pid = pid;
        out[count].title_off = -1;
        if(!sceKernelGetAppInfo(pid, raw)) {
          memcpy(&out[count].app_id, raw, sizeof out[count].app_id);
          off = title_id_offset(raw, sizeof raw);
          out[count].title_off = off;
          if(off >= 0) {
            memcpy(out[count].title_id, raw + off, 9);
            out[count].title_id[9] = '\0';
          }
        }
        count++;
      }
    }

    ptr += size;
  }

  free(buf);
  return count;
}


/**
 * Say which big app is in front, once per distinct answer.
 **/
static void
report_big_app(int app_id) {
  static int seen = 0;
  static int last = 0;

  if(seen && app_id == last) {
    return;
  }
  seen = 1;
  last = app_id;
  if(app_id > 0) {
    report("running big app 0x%08x", (unsigned int)app_id);
  } else {
    report("no running big app (0x%08x)", (unsigned int)app_id);
  }
}


/**
 * Say which titles exist, once per distinct set.
 **/
static void
report_titles(const title_proc_t* titles, int count) {
  static char last[512];
  char sig[512];
  size_t len = 0;

  sig[0] = '\0';
  for(int i=0; i<count; i++) {
    char piece[80];
    int wrote = snprintf(piece, sizeof piece, "%d:%x:%s;",
                         (int)titles[i].pid, titles[i].app_id,
                         titles[i].title_id);

    if(wrote < 0 || len + (size_t)wrote >= sizeof sig) {
      break;
    }
    memcpy(sig + len, piece, (size_t)wrote);
    len += (size_t)wrote;
    sig[len] = '\0';
  }

  if(!strcmp(sig, last)) {
    return;
  }
  memcpy(last, sig, len + 1);

  if(count == 0) {
    report("no eboot.bin process");
    return;
  }

  for(int i=0; i<count; i++) {
    report("eboot pid %d app 0x%08x title %s off %d",
           (int)titles[i].pid, titles[i].app_id,
           titles[i].title_id[0] ? titles[i].title_id : "(none)",
           titles[i].title_off);
  }
}


/**
 * The three user ids the shell probe already used. Logged once.
 **/
static void
load_candidates(int* user_id, int* candidates) {
  static int ready = 0;
  static int saved[3];
  int users[PAD_LOGIN_USERS];
  int foreground = PAD_USER_INVALID;

  if(ready) {
    candidates[0] = saved[0];
    candidates[1] = saved[1];
    candidates[2] = saved[2];
    *user_id = saved[1];
    return;
  }

  for(int i=0; i<PAD_LOGIN_USERS; i++) {
    users[i] = PAD_USER_INVALID;
  }
  if(!sceUserServiceGetLoginUserIdList(users) &&
     users[0] != PAD_USER_INVALID) {
    *user_id = users[0];
  }
  if(!sceUserServiceGetForegroundUser(&foreground) &&
     foreground != PAD_USER_INVALID) {
    *user_id = foreground;
  }

  saved[0] = 1;
  saved[1] = *user_id > 0 ? *user_id : 0;
  saved[2] = 0x10000000;
  ready = 1;
  candidates[0] = saved[0];
  candidates[1] = saved[1];
  candidates[2] = saved[2];
  report("user candidates %d %d %d", saved[0], saved[1], saved[2]);
}


/**
 * Resolve the pad exports in the title. Repeat reports are suppressed.
 **/
static int
resolve_pad(pid_t pid, intptr_t* get_handle, intptr_t* read_state) {
  static pid_t last_pid = -1;
  static intptr_t last_get = 0;
  static intptr_t last_read = 0;
  static int last_missing = -1;
  uint32_t lib = 0;
  int missing;

  *get_handle = 0;
  *read_state = 0;
  missing = kernel_dynlib_handle(pid, "libScePad.sprx", &lib);
  if(!missing) {
    *get_handle = kernel_dynlib_resolve(pid, lib, SPIKE_NID_GETHANDLE);
    *read_state = kernel_dynlib_resolve(pid, lib, SPIKE_NID_READSTATE);
  }

  if(pid != last_pid || *get_handle != last_get ||
     *read_state != last_read || missing != last_missing) {
    last_pid = pid;
    last_get = *get_handle;
    last_read = *read_state;
    last_missing = missing;
    if(missing) {
      report("title pid %d libScePad.sprx not found (%d)", (int)pid, errno);
    } else {
      report("title pid %d getHandle %p readState %p", (int)pid,
             (void*)*get_handle, (void*)*read_state);
    }
  }

  return (*get_handle && *read_state) ? 0 : -1;
}


/**
 * Ask the title for the handle it already holds.
 *
 * Port type 1 is not a port type. Port type 3 and the extra indexes belong
 * to the next experiment, so this probe stays on types 0 and 2, index 0.
 **/
static int
probe_handles(pid_t pid, intptr_t get_handle, int* user_id, int* candidates) {
  static pid_t logged_pid = -1;
  static const int types[2] = {
    PAD_PORT_TYPE_STANDARD,
    PAD_PORT_TYPE_SPECIAL
  };
  int handle = -1;
  int first = pid != logged_pid;

  if(first) {
    logged_pid = pid;
  }

  for(int u=0; u<3 && handle < 0; u++) {
    for(int t=0; t<2 && handle < 0; t++) {
      int got = (int)pt_call(pid, get_handle, (uint64_t)candidates[u],
                             (uint64_t)types[t], 0, 0, 0, 0);

      if(first || got >= 0) {
        report("title getHandle user %d type %d -> 0x%08x",
               candidates[u], types[t], (unsigned int)got);
      }
      if(got >= 0) {
        handle = got;
        *user_id = candidates[u];
      }
    }
  }

  return handle;
}


/**
 * Copy one pad sample out of the title. The caller is already attached.
 * Returns 0 when the sample was copied, whatever scePadReadState returned.
 **/
static int
read_attached(pid_t pid, intptr_t read_state, int handle, pad_data_t* data,
              int* sce_err) {
  intptr_t remote;
  long err;

  remote = pt_mmap(pid, 0, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
  if(remote == (intptr_t)-1 || remote == 0) {
    report("title mmap failed 0x%lx", (unsigned long)remote);
    return -1;
  }

  err = pt_call(pid, read_state, (uint64_t)handle, (uint64_t)remote,
                0, 0, 0, 0);
  if(pt_copyout(pid, remote, data, sizeof *data)) {
    report("title copyout failed (%d)", errno);
    pt_munmap(pid, remote, 4096);
    return -1;
  }

  pt_munmap(pid, remote, 4096);
  *sce_err = (int)err;
  return 0;
}


/**
 * Read the pad from inside the foreground title.
 *
 * scePadOpen in this process, and scePadGetHandle inside SceShellCore, both
 * failed on the home screen. A title is a registered pad client, so the
 * handle is looked up there. The handle is not closed: it belongs to the
 * title.
 **/
static int
pad_from_title(int* user_id) {
  title_proc_t titles[SPIKE_TITLES];
  int match[SPIKE_TITLES];
  int candidates[3];
  int big;
  int count;
  int matches = 0;
  int exact = 0;

  big = sceSystemServiceGetAppIdOfRunningBigApp();
  report_big_app(big);
  if(big <= 0) {
    return -1;
  }

  count = find_titles(titles, SPIKE_TITLES);
  if(count < 0) {
    return -1;
  }
  report_titles(titles, count);

  for(int i=0; i<count; i++) {
    if((int)titles[i].app_id == big) {
      match[matches++] = i;
      exact = 1;
    }
  }
  if(!exact) {
    static int fallback_app = 0;

    matches = 0;
    for(int i=0; i<count; i++) {
      if(titles[i].title_id[0] &&
         strncmp(titles[i].title_id, "NPXS", 4) != 0) {
        match[matches++] = i;
      }
    }
    if(matches > 0 && fallback_app != big) {
      fallback_app = big;
      report("no eboot app id matches 0x%08x, trying non-system titles",
             (unsigned int)big);
    }
  }
  if(matches == 0) {
    return -1;
  }

  load_candidates(user_id, candidates);

  for(int m=0; m<matches; m++) {
    title_proc_t* title = &titles[match[m]];
    intptr_t get_handle = 0;
    intptr_t read_state = 0;
    int handle;

    if(resolve_pad(title->pid, &get_handle, &read_state)) {
      continue;
    }
    if(pt_attach(title->pid)) {
      static pid_t failed_pid = -1;
      static int failed_err = 0;

      if(failed_pid != title->pid || failed_err != errno) {
        failed_pid = title->pid;
        failed_err = errno;
        report("title pid %d attach failed (%d)", (int)title->pid, errno);
      }
      continue;
    }

    handle = probe_handles(title->pid, get_handle, user_id, candidates);
    if(handle >= 0) {
      memset(&title_sample, 0, sizeof title_sample);
      if(!read_attached(title->pid, read_state, handle, &title_sample,
                        &title_sample_err)) {
        title_sample_ready = 1;
        report("title readState -> 0x%08x buttons 0x%08x connected %u",
               (unsigned int)title_sample_err, title_sample.buttons,
               title_sample.connected);
      }
      title_pid = title->pid;
      title_read_state = read_state;
    }
    pt_detach(title->pid, 0);

    if(handle >= 0) {
      pad_data_t local;
      int init_err;
      int local_err;

      init_err = scePadInit();
      memset(&local, 0, sizeof local);
      local_err = scePadReadState(handle, &local);
      title_local_ok = local_err >= 0;
      report("payload init 0x%08x readState 0x%08x buttons 0x%08x connected %u",
             (unsigned int)init_err, (unsigned int)local_err,
             title_local_ok ? local.buttons : 0,
             title_local_ok ? local.connected : 0);
      return handle;
    }
  }

  return -1;
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
 * Report what changed in a pad sample that was already read.
 **/
static void
report_read(int err, pad_data_t* data, unsigned int* buttons,
            unsigned int* last_err, int* intercepted, int* presses,
            int* errors) {
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
 * Read the controller once in this process and report what changed.
 **/
static void
read_pad(int handle, pad_data_t* data, unsigned int* buttons,
         unsigned int* last_err, int* intercepted, int* presses, int* errors) {
  memset(data, 0, sizeof *data);
  report_read(scePadReadState(handle, data), data, buttons, last_err,
              intercepted, presses, errors);
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
 * Give this process the credentials a system app has.
 *
 * sceUserService refuses a process that still carries the credentials of
 * the ELF loader's parent, which is what produces USER_NOT_LOGIN. ProsperoMgr
 * raises them the same way before it calls sceUserService.
 **/
static void
raise_credentials(void) {
  pid_t pid = getpid();
  intptr_t root;
  uint8_t caps[16];
  uint8_t attrs[32];
  int failed = 0;

  if(!kernel_get_proc(pid)) {
    report("credentials: kernel read/write is not available");
    return;
  }

  failed |= kernel_set_ucred_uid(pid, 0);
  failed |= kernel_set_ucred_ruid(pid, 0);
  failed |= kernel_set_ucred_svuid(pid, 0);
  failed |= kernel_set_ucred_rgid(pid, 0);
  failed |= kernel_set_ucred_svgid(pid, 0);

  root = kernel_get_root_vnode();
  if(root) {
    failed |= kernel_set_proc_rootdir(pid, root);
    failed |= kernel_set_proc_jaildir(pid, root);
  }

  failed |= kernel_set_ucred_authid(pid, SPIKE_AUTHID);

  memset(caps, 0xff, sizeof caps);
  failed |= kernel_set_ucred_caps(pid, caps);

  memset(attrs, 0, sizeof attrs);
  attrs[0] = 0x80;
  failed |= kernel_set_ucred_attrs(pid, attrs);

  if(failed) {
    report("credentials: one or more kernel_set_ucred calls failed");
  } else {
    report("credentials raised");
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
  long next_read = 0;
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

  raise_credentials();

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
        handle = pad_from_title(&user_id);
        if(handle >= 0 && title_sample_ready) {
          report_read(title_sample_err, &title_sample, &buttons, &last_err,
                      &intercepted, &presses, &errors);
          title_sample_ready = 0;
          next_read = elapsed + 1000;
        }
      }
    } else if(title_local_ok) {
      read_pad(handle, &data, &buttons, &last_err, &intercepted,
               &presses, &errors);
    } else if(elapsed >= next_read) {
      int sce_err = 0;

      next_read = elapsed + 1000;
      if(pt_attach(title_pid)) {
        report("title pid %d attach failed (%d)", (int)title_pid, errno);
        handle = -1;
        next_open = elapsed + 2000;
      } else {
        memset(&data, 0, sizeof data);
        if(read_attached(title_pid, title_read_state, handle, &data,
                         &sce_err)) {
          pt_detach(title_pid, 0);
          handle = -1;
          next_open = elapsed + 2000;
        } else {
          pt_detach(title_pid, 0);
          report_read(sce_err, &data, &buttons, &last_err, &intercepted,
                      &presses, &errors);
        }
      }
    }
  }

  if(handle >= 0) {
    report("stop after %d s, presses %d, errors %d, title handle left open",
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
