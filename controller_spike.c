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

#include <dirent.h>
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
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "notify.h"
#include "pad.h"
#include "pt.h"


#define SPIKE_PORT        9150
#define SPIKE_SECONDS     120

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
#define SPIKE_SHELL         "SceShellCore"


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


#define PAD_HOME_DIR "/system_data/priv/home"


/**
 * Collect the user ids from the home directories, which name each logged-in
 * account by its id in hex. The user service calls do not return one.
 **/
static int
home_users(int* users, int cap) {
  DIR* dir;
  struct dirent* ent;
  int count = 0;

  dir = opendir(PAD_HOME_DIR);
  if(!dir) {
    report("home dir error %d", errno);
    return 0;
  }

  while((ent = readdir(dir))) {
    char* end = NULL;
    long id;

    if(ent->d_name[0] == '.') {
      continue;
    }
    id = strtol(ent->d_name, &end, 16);
    if(end == ent->d_name || *end != '\0' || id < 0) {
      continue;
    }
    report("home user %ld (%s)", id, ent->d_name);
    if(count < cap) {
      users[count++] = (int)id;
    }
  }

  closedir(dir);
  return count;
}


/**
 * The pid of a process with the given name, or -1.
 *
 * The layout matches find_pid in shsrv.c: the struct size at the start of
 * each entry, the pid at byte 72 and the thread name at byte 447.
 **/
static pid_t
find_process(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t pid = -1;
  size_t buf_size;
  uint8_t* buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    report("process list error %d", errno);
    return -1;
  }
  if(!(buf = malloc(buf_size))) {
    return -1;
  }
  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    free(buf);
    return -1;
  }

  for(uint8_t* ptr = buf; ptr < buf + buf_size;) {
    int size = *(int*)ptr;
    pid_t found = *(pid_t*)&ptr[72];
    char* thread = (char*)&ptr[447];

    ptr += size;
    if(!strcmp(name, thread) && found != getpid()) {
      pid = found;
    }
  }

  free(buf);
  return pid;
}


/**
 * Read the controller from inside the process that already holds it.
 *
 * A payload is not a registered pad client, so scePadOpen refuses it. The
 * shell is a client. Attaching to it and calling scePadGetHandle there
 * borrows the handle the console gave it.
 **/
static int
pad_from_shell(int* user_id) {
  pid_t pid;
  intptr_t get_handle;
  intptr_t read_state;
  int handle = -1;

  pid = find_process(SPIKE_SHELL);
  if(pid < 0) {
    report("no %s process", SPIKE_SHELL);
    return -1;
  }
  report("%s pid %d", SPIKE_SHELL, pid);

  {
    uint32_t handle = 0;

    if(kernel_dynlib_handle(pid, "libScePad.sprx", &handle)) {
      report("libScePad.sprx not found (%d)", errno);
      return -1;
    }
    get_handle = kernel_dynlib_resolve(pid, handle, SPIKE_NID_GETHANDLE);
    read_state = kernel_dynlib_resolve(pid, handle, SPIKE_NID_READSTATE);
  }
  report("resolved getHandle %p readState %p",
         (void*)get_handle, (void*)read_state);
  if(!get_handle || !read_state) {
    return -1;
  }

  if(pt_attach(pid)) {
    report("attach failed (%d)", errno);
    return -1;
  }

  {
    int candidates[3];

    candidates[0] = 1;
    candidates[1] = *user_id;
    candidates[2] = 0x10000000;
    for(int i=0; i<3 && handle < 0; i++) {
      int got = (int)pt_call(pid, get_handle, (uint64_t)candidates[i],
                             (uint64_t)PAD_PORT_TYPE_STANDARD, 0);
      report("shell getHandle user %d -> 0x%08x", candidates[i],
             (unsigned int)got);
      if(got >= 0) {
        handle = got;
        *user_id = candidates[i];
      }
    }
  }

  pt_detach(pid, 0);

  if(handle < 0) {
    return -1;
  }
  return handle;
}


/**
 * Report the name the console stores for a user, so the operator can tell
 * which account the id belongs to.
 **/
static void
report_user_name(int user) {
  char name[32];
  int err;

  memset(name, 0, sizeof name);
  err = sceUserServiceGetUserName(user, name, sizeof name);
  if(err) {
    report("user %d name error 0x%08x", user, (unsigned int)err);
    return;
  }
  report("user %d name %s", user, name[0] ? name : "(empty)");

  /**
   * The sign-in flag lives in the registry, one entity per account slot.
   * Slot 1 is the base; each next slot adds 65536.
   **/
  for(int slot=1; slot<=16; slot++) {
    int value = 0;
    int entity = 125874185 + (slot - 1) * 65536;

    err = sceRegMgrGetInt(entity, &value);
    if(err) {
      report("sign-in slot %d error 0x%08x", slot, (unsigned int)err);
      break;
    }
    if(value) {
      report("sign-in slot %d value %d", slot, value);
    }
  }

  {
    char path[64];
    struct stat st;

    snprintf(path, sizeof path, "/system_data/priv/home/%x/np/auth.dat", user);
    if(stat(path, &st) == 0) {
      report("auth.dat present, %ld bytes", (long)st.st_size);
    } else {
      report("auth.dat absent (%d)", errno);
    }
  }
}


/**
 * Open the controller for one user, by opening a handle or by borrowing one.
 **/
static int
pad_try(const char* label, int user, int type, int borrow) {
  int handle;

  if(user < 0) {
    return -1;
  }

  handle = borrow ? scePadGetHandle(user, type, 0)
                  : scePadOpen(user, type, 0, NULL);
  if(handle < 0) {
    if((unsigned int)handle != open_error) {
      open_error = (unsigned int)handle;
      report("%s user %d type %d error 0x%08x", label, user, type, open_error);
    }
    return -1;
  }

  open_error = 0;
  report("%s ok user %d handle %d", label, user, handle);
  return handle;
}


/**
 * Open the controller for the console's logged-in user.
 *
 * scePadOpen only accepts a user that is logged in, and it rejects anything
 * else with USER_NOT_LOGIN. GetInitialUser fails in a payload and the
 * foreground user is not a logged-in user, so the login list is the source.
 * Borrowing an existing handle covers the case where the system already
 * holds the controller.
 **/
static int
pad_attempt(int* user_id) {
  int users[PAD_LOGIN_USERS];
  int err;
  int handle = -1;
  int chosen = PAD_USER_INVALID;

  err = scePadInit();
  if(err) {
    report_error("init", (unsigned int)err, &init_error);
  } else if(init_error) {
    init_error = 0;
    report("init ok");
  }

  err = scePadSetProcessPrivilege(1);
  if(err) {
    report_error("privilege", (unsigned int)err, &user_error);
  }

  for(int i=0; i<PAD_LOGIN_USERS; i++) {
    users[i] = PAD_USER_INVALID;
  }

  if(home_users(users, PAD_LOGIN_USERS) == 0) {
    err = sceUserServiceGetLoginUserIdList(users);
    if(err) {
      report_error("login list", (unsigned int)err, &user_error);
    }
  }

  if(users[0] != PAD_USER_INVALID) {
    *user_id = users[0];
    handle = pad_from_shell(user_id);
    if(handle >= 0) {
      return handle;
    }
  }

  for(int i=0; i<PAD_LOGIN_USERS && handle < 0; i++) {
    if(users[i] == PAD_USER_INVALID) {
      continue;
    }
    report_user_name(users[i]);
    for(int type=0; type<PAD_PORT_TYPE_COUNT && handle < 0; type++) {
      handle = pad_try("open", users[i], type, 0);
      if(handle < 0) {
        handle = pad_try("borrow", users[i], type, 1);
      }
    }
    if(handle >= 0) {
      chosen = users[i];
    }
  }

  if(handle < 0) {
    int foreground = PAD_USER_INVALID;

    err = sceUserServiceGetForegroundUser(&foreground);
    if(!err && foreground != PAD_USER_INVALID) {
      for(int type=0; type<PAD_PORT_TYPE_COUNT && handle < 0; type++) {
        handle = pad_try("open foreground", foreground, type, 0);
        if(handle < 0) {
          handle = pad_try("borrow foreground", foreground, type, 1);
        }
      }
      if(handle >= 0) {
        chosen = foreground;
      }
    }
  }

  if(handle < 0) {
    return -1;
  }

  *user_id = chosen;
  user_error = 0;
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
