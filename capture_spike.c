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
 * Capture spike payload (issue #55).
 *
 * Loads the system's screen-shot client library into this process, resolves
 * its exported functions and tries one capture, writing the outcome to
 * /data/capture-spike.log after every step so a crash still says where it
 * died. It changes no product code and is never linked into shsrv-ps5.elf.
 **/

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "notify.h"


#define SPIKE_LOG          "/data/capture-spike.log"
#define SPIKE_LIB          "/system/common/lib/libSceScreenShot.sprx"
#define SPIKE_LIB_SHORT    "libSceScreenShot.sprx"
#define SPIKE_TITLE        "Ariel capture spike"
#define SPIKE_COMMENT      "issue #55"
#define SPIKE_CAPTURE_SECONDS 20
#define SPIKE_PATH_MAX     1024

#define SPIKE_FLAG_PAD     0x00000000u
#define SPIKE_PARAM_SIZE   0x28u

/**
 * The parameter block the capture export reads, as its disassembly spells
 * it: a size that must be 0x28, then three strings, then a field it requires
 * to be null.
 **/
typedef struct capture_param {
  unsigned int  size;
  unsigned int  pad;
  const char   *first;
  const char   *second;
  const char   *third;
  const char   *reserved;
} capture_param_t;

/** Every export libSceScreenShot.sprx carries, as its symbol table names it. **/
static const char *nids[] = {
  "G7KlmIYFIZc", "ahHhOf+QNkQ", "73WQ4Jj0nJI", "tIYf0W5VTi8",
  "2xxUtuC-RzE", "-SV-oTNGFQk", "hNmK4SdhPT0", "ICNJ-1POs84",
  "VlAQIgXa2R0", "ysfza71rm9M", "BDUaqlVdSAY", "JuMLLmmvRgk",
  "itlWFWV3Tzc",
};

#define NID_COUNT (sizeof(nids) / sizeof(nids[0]))


/** The module loader and its symbol lookup, as libkernel exports them. **/
int sceKernelLoadStartModule(const char* name, unsigned int argn, void* argp,
                             unsigned int flags, void* opt, int* res);
int sceKernelDlsym(int handle, const char* nid, void** addr);


static int logfd = -1;
/** Whether the handle came from the loader, which resolves by its own call. **/
static int by_loader;

/** Where the system says it put the shot. **/
static char shot_path[SPIKE_PATH_MAX];


/** The capture blocks until the system answers: give up after a deadline. **/
static int
spy_cancel(void* arg) {
  time_t* deadline = arg;

  return time(0) >= *deadline;
}


static void* resolve_logged(void* handle, const char* nid);


static void
log_line(const char* fmt, ...) {
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
}


/**
 * Find one export and say how each lookup went. A loader handle answers to
 * its own call; the plain NID first, then the decorated name the symbol
 * table actually carries.
 **/
static void*
resolve_logged(void* handle, const char* nid) {
  intptr_t fn;

  if(by_loader) {
    // The kernel keeps the module's own symbol table; ask it, since the
    // userland lookup answers ESRCH for a module a payload loaded.
    fn = kernel_dynlib_resolve(getpid(), (uint32_t)(long)handle, nid);
    log_line("kernel_dynlib_resolve(%s) -> %p", nid, (void*)fn);
    return (void*)fn;
  }

  fn = (intptr_t)dlsym(handle, nid);
  log_line("dlsym(%s) fn %p", nid, (void*)fn);
  return (void*)fn;
}


int
main(void) {
  void* handle = 0;
  int   i;
  int   rc;
  void* fn = 0;
  capture_param_t param;
  time_t deadline;

  logfd = open(SPIKE_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  log_line("capture spike start");

  notify("Capture spike: loading libSceScreenShot");

  log_line("dlopen %s flags %#x", SPIKE_LIB, SPIKE_FLAG_PAD);
  handle = dlopen(SPIKE_LIB, SPIKE_FLAG_PAD);
  log_line("dlopen -> %p", handle);

  if(!handle) {
    log_line("dlerror: %s", dlerror());
    log_line("dlopen %s flags %#x", SPIKE_LIB_SHORT, SPIKE_FLAG_PAD);
    handle = dlopen(SPIKE_LIB_SHORT, SPIKE_FLAG_PAD);
    log_line("dlopen short -> %p", handle);
    if(!handle) {
      log_line("dlerror: %s", dlerror());
    }
  }

  if(!handle) {
    static const char* deps[] = {
      "/system/common/lib/libSceIpmi.sprx",
      "/system/common/lib/libSceSysUtil.sprx",
    };
    size_t n;

    log_line("dlopen is dead on a payload; try the module loader");
    by_loader = 1;

    for(n=0; n<sizeof(deps) / sizeof(deps[0]); n++) {
      int res = 0;
      int mh;

      log_line("dependency %s", deps[n]);
      mh = sceKernelLoadStartModule(deps[n], 0, 0, 0, 0, &res);
      log_line("dependency -> %d (%#x) res %d", mh, mh, res);
    }

    {
      int res = 0;
      int mh;

      log_line("sceKernelLoadStartModule(%s)", SPIKE_LIB);
      mh = sceKernelLoadStartModule(SPIKE_LIB, 0, 0, 0, 0, &res);
      log_line("sceKernelLoadStartModule -> %d (%#x) res %d", mh, mh, res);
      if(mh < 0) {
        mh = sceKernelLoadStartModule(SPIKE_LIB_SHORT, 0, 0, 0, 0, &res);
        log_line("retry with the short name -> %d (%#x) res %d",
                 mh, mh, res);
      }
      if(mh < 0) {
        notify("Capture spike: the library did not load");
        log_line("no handle, stopping");
        close(logfd);
        return 1;
      }

      log_line("mapbase %#lx",
               (long)kernel_dynlib_mapbase_addr(getpid(), (uint32_t)mh));
      handle = (void*)(long)mh;
    }
  }

  for(i=0; i<(int)NID_COUNT; i++) {
    fn = 0;
    fn = resolve_logged(handle, nids[i]);
  }

  // The metadata the shot is filed under: thisSize, photoTitle, gameTitle,
  // gameComment, reserved.
  memset(&param, 0, sizeof(param));
  param.size = SPIKE_PARAM_SIZE;
  param.first = SPIKE_TITLE;
  param.second = SPIKE_TITLE;
  param.third = SPIKE_COMMENT;

  log_line("call SetParam(%s, %s, %s)", param.first, param.second, param.third);
  fn = resolve_logged(handle, "G7KlmIYFIZc");
  if(fn) {
    rc = ((int (*)(const capture_param_t*))fn)(&param);
    log_line("SetParam() -> %d (%#x)", rc, rc);
  }
  log_line("survived SetParam");

  // Whether the system says capture is off at all: two flags, each written
  // through a pointer the function insists on.
  fn = resolve_logged(handle, "-SV-oTNGFQk");
  if(fn) {
    int disabled = -1;

    rc = ((int (*)(int*))fn)(&disabled);
    log_line("IsDisabled() -> %d (%#x), flag %d", rc, rc, disabled);
  }
  fn = resolve_logged(handle, "ICNJ-1POs84");
  if(fn) {
    int vsh_disabled = -1;

    rc = ((int (*)(int*))fn)(&vsh_disabled);
    log_line("IsVshScreenCaptureDisabled() -> %d (%#x), flag %d",
             rc, rc, vsh_disabled);
  }
  log_line("survived the flag queries");

  // The capture: a mode, a 1024-byte buffer the system fills with the path
  // it wrote, a cancel callback and its argument.
  fn = resolve_logged(handle, "JuMLLmmvRgk");
  for(i=0; i<2 && fn; i++) {
    memset(shot_path, 0, sizeof(shot_path));
    deadline = time(0) + SPIKE_CAPTURE_SECONDS;
    log_line("call Capture(mode %d, buf, cancel, deadline +%ds)", i,
             SPIKE_CAPTURE_SECONDS);
    rc = ((int (*)(int, char*, int (*)(void*), void*))fn)(i, shot_path,
                                                          spy_cancel, &deadline);
    log_line("Capture(mode %d) -> %d (%#x) path \"%s\"", i, rc, rc, shot_path);
    notify("Capture spike: mode %d answered %#x", i, rc);
    log_line("survived Capture(mode %d)", i);
  }

  log_line("capture spike end");
  close(logfd);
  return 0;
}
