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
 * Share spike payload (issue #100).
 *
 * The screenshot client in libSceScreenShot wedges the console and never
 * completes a capture (#55, #53). This spike tries the other route the system
 * offers: the share library, whose capture exports the system's own share
 * feature serves rather than the VSH IPC client. It loads the library into
 * this process, resolves its exports and asks for one screenshot, writing the
 * outcome to /data/share-spike.log after every step so a wedge still says
 * where it died. It changes no product code and is never linked into
 * shsrv-ps5.elf.
 **/

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "notify.h"


#define SPIKE_LOG      "/data/share-spike.log"
#define SPIKE_LIB      "/system/common/lib/libSceShare.native.sprx"
#define SPIKE_LIB_SHORT "libSceShare.native.sprx"

/** The request id the capture calls answer with, when they answer. **/
#define SHARE_REQUEST_ID_INVALID (-1)

/** sceShareInitialize(heap, priority, affinity). The export rejects a heap
    below 0x20000 with INVALID_PARAM before it calls anyone, and treats
    ALREADY_INITIALIZED (0x8196000D) as success. **/
#define SHARE_HEAP_SIZE     0x20000u
#define SHARE_THREAD_PRIO   700
#define SHARE_AFFINITY_NONE 0ull

/** The feature flags sceShareGetCurrentStatus and sceShareFeaturePermit take.
    0x1 is video recording; a screenshot is 0x2. **/
#define SHARE_FEATURE_SCREENSHOT 0x2u

/** The exports this spike asks for, by the NID the library carries. **/
static const char *nids[] = {
  "nBDD66kiFW8",  /* ShareInitialize **/
  "0IL1keINExQ",  /* ShareTerminate **/
  "QNop2YAtIDE",  /* ShareGetCurrentStatus **/
  "crFxyW3HdK0",  /* ShareGetRunningStatus **/
  "kCurUZVFqcI",  /* ShareSetCaptureSource **/
  "ErH6tKS7fzE",  /* ShareCaptureScreenshot **/
  "GQTObcITIXI",  /* ShareCaptureScreenshotExtended **/
  "YBiIdcDPrxs",  /* ShareFeaturePermit **/
  "5wjxESwX68I",  /* ShareFeatureProhibit **/
};

#define NID_COUNT (sizeof(nids) / sizeof(nids[0]))

/** The status block ShareGetCurrentStatus fills: sixteen bytes, as the
    reimplementation that named these exports spells it. **/
typedef struct share_status {
  unsigned char bytes[16];
} share_status_t;


/** The module loader and its symbol lookup, as libkernel exports them. **/
int sceKernelLoadStartModule(const char* name, unsigned int argn, void* argp,
                             unsigned int flags, void* opt, int* res);
int sceKernelDlsym(int handle, const char* nid, void** addr);


static int logfd = -1;
/** Whether the handle came from the loader, which resolves by its own call. **/
static int by_loader;


static void*
resolve_logged(void* handle, const char* nid);


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
 * Find one export and say how the lookup went. A loader handle answers to
 * its own call: the userland lookup answers ESRCH for a module a payload
 * loaded.
 **/
static void*
resolve_logged(void* handle, const char* nid) {
  intptr_t fn;

  if(by_loader) {
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
  void* fn = 0;
  int   rc;
  int   i;
  int32_t req_id;
  share_status_t status;
  struct {
    unsigned char bytes[0x40];
  } capture;

  logfd = open(SPIKE_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  log_line("share spike start");

  notify("Share spike: loading libSceShare");
  log_line("dlopen %s", SPIKE_LIB);
  handle = dlopen(SPIKE_LIB, 0);
  log_line("dlopen -> %p", handle);
  if(!handle) {
    log_line("dlerror: %s", dlerror());
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

      mh = sceKernelLoadStartModule(deps[n], 0, 0, 0, 0, &res);
      log_line("dependency %s -> %d res %d", deps[n], mh, res);
    }

    {
      int res = 0;
      int mh;

      log_line("sceKernelLoadStartModule(%s)", SPIKE_LIB);
      mh = sceKernelLoadStartModule(SPIKE_LIB, 0, 0, 0, 0, &res);
      log_line("sceKernelLoadStartModule -> %d (%#x) res %d", mh, mh, res);
      if(mh < 0) {
        mh = sceKernelLoadStartModule(SPIKE_LIB_SHORT, 0, 0, 0, 0, &res);
        log_line("retry with the short name -> %d (%#x) res %d", mh, mh, res);
      }
      if(mh < 0) {
        notify("Share spike: the library did not load");
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
    resolve_logged(handle, nids[i]);
  }

  // Every call made before this one answered NOT_INITIALIZED (0x8196000C),
  // which is the library saying it was never started, not that the feature
  // is denied. The heap, the priority and the affinity are the defaults a
  // title passes.
  fn = resolve_logged(handle, "nBDD66kiFW8");
  if(fn) {
    log_line("call Initialize(heap %#x, prio %d, affinity 0)",
             (unsigned)SHARE_HEAP_SIZE, SHARE_THREAD_PRIO);
    rc = ((int (*)(size_t, int, uint64_t))fn)(SHARE_HEAP_SIZE,
                                              SHARE_THREAD_PRIO,
                                              SHARE_AFFINITY_NONE);
    log_line("Initialize() -> %d (%#x)", rc, rc);
    log_line("survived Initialize");
  }

  // A read first: the status call takes a feature flag and a status block,
  // and a bad flag answers an error rather than touching the client. The
  // screenshot feature is 0x2; 0x1 is video recording.
  memset(&status, 0, sizeof(status));
  fn = resolve_logged(handle, "QNop2YAtIDE");
  if(fn) {
    log_line("call GetCurrentStatus(flag 0x2, status, 16 bytes)");
    rc = ((int (*)(uint32_t, share_status_t*))fn)(SHARE_FEATURE_SCREENSHOT,
                                                  &status);
    log_line("GetCurrentStatus() -> %d (%#x), status %02x%02x%02x%02x",
             rc, rc, status.bytes[0], status.bytes[1], status.bytes[2],
             status.bytes[3]);
    log_line("survived GetCurrentStatus");
  }

  // The capture, with no parameter block first: the reimplementation answers
  // NOT_SUPPORTED for a null one, so a null is a bound the console can judge.
  fn = resolve_logged(handle, "ErH6tKS7fzE");
  if(fn) {
    req_id = SHARE_REQUEST_ID_INVALID;
    log_line("call CaptureScreenshot(param null, req_id)");
    rc = ((int (*)(const void*, int32_t*))fn)(0, &req_id);
    log_line("CaptureScreenshot(null) -> %d (%#x) req %d", rc, rc, req_id);
    log_line("survived CaptureScreenshot(null)");
  }

  fn = resolve_logged(handle, "GQTObcITIXI");
  if(fn) {
    req_id = SHARE_REQUEST_ID_INVALID;
    log_line("call CaptureScreenshotExtended(param null, req_id)");
    rc = ((int (*)(const void*, int32_t*))fn)(0, &req_id);
    log_line("CaptureScreenshotExtended(null) -> %d (%#x) req %d",
             rc, rc, req_id);
    log_line("survived CaptureScreenshotExtended(null)");
  }

  // The disassembly of the export rejects a null block and requires bytes
  // 0x08 to 0x1f to be zero, with a kind word at 0x04 compared against 2: a
  // zeroed block of 0x40 bytes is the smallest thing that passes.
  fn = resolve_logged(handle, "ErH6tKS7fzE");
  if(fn) {
    memset(&capture, 0, sizeof(capture));
    req_id = SHARE_REQUEST_ID_INVALID;
    log_line("call CaptureScreenshot(zeroed 0x40, req_id)");
    rc = ((int (*)(const void*, int32_t*))fn)(&capture, &req_id);
    log_line("CaptureScreenshot(zeroed) -> %d (%#x) req %d", rc, rc, req_id);
    log_line("survived CaptureScreenshot(zeroed)");
  }

  // The status and the capture both answer 0x8196000C, which reads as the
  // share feature being unavailable to this process. The library also carries
  // a permit and a prohibit for feature flags: ask for the flag the status
  // call was given, then read the status and ask for a capture once more.
  fn = resolve_logged(handle, "YBiIdcDPrxs");
  if(fn) {
    log_line("call FeaturePermit(flag 0x2)");
    rc = ((int (*)(unsigned int))fn)(SHARE_FEATURE_SCREENSHOT);
    log_line("FeaturePermit(0x2) -> %d (%#x)", rc, rc);
    log_line("survived FeaturePermit");
  }

  memset(&status, 0, sizeof(status));
  fn = resolve_logged(handle, "QNop2YAtIDE");
  if(fn) {
    log_line("call GetCurrentStatus(flag 0x2) after the permit");
    rc = ((int (*)(uint32_t, share_status_t*))fn)(SHARE_FEATURE_SCREENSHOT,
                                                  &status);
    log_line("GetCurrentStatus() -> %d (%#x), status %02x%02x%02x%02x",
             rc, rc, status.bytes[0], status.bytes[1], status.bytes[2],
             status.bytes[3]);
  }

  fn = resolve_logged(handle, "ErH6tKS7fzE");
  if(fn) {
    memset(&capture, 0, sizeof(capture));
    req_id = SHARE_REQUEST_ID_INVALID;
    log_line("call CaptureScreenshot(zeroed 0x40) after the permit");
    rc = ((int (*)(const void*, int32_t*))fn)(&capture, &req_id);
    log_line("CaptureScreenshot(after permit) -> %d (%#x) req %d",
             rc, rc, req_id);
    log_line("survived CaptureScreenshot(after permit)");
  }

  log_line("share spike end");
  close(logfd);
  return 0;
}
