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
 * System spike (issue #135, the spike behind #133).
 *
 * A separate payload. It is never linked into ariel-ps5.elf. The operator
 * sends it to the ELF loader, which copies this process's standard output
 * back over the deploy connection.
 *
 * Answers what no command should be designed on before it is known: does a
 * payload reach the console's own shutdown path, and does the console go off,
 * unmount its removable volumes and come back closed?
 *
 * One candidate per run, because a candidate that works ends the console and
 * takes the rest of the run with it:
 *
 *   system-spike list       what each candidate is, and what it will be called with
 *   system-spike read       the calls that only read state, safe to run twice
 *   system-spike shutdown   sceShellCoreUtilRequestShutdown
 *   system-spike poweroff   sceSystemServiceRequestPowerOff
 *   system-spike reboot     sceSystemServiceRequestReboot
 *   system-spike statreboot sceSystemStateMgrReboot
 *   system-spike sysreboot  sceApplicationSystemReboot, the call the shell
 *                           itself makes on the way down
 *   system-spike syscall    reboot(RB_AUTOBOOT), the route the agent uses today
 *
 * Every mode writes each line to the file named by SPIKE_LOG as well as to the
 * standard output, and fsyncs the file before the candidate is called: a
 * candidate that ends the console ends the connection with it, so the record
 * has to be on the disk before the call, not after it.
 *
 * The SDK ships no header for these symbols, so they are declared here with a
 * single pointer parameter. The candidates are believed to take no argument or
 * one; passing a pointer to a zeroed buffer is correct for both under the
 * platform's calling convention, and wrong for neither.
 *
 * Run procedure: docs/console-findings.md, the issue #135 section — inventory
 * first, klog captured on 3232 for the whole window, no image mounted, and the
 * physical button available as the recovery.
 **/

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

/* Tried in order: the stick is writable from a payload, the agent's own
   state directory is not always reachable from another process. */
static const char *const spike_logs[] = {
  "/mnt/usb0/tools/spike135.log",
  "/data/spike135.log",
  "/data/ariel/spike135.log",
  NULL
};
#define SPIKE_TAG "spike135"


/* The candidates, as the SDK exports them from libSceSystemService.so. */
int sceShellCoreUtilRequestShutdown(void *arg);
int sceSystemServiceRequestPowerOff(void *arg);
int sceSystemServiceRequestReboot(void *arg);
int sceSystemStateMgrIsShellUIShutdownInProgress(void);
int sceSystemStateMgrIsStandbyModeEnabled(void);
int sceSystemStateMgrReboot(void *arg);
int sceApplicationSystemReboot(void *arg);
int sceSystemStateMgrGetCurrentState(void);


static FILE *g_log;


/**
 * Write one line to the log and the standard output, flushing both.
 **/
static void
say(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  fputc('\n', stdout);
  fflush(stdout);

  if(g_log) {
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
  }
}


/**
 * Put the log on the disk before the call that may take the console with it.
 **/
static void
commit_log(void) {
  if(g_log) {
    fsync(fileno(g_log));
  }
  sync();
  say("%s sync done", SPIKE_TAG);
}


/**
 * Call one candidate and print what it answered.
 *
 * The console may be gone before the next line runs, so the call is announced,
 * committed to the disk, and only then made.
 **/
static void
run(const char *name, int (*fn)(void *)) {
  uint8_t arg[64];
  int rc;
  int err;

  memset(arg, 0, sizeof(arg));
  say("%s calling %s", SPIKE_TAG, name);
  commit_log();

  errno = 0;
  rc = fn(arg);
  err = errno;

  say("%s %s rc=%d errno=%d", SPIKE_TAG, name, rc, err);
  if(g_log) {
    fsync(fileno(g_log));
  }
  say("%s %s returned and the console is still up", SPIKE_TAG, name);
}


static void
show_list(void) {
  say("%s list", SPIKE_TAG);
  say("%s read     sceSystemStateMgrIsStandbyModeEnabled", SPIKE_TAG);
  say("%s read     sceSystemStateMgrGetCurrentState", SPIKE_TAG);
  say("%s read     sceSystemStateMgrIsShellUIShutdownInProgress", SPIKE_TAG);
  say("%s shutdown sceShellCoreUtilRequestShutdown(void *arg)", SPIKE_TAG);
  say("%s poweroff sceSystemServiceRequestPowerOff(void *arg)", SPIKE_TAG);
  say("%s reboot   sceSystemServiceRequestReboot(void *arg)", SPIKE_TAG);
  say("%s statreboot sceSystemStateMgrReboot(void *arg)", SPIKE_TAG);
  say("%s sysreboot sceApplicationSystemReboot(void *arg), libSceSysCore", SPIKE_TAG);
  say("%s syscall  reboot(RB_AUTOBOOT)", SPIKE_TAG);
}


static void
show_read(void) {
  int standby;
  int shutting;

  errno = 0;
  standby = sceSystemStateMgrIsStandbyModeEnabled();
  say("%s sceSystemStateMgrIsStandbyModeEnabled rc=%d errno=%d", SPIKE_TAG, standby, errno);

  errno = 0;
  say("%s sceSystemStateMgrGetCurrentState rc=%d errno=%d",
      SPIKE_TAG, sceSystemStateMgrGetCurrentState(), errno);

  errno = 0;
  shutting = sceSystemStateMgrIsShellUIShutdownInProgress();
  say("%s sceSystemStateMgrIsShellUIShutdownInProgress rc=%d errno=%d",
      SPIKE_TAG, shutting, errno);
}


int
main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "list";
  int i;

  setvbuf(stdout, NULL, _IONBF, 0);
  for(i=0; spike_logs[i] && !g_log; i++) {
    g_log = fopen(spike_logs[i], "a");
  }
  say("%s start pid=%d mode=%s", SPIKE_TAG, (int)getpid(), mode);
  show_read();

  if(!strcmp(mode, "list")) {
    show_list();
  } else if(!strcmp(mode, "read")) {
    say("%s read complete", SPIKE_TAG);
  } else if(!strcmp(mode, "shutdown")) {
    run("sceShellCoreUtilRequestShutdown", sceShellCoreUtilRequestShutdown);
  } else if(!strcmp(mode, "poweroff")) {
    run("sceSystemServiceRequestPowerOff", sceSystemServiceRequestPowerOff);
  } else if(!strcmp(mode, "reboot")) {
    run("sceSystemServiceRequestReboot", sceSystemServiceRequestReboot);
  } else if(!strcmp(mode, "statreboot")) {
    run("sceSystemStateMgrReboot", sceSystemStateMgrReboot);
  } else if(!strcmp(mode, "sysreboot")) {
    run("sceApplicationSystemReboot", sceApplicationSystemReboot);
  } else if(!strcmp(mode, "syscall")) {
    say("%s calling reboot(RB_AUTOBOOT)", SPIKE_TAG);
    commit_log();
    errno = 0;
    say("%s reboot(2) rc=%d errno=%d", SPIKE_TAG, reboot(RB_AUTOBOOT), errno);
  } else {
    say("%s bad_arg %s", SPIKE_TAG, mode);
    show_list();
    return 1;
  }

  say("%s end", SPIKE_TAG);
  if(g_log) {
    fclose(g_log);
  }
  return 0;
}
