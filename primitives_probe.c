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
 * Console primitives probe (issue #18).
 *
 * A separate payload. It is never linked into ariel-ps5.elf. The operator
 * sends it to the ELF loader, which copies this process's standard output
 * back over the deploy connection.
 *
 * It exercises openat, renameat as an atomic replace of an existing file,
 * unlinkat, fsync of a file and fsync of a directory through ps5_at.h, and
 * prints each call, its rc and errno, and whether the POSIX behavior held.
 * fsync is the libkernel symbol: it already returns -1 and sets errno, so
 * ps5_at.h does not wrap it.
 *
 * Run procedure: docs/console-findings.md, the issue #18 section.
 **/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ps5_at.h"


#define PROBE_DIR "/data/ariel/probe18"


static int g_failed;


/**
 * Print the call, its rc and errno, and a PASS or FAIL line.
 **/
static void
report(const char *call, int rc, int err, int held, const char *why) {
  printf("call %s\n", call);
  printf("rc %d errno %d\n", rc, err);
  printf("%s %s: %s\n", held ? "PASS" : "FAIL", call, why);
  if(!held) {
    g_failed = 1;
  }
}


/**
 * Create the probe directory. A directory that is already there is fine.
 **/
static int
probe_dir(void) {
  int rc;
  int err;

  errno = 0;
  rc = mkdirat(AT_FDCWD, PROBE_DIR, 0755);
  err = errno;
  if(rc == 0 || (rc == -1 && err == EEXIST)) {
    report("mkdirat(AT_FDCWD, \"" PROBE_DIR "\", 0755)", rc, err, 1,
           rc == 0 ? "directory created" : "directory already exists");
    return 0;
  }
  report("mkdirat(AT_FDCWD, \"" PROBE_DIR "\", 0755)", rc, err, 0,
         "POSIX mkdirat returns 0 or -1 with EEXIST");
  return -1;
}


/**
 * openat of a new file must return a file descriptor and leave errno alone.
 **/
static int
probe_openat(int dirfd) {
  int fd;
  int err;

  errno = 0;
  fd = openat(dirfd, "openat.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  err = errno;
  if(fd >= 0 && err == 0) {
    report("openat(dirfd, \"openat.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0644)",
           fd, err, 1, "new file, fd returned, errno unchanged");
    return fd;
  }
  report("openat(dirfd, \"openat.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0644)",
         fd, err, 0, "POSIX openat returns an fd and does not set errno");
  if(fd >= 0) {
    close(fd);
  }
  return -1;
}


/**
 * Write the whole buffer or report a short write.
 **/
static int
write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;
  ssize_t n;

  while(off < len) {
    n = write(fd, buf + off, len - off);
    if(n < 0) {
      return -1;
    }
    off += (size_t)n;
  }
  return 0;
}


/**
 * renameat over an existing destination must leave the new content there
 * and no temporary file behind.
 **/
static void
probe_renameat(int dirfd) {
  char got[8];
  const char *call = "renameat(dirfd, \"new.txt\", dirfd, \"dst.txt\")";
  int dst;
  int src;
  int rc;
  int err;
  ssize_t n;

  errno = 0;
  dst = openat(dirfd, "dst.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  err = errno;
  if(dst < 0 || write_all(dst, "old\n", 4)) {
    report("openat(dirfd, \"dst.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0644)",
           dst, err, 0, "existing destination could not be created");
    if(dst >= 0) {
      close(dst);
    }
    return;
  }
  close(dst);

  errno = 0;
  src = openat(dirfd, "new.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  err = errno;
  if(src < 0 || write_all(src, "new\n", 4)) {
    report("openat(dirfd, \"new.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0644)",
           src, err, 0, "replacement file could not be created");
    if(src >= 0) {
      close(src);
    }
    return;
  }
  close(src);

  errno = 0;
  rc = renameat(dirfd, "new.txt", dirfd, "dst.txt");
  err = errno;
  if(rc != 0 || err != 0) {
    report(call, rc, err, 0,
           "POSIX renameat of an existing file returns 0");
    return;
  }

  errno = 0;
  src = openat(dirfd, "new.txt", O_RDONLY, 0);
  err = errno;
  if(src != -1 || err != ENOENT) {
    report("openat(dirfd, \"new.txt\", O_RDONLY)", src, err, 0,
           "the temporary file is still there after renameat");
    if(src >= 0) {
      close(src);
    }
    report(call, rc, 0, 0, "rename returned 0 but left the source");
    return;
  }
  report("openat(dirfd, \"new.txt\", O_RDONLY)", src, err, 1,
         "temporary file is gone, errno ENOENT");

  errno = 0;
  dst = openat(dirfd, "dst.txt", O_RDONLY, 0);
  err = errno;
  if(dst < 0) {
    report("openat(dirfd, \"dst.txt\", O_RDONLY)", dst, err, 0,
           "destination missing after renameat");
    report(call, rc, 0, 0, "rename returned 0 but the destination is gone");
    return;
  }
  n = read(dst, got, sizeof(got));
  close(dst);
  if(n == 4 && !memcmp(got, "new\n", 4)) {
    report(call, rc, 0, 1,
           "existing destination replaced, it holds the new content, "
           "no temporary file left");
    return;
  }
  report(call, rc, 0, 0,
         "destination does not hold the new content");
}


/**
 * unlinkat of a file that exists must return 0, and a second unlinkat of
 * the same name must return -1 with ENOENT.
 **/
static void
probe_unlinkat(int dirfd) {
  int fd;
  int rc;
  int err;

  errno = 0;
  fd = openat(dirfd, "unlink.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  err = errno;
  if(fd < 0) {
    report("openat(dirfd, \"unlink.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0644)",
           fd, err, 0, "file to unlink could not be created");
    return;
  }
  close(fd);

  errno = 0;
  rc = unlinkat(dirfd, "unlink.txt", 0);
  err = errno;
  if(rc != 0 || err != 0) {
    report("unlinkat(dirfd, \"unlink.txt\", 0)", rc, err, 0,
           "POSIX unlinkat of an existing file returns 0");
    return;
  }
  report("unlinkat(dirfd, \"unlink.txt\", 0)", rc, err, 1,
         "existing file removed");

  errno = 0;
  rc = unlinkat(dirfd, "unlink.txt", 0);
  err = errno;
  if(rc == -1 && err == ENOENT) {
    report("unlinkat(dirfd, \"unlink.txt\", 0) again", rc, err, 1,
           "missing file returns -1 with ENOENT");
    return;
  }
  report("unlinkat(dirfd, \"unlink.txt\", 0) again", rc, err, 0,
         "POSIX unlinkat of a missing file returns -1 with ENOENT");
}


/**
 * fsync of a file descriptor must return 0. fsync is the libkernel symbol.
 **/
static void
probe_fsync_file(int fd) {
  int rc;
  int err;

  if(fd < 0) {
    report("fsync(file fd)", -1, EBADF, 0, "no file was opened");
    return;
  }

  errno = 0;
  rc = fsync(fd);
  err = errno;
  if(rc == 0) {
    report("fsync(file fd)", rc, err, 1, "file descriptor synced");
    return;
  }
  report("fsync(file fd)", rc, err, 0,
         "POSIX fsync of a file descriptor returns 0");
}


/**
 * fsync of a directory descriptor must return 0.
 **/
static void
probe_fsync_dir(int dirfd) {
  int rc;
  int err;

  errno = 0;
  rc = fsync(dirfd);
  err = errno;
  if(rc == 0) {
    report("fsync(directory fd)", rc, err, 1, "directory descriptor synced");
    return;
  }
  report("fsync(directory fd)", rc, err, 0,
         "POSIX fsync of a directory descriptor returns 0");
}


int
main(void) {
  int dirfd;
  int fd;

  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("primitives probe: start, dir %s\n", PROBE_DIR);

  if(probe_dir()) {
    printf("primitives probe: done, failures %d\n", g_failed ? 1 : 0);
    return 1;
  }

  errno = 0;
  dirfd = openat(AT_FDCWD, PROBE_DIR, O_RDONLY | O_DIRECTORY, 0);
  if(dirfd < 0) {
    report("openat(AT_FDCWD, \"" PROBE_DIR "\", O_RDONLY|O_DIRECTORY)",
           dirfd, errno, 0, "probe directory did not open");
    printf("primitives probe: done, failures 1\n");
    return 1;
  }
  report("openat(AT_FDCWD, \"" PROBE_DIR "\", O_RDONLY|O_DIRECTORY)",
         dirfd, errno, 1, "directory fd returned");

  fd = probe_openat(dirfd);
  probe_renameat(dirfd);
  probe_unlinkat(dirfd);
  probe_fsync_file(fd);
  probe_fsync_dir(dirfd);

  if(fd >= 0) {
    close(fd);
  }
  close(dirfd);

  printf("primitives probe: done, failures %d\n", g_failed ? 1 : 0);
  return g_failed ? 1 : 0;
}
