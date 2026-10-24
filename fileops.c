/* Ariel: the gated file commands, mkdir, rmdir, touch and rm.

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

#if defined(__APPLE__)
// macOS hides O_NOFOLLOW and AT_* behind _DARWIN_C_SOURCE once _POSIX_C_SOURCE
// is defined, and every entry here is opened without following symbolic links.
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "approval.h"
#include "fileops.h"
#include "protected.h"
#include "ps5_at.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// The value is the platform's; the PS5 shim passes flags to the kernel as is.
#ifndef AT_REMOVEDIR
#if defined(__APPLE__)
#define AT_REMOVEDIR 0x0080
#else
#define AT_REMOVEDIR 0x0800
#endif
#endif


/** The part of path below root, starting with '/', or NULL when path is not
    under root. **/
static const char *
below(const char *root, const char *path) {
  size_t n = strlen(root);

  if(strncmp(path, root, n) || path[n] != '/') {
    return NULL;
  }
  return path + n;
}


/** Whether rel names something strictly below dir, which ends in '/'. **/
static int
under(const char *rel, const char *dir) {
  size_t n = strlen(dir);

  return !strncmp(rel, dir, n) && rel[n] != '\0';
}


/** Whether rel is below one mount /mnt/usb<name>, and not the mount itself. **/
static int
usb_under(const char *rel) {
  const char *seg = rel + 5;
  const char *slash;

  if(strncmp(rel, "/mnt/usb", 8)) {
    return 0;
  }

  slash = strchr(seg, '/');
  return slash && slash - seg > 3 && slash[1] != '\0';
}


/** The writable roots: below /data, below /user and below /mnt/usb*. **/
static int
writable(const char *rel) {
  return under(rel, "/data/") || under(rel, "/user/") || usb_under(rel);
}


/** Map the errno of a walk step to its refusal. **/
static int
walk_refusal(int err) {
  switch(err) {
  case ENOENT:
    return FILEOPS_NO_FILE;
  case ENOTDIR:
    return FILEOPS_NOT_DIR;
  case ELOOP:
    return FILEOPS_LINK;
  default:
    return FILEOPS_FAILED;
  }
}


/**
 * Open the directory that holds the last name of rel, walking down from root
 * without following a symbolic link, and copy that name into leaf. The walk
 * starts at root, or at the file system root when root is empty.
 **/
static int
parent_open(const char *root, const char *rel, int *dirfd, char *leaf,
            size_t size) {
  char walk[PATH_MAX];
  char *part;
  char *slash;
  int fd;
  int next;

  if(snprintf(walk, sizeof(walk), "%s", rel + 1) >= (int)sizeof(walk)) {
    return FILEOPS_BAD_PATH;
  }

  fd = open(*root ? root : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if(fd < 0) {
    return FILEOPS_FAILED;
  }

  part = walk;
  while((slash = strchr(part, '/'))) {
    *slash = '\0';
    next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if(next < 0) {
      int refusal = walk_refusal(errno);

      close(fd);
      return refusal;
    }
    close(fd);
    fd = next;
    part = slash + 1;
  }

  snprintf(leaf, size, "%s", part);
  *dirfd = fd;
  return FILEOPS_OK;
}


/** Record the kind, device and inode of the entry named leaf in dirfd. **/
static int
identity(int dirfd, const char *leaf, approval_facts_t *facts) {
  struct stat st;

  if(fstatat(dirfd, leaf, &st, AT_SYMLINK_NOFOLLOW)) {
    if(errno != ENOENT) {
      return FILEOPS_FAILED;
    }
    snprintf(facts->kind, sizeof(facts->kind), "%s", "absent");
    facts->dev = 0;
    facts->ino = 0;
    return FILEOPS_OK;
  }

  if(protected_stat(&st)) {
    return FILEOPS_PROTECTED;
  }

  if(S_ISREG(st.st_mode)) {
    snprintf(facts->kind, sizeof(facts->kind), "%s", "file");
  } else if(S_ISDIR(st.st_mode)) {
    snprintf(facts->kind, sizeof(facts->kind), "%s", "dir");
  } else if(S_ISLNK(st.st_mode)) {
    snprintf(facts->kind, sizeof(facts->kind), "%s", "link");
  } else {
    snprintf(facts->kind, sizeof(facts->kind), "%s", "other");
  }
  facts->dev = (uint64_t)st.st_dev;
  facts->ino = (uint64_t)st.st_ino;

  return FILEOPS_OK;
}


/**
 * Resolve path to its parent directory and entry, and say what the entry is.
 * On success the parent stays open in dirfd for the caller to close.
 **/
static int
inspect(const char *root, const char *path, approval_facts_t *facts,
        int *dirfd, char *leaf, size_t size) {
  const char *rel;
  int rc;

  if(path[0] != '/') {
    return FILEOPS_RELATIVE;
  }
  if(!approval_target_valid(path)) {
    return FILEOPS_BAD_PATH;
  }

  rel = below(root, path);
  if(!rel || !writable(rel)) {
    return FILEOPS_PROTECTED;
  }

  rc = parent_open(root, rel, dirfd, leaf, size);
  if(rc) {
    return rc;
  }

  rc = identity(*dirfd, leaf, facts);
  if(rc) {
    close(*dirfd);
  }
  return rc;
}


/** Whether the entry's kind lets the command run. **/
static int
precondition(const char *command, const char *kind) {
  int absent = !strcmp(kind, "absent");
  int file = !strcmp(kind, "file");
  int dir = !strcmp(kind, "dir");
  int link = !strcmp(kind, "link");

  if(!strcmp(command, "mkdir")) {
    return absent ? FILEOPS_OK : FILEOPS_EXISTS;
  }
  if(!strcmp(command, "rmdir")) {
    if(absent) {
      return FILEOPS_NO_FILE;
    }
    if(link) {
      return FILEOPS_LINK;
    }
    return dir ? FILEOPS_OK : FILEOPS_NOT_DIR;
  }
  if(!strcmp(command, "touch")) {
    if(absent || file) {
      return FILEOPS_OK;
    }
    if(link) {
      return FILEOPS_LINK;
    }
    return dir ? FILEOPS_IS_DIR : FILEOPS_NOT_FILE;
  }

  // rm
  if(absent) {
    return FILEOPS_NO_FILE;
  }
  if(link) {
    return FILEOPS_LINK;
  }
  if(dir) {
    return FILEOPS_IS_DIR;
  }
  return file ? FILEOPS_OK : FILEOPS_NOT_FILE;
}


/** Run a command whose precondition holds, on the entry leaf in dirfd. **/
static int
perform(const char *command, const char *kind, int dirfd, const char *leaf) {
  int fd;

  if(!strcmp(command, "mkdir")) {
    return mkdirat(dirfd, leaf, 0755) ? FILEOPS_FAILED : FILEOPS_OK;
  }
  if(!strcmp(command, "rmdir")) {
    return unlinkat(dirfd, leaf, AT_REMOVEDIR) ? FILEOPS_FAILED : FILEOPS_OK;
  }
  if(!strcmp(command, "touch")) {
    // An existing file is left as it is; only a missing one is made here.
    if(strcmp(kind, "absent")) {
      return FILEOPS_OK;
    }
    fd = openat(dirfd, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                             O_CLOEXEC, 0644);
    if(fd < 0) {
      return FILEOPS_FAILED;
    }
    return close(fd) ? FILEOPS_FAILED : FILEOPS_OK;
  }

  return unlinkat(dirfd, leaf, 0) ? FILEOPS_FAILED : FILEOPS_OK;
}


int
fileops_check(const char *root, const char *command, const char *path,
              approval_facts_t *facts) {
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  rc = inspect(root, path, facts, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }

  rc = precondition(command, facts->kind);
  close(dirfd);
  return rc;
}


int
fileops_act(const char *root, const char *command, const char *path,
            const approval_facts_t *expected) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = inspect(root, path, &now, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }

  // The entry is checked again: it must be the one the owner signed for.
  if(strcmp(now.kind, expected->kind) || now.dev != expected->dev ||
     now.ino != expected->ino) {
    close(dirfd);
    return FILEOPS_CHANGED;
  }

  rc = precondition(command, now.kind);
  if(!rc) {
    rc = perform(command, now.kind, dirfd, leaf);
  }

  close(dirfd);
  return rc;
}


const char *
fileops_word(int rc) {
  switch(rc) {
  case FILEOPS_RELATIVE:
    return "relative_path";
  case FILEOPS_BAD_PATH:
    return "bad_path";
  case FILEOPS_PROTECTED:
    return "protected";
  case FILEOPS_EXISTS:
    return "exists";
  case FILEOPS_NO_FILE:
    return "no_such_file";
  case FILEOPS_NOT_DIR:
    return "not_a_directory";
  case FILEOPS_IS_DIR:
    return "is_a_directory";
  case FILEOPS_NOT_FILE:
    return "not_a_file";
  case FILEOPS_LINK:
    return "symbolic_link";
  case FILEOPS_CHANGED:
    return "approval_stale";
  case FILEOPS_FAILED:
    return "operation_failed";
  default:
    return "ok";
  }
}


int
fileops_status(int rc) {
  switch(rc) {
  case FILEOPS_OK:
    return 0;
  case FILEOPS_PROTECTED:
    return 87;
  case FILEOPS_CHANGED:
    return 78;
  default:
    return 1;
  }
}
