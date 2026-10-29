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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "approval.h"
#include "fileops.h"
#include "protected.h"
#include "ps5_at.h"
#include "sha256.h"
#include "zip.h"

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


/**
 * What a copy or move expects to open again: the device and inode the scan
 * saw. It is deliberately not the whole approval record: tree_copy carries
 * one of these on every frame of its walk, and the connection thread's stack
 * has to hold TREE_DEPTH_MAX of them.
 **/
typedef struct {
  uint64_t dev;
  uint64_t ino;
} expected_object_t;


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


/** Whether the entry name under dirfd, followed through a link, is protected. **/
static int
entry_protected(int dirfd, const char *name) {
  struct stat st;

  return !fstatat(dirfd, name, &st, 0) && protected_stat(&st);
}


/**
 * Open the directory that holds the last name of rel, walking down from root
 * without following a symbolic link, and copy that name into leaf. The walk
 * starts at root, or at the file system root when root is empty. Every
 * directory it opens is checked for protection by identity.
 **/
static int
parent_open(const char *root, const char *rel, int *dirfd, char *leaf,
            size_t size) {
  char walk[PATH_MAX];
  char *part;
  char *slash;
  int fd;
  int next;
  int state;

  if(snprintf(walk, sizeof(walk), "%s", rel + 1) >= (int)sizeof(walk)) {
    return FILEOPS_BAD_PATH;
  }

  fd = open(*root ? root : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if(fd < 0) {
    return FILEOPS_FAILED;
  }
  state = protected_object(fd);
  if(state) {
    close(fd);
    return state > 0 ? FILEOPS_PROTECTED : FILEOPS_FAILED;
  }

  part = walk;
  while((slash = strchr(part, '/'))) {
    *slash = '\0';
    next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if(next < 0) {
      int err = errno;
      int refusal = entry_protected(fd, part) ? FILEOPS_PROTECTED
                                              : walk_refusal(err);

      close(fd);
      return refusal;
    }
    state = protected_object(next);
    if(state) {
      close(fd);
      close(next);
      return state > 0 ? FILEOPS_PROTECTED : FILEOPS_FAILED;
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

  if(protected_stat(&st) ||
     (S_ISLNK(st.st_mode) && entry_protected(dirfd, leaf))) {
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
 * On success the parent stays open in dirfd for the caller to close. A read
 * (a run, a built-in check) may reach any entry under root; a write reaches
 * only below a writable root.
 **/
static int
inspect(const char *root, const char *path, approval_facts_t *facts,
        int *dirfd, char *leaf, size_t size, int writing) {
  const char *rel;
  int rc;

  if(path[0] != '/') {
    return FILEOPS_RELATIVE;
  }
  if(!approval_target_valid(path)) {
    return FILEOPS_BAD_PATH;
  }

  rel = below(root, path);
  if(!rel || (writing && !writable(rel))) {
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


int
fileops_builtin_check(const char *root, const char *path,
                      approval_facts_t *facts) {
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  rc = inspect(root, path, facts, &dirfd, leaf, sizeof(leaf), 0);
  if(rc) {
    return rc;
  }
  close(dirfd);

  return strcmp(facts->kind, "file") ? FILEOPS_NOT_FILE : FILEOPS_OK;
}


int
fileops_local_path(const char *text, char *out, size_t size) {
  static const char scheme[] = "file://";
  size_t n = sizeof(scheme) - 1;

  if(!strncmp(text, scheme, n)) {
    text += n;
    // The empty authority is the only one this takes: what follows the
    // scheme is the path itself, which must then be absolute.
    if(text[0] != '/') {
      return -1;
    }
  }
  if(snprintf(out, size, "%s", text) >= (int)size) {
    return -1;
  }
  return 0;
}


int
fileops_title_id(const char *path, char *out, size_t size) {
  const char *base = strrchr(path, '/');
  const char *end;
  size_t n;
  size_t i;

  base = base ? base + 1 : path;
  end = strchr(base, '-');
  if(!end) {
    // A package without the usual "-..." suffix still names its title, so
    // the .pkg extension is cut off instead.
    end = base + strlen(base);
    if((size_t)(end - base) > 4 && !strncmp(end - 4, ".pkg", 4)) {
      end -= 4;
    }
  }
  n = (size_t)(end - base);
  if(!n || n > FILEOPS_TITLE_MAX || n >= size) {
    return -1;
  }
  for(i = 0; i < n; i++) {
    char c = base[i];

    if(!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9'))) {
      return -1;
    }
  }
  memcpy(out, base, n);
  out[n] = '\0';
  return 0;
}


/** Whether the command sets attributes: chmod, chown or chgrp. **/
static int
attribute(const char *command) {
  return !strcmp(command, "chmod") || !strcmp(command, "chown") ||
         !strcmp(command, "chgrp");
}


/**
 * Parse the operand of an attribute command into its canonical text: a mode
 * in octal up to 07777, or an owner or group in decimal below 2^32 - 1, which
 * is the one id chown reads as "unchanged". Other commands have no operand.
 **/
static int
operand_value(const char *command, const char *operand, char *value,
              size_t size) {
  int octal = !strcmp(command, "chmod");
  uint64_t base = octal ? 8 : 10;
  uint64_t limit = octal ? 07777 : 4294967294ULL;
  uint64_t n = 0;
  const char *p;

  value[0] = '\0';
  if(!attribute(command)) {
    return FILEOPS_OK;
  }

  if(!*operand) {
    return octal ? FILEOPS_BAD_MODE :
           !strcmp(command, "chown") ? FILEOPS_BAD_OWNER : FILEOPS_BAD_GROUP;
  }
  for(p = operand; *p; p++) {
    if(*p < '0' || (uint64_t)(*p - '0') >= base) {
      break;
    }
    n = n * base + (uint64_t)(*p - '0');
    if(n > limit) {
      break;
    }
  }
  if(*p) {
    return octal ? FILEOPS_BAD_MODE :
           !strcmp(command, "chown") ? FILEOPS_BAD_OWNER : FILEOPS_BAD_GROUP;
  }

  if(octal) {
    snprintf(value, size, "%04llo", (unsigned long long)n);
  } else {
    snprintf(value, size, "%llu", (unsigned long long)n);
  }
  return FILEOPS_OK;
}


/**
 * The refusal of a symbolic link. An attribute command on a link to a
 * protected object answers protected: the link is not followed, only looked
 * at, so no change reaches the object.
 **/
static int
link_refusal(const char *command, int dirfd, const char *leaf) {
  struct stat st;

  if(attribute(command) && !fstatat(dirfd, leaf, &st, 0) &&
     protected_stat(&st)) {
    return FILEOPS_PROTECTED;
  }
  return FILEOPS_LINK;
}


/**
 * Resolve path like inspect, but when the entry is a symbolic link, refuse it
 * as protected if the object it leads to is one. A system command follows
 * links the way the kernel does, so an alias of a protected object is caught.
 **/
static int
system_entry(const char *root, const char *path, approval_facts_t *facts,
             int *dirfd, char *leaf, size_t size) {
  struct stat st;
  int rc;

  rc = inspect(root, path, facts, dirfd, leaf, size, 1);
  if(rc) {
    return rc;
  }

  if(!strcmp(facts->kind, "link") && !fstatat(*dirfd, leaf, &st, 0) &&
     protected_stat(&st)) {
    close(*dirfd);
    return FILEOPS_PROTECTED;
  }
  return FILEOPS_OK;
}


/** The largest program exec reads: the size of a store object at most. **/
#define PROGRAM_MAX (64UL * 1024 * 1024)


/** Read the whole regular file open at fd, which has the size st_size. **/
static int
read_all(int fd, off_t size, unsigned char *out) {
  off_t done = 0;
  ssize_t n;

  while(done < size) {
    n = read(fd, out + done, (size_t)(size - done));
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      return FILEOPS_FAILED;
    }
    done += n;
  }
  return FILEOPS_OK;
}


int
fileops_program(const char *root, const char *path, unsigned char **bytes,
                size_t *size) {
  char leaf[PATH_MAX];
  struct stat st;
  const char *rel;
  int dirfd;
  int fd;
  int rc;

  if(path[0] != '/') {
    return FILEOPS_RELATIVE;
  }
  if(!approval_target_valid(path)) {
    return FILEOPS_BAD_PATH;
  }

  rel = below(root, path);
  if(!rel) {
    return FILEOPS_PROTECTED;
  }

  rc = parent_open(root, rel, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }

  fd = openat(dirfd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  close(dirfd);
  if(fd < 0) {
    return walk_refusal(errno);
  }

  if(fstat(fd, &st)) {
    close(fd);
    return FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    close(fd);
    return FILEOPS_PROTECTED;
  }
  if(!S_ISREG(st.st_mode)) {
    close(fd);
    return FILEOPS_NOT_FILE;
  }
  if((uint64_t)st.st_size > PROGRAM_MAX) {
    close(fd);
    return FILEOPS_TOO_LARGE;
  }

  *size = (size_t)st.st_size;
  *bytes = malloc(*size ? *size : 1);
  if(!*bytes) {
    close(fd);
    return FILEOPS_FAILED;
  }

  rc = read_all(fd, st.st_size, *bytes);
  close(fd);
  if(rc) {
    free(*bytes);
    *bytes = NULL;
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

  if(!strcmp(command, "mknod")) {
    return absent ? FILEOPS_OK : FILEOPS_EXISTS;
  }
  if(!strcmp(command, "mount") || !strcmp(command, "umount") ||
     !strcmp(command, "chroot")) {
    if(absent) {
      return FILEOPS_NO_FILE;
    }
    if(link) {
      return FILEOPS_LINK;
    }
    return dir ? FILEOPS_OK : FILEOPS_NOT_DIR;
  }
  if(attribute(command)) {
    if(absent) {
      return FILEOPS_NO_FILE;
    }
    return link ? FILEOPS_LINK : FILEOPS_OK;
  }

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


/**
 * Set the mode, owner or group of the entry leaf in dirfd. The entry is opened
 * without following a link and must still be the one now describes, so the
 * change lands on the object that was checked.
 **/
static int
set_attributes(const char *command, const approval_facts_t *now, int dirfd,
               const char *leaf) {
  struct stat st;
  int fd;
  int rc;

  fd = openat(dirfd, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if(fd < 0) {
    return FILEOPS_FAILED;
  }
  if(fstat(fd, &st) || (uint64_t)st.st_dev != now->dev ||
     (uint64_t)st.st_ino != now->ino) {
    close(fd);
    return FILEOPS_CHANGED;
  }

  if(!strcmp(command, "chmod")) {
    rc = fchmod(fd, (mode_t)strtoul(now->value, NULL, 8));
  } else if(!strcmp(command, "chown")) {
    rc = fchown(fd, (uid_t)strtoul(now->value, NULL, 10), (gid_t)-1);
  } else {
    rc = fchown(fd, (uid_t)-1, (gid_t)strtoul(now->value, NULL, 10));
  }
  close(fd);
  return rc ? FILEOPS_FAILED : FILEOPS_OK;
}


/** Run a command whose precondition holds, on the entry leaf in dirfd. **/
static int
perform(const char *command, const approval_facts_t *now, int dirfd,
        const char *leaf) {
  const char *kind = now->kind;
  int fd;

  if(attribute(command)) {
    return set_attributes(command, now, dirfd, leaf);
  }

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
              const char *operand, approval_facts_t *facts) {
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  rc = operand_value(command, operand, facts->value, sizeof(facts->value));
  if(rc) {
    return rc;
  }

  rc = inspect(root, path, facts, &dirfd, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }

  rc = precondition(command, facts->kind);
  if(rc == FILEOPS_LINK) {
    rc = link_refusal(command, dirfd, leaf);
  }
  close(dirfd);
  return rc;
}


int
fileops_act(const char *root, const char *command, const char *path,
            const char *operand, const approval_facts_t *expected) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = operand_value(command, operand, now.value, sizeof(now.value));
  if(rc) {
    return rc;
  }

  rc = inspect(root, path, &now, &dirfd, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }

  // The entry and the operand are checked again: both must be the ones the
  // owner signed for.
  if(strcmp(now.kind, expected->kind) || now.dev != expected->dev ||
     now.ino != expected->ino || strcmp(now.value, expected->value)) {
    close(dirfd);
    return FILEOPS_CHANGED;
  }

  rc = precondition(command, now.kind);
  if(rc == FILEOPS_LINK) {
    rc = link_refusal(command, dirfd, leaf);
  }
  if(!rc) {
    rc = perform(command, &now, dirfd, leaf);
  }

  close(dirfd);
  return rc;
}


/**
 * What the entry at path is, for a transfer. Its parent directory must not be
 * a protected object, and a symbolic link must not lead to one. The parent
 * stays open in dirfd for the caller to close.
 **/
static int
transfer_inspect(const char *root, const char *path, approval_facts_t *facts,
                 int *dirfd, char *leaf, size_t size) {
  struct stat dir;
  struct stat target;
  int rc;

  rc = inspect(root, path, facts, dirfd, leaf, size, 1);
  if(rc) {
    return rc;
  }

  if(fstat(*dirfd, &dir)) {
    close(*dirfd);
    return FILEOPS_FAILED;
  }
  if(protected_stat(&dir)) {
    close(*dirfd);
    return FILEOPS_PROTECTED;
  }

  if(!strcmp(facts->kind, "link") &&
     !fstatat(*dirfd, leaf, &target, 0) && protected_stat(&target)) {
    close(*dirfd);
    return FILEOPS_PROTECTED;
  }

  return FILEOPS_OK;
}


/** Whether the source's kind lets a transfer run: a regular file only. **/
static int
transfer_source(const char *kind) {
  if(!strcmp(kind, "absent")) {
    return FILEOPS_NO_FILE;
  }
  if(!strcmp(kind, "link")) {
    return FILEOPS_LINK;
  }
  if(!strcmp(kind, "dir")) {
    return FILEOPS_IS_DIR;
  }
  return strcmp(kind, "file") ? FILEOPS_NOT_FILE : FILEOPS_OK;
}


/**
 * Open the entry at path for reading: a regular file, or a directory when dir
 * is set. A symbolic link answers protected when the object it leads to is one.
 **/
static int
entry_open(const char *root, const char *path, int dir, int *fd) {
  approval_facts_t facts;
  char leaf[PATH_MAX];
  struct stat st;
  int dirfd;
  int rc;

  memset(&facts, 0, sizeof(facts));
  // tar reads and extracts only below a writable root, as before reads were split.
  rc = inspect(root, path, &facts, &dirfd, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }

  if(!strcmp(facts.kind, "link") && !fstatat(dirfd, leaf, &st, 0) &&
     protected_stat(&st)) {
    close(dirfd);
    return FILEOPS_PROTECTED;
  }

  if(!dir) {
    rc = transfer_source(facts.kind);
  } else if(!strcmp(facts.kind, "absent")) {
    rc = FILEOPS_NO_FILE;
  } else if(!strcmp(facts.kind, "link")) {
    rc = FILEOPS_LINK;
  } else {
    rc = strcmp(facts.kind, "dir") ? FILEOPS_NOT_DIR : FILEOPS_OK;
  }
  if(rc) {
    close(dirfd);
    return rc;
  }

  *fd = openat(dirfd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                            (dir ? O_DIRECTORY : 0));
  close(dirfd);
  return *fd < 0 ? FILEOPS_FAILED : FILEOPS_OK;
}


int
fileops_discard(const char *root, const char *path) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = inspect(root, path, &now, &dirfd, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }
  rc = unlinkat(dirfd, leaf, 0) ? FILEOPS_FAILED : FILEOPS_OK;
  close(dirfd);
  return rc;
}


int
fileops_read_open(const char *root, const char *path, int *fd) {
  return entry_open(root, path, 0, fd);
}


int
fileops_write_open(const char *root, const char *path,
                   const approval_facts_t *expected, int *fd) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  struct stat st;
  int absent = !strcmp(expected->kind, "absent");
  int dirfd;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = inspect(root, path, &now, &dirfd, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }
  if(strcmp(now.kind, expected->kind) || now.dev != expected->dev ||
     now.ino != expected->ino) {
    close(dirfd);
    return FILEOPS_CHANGED;
  }

  *fd = openat(dirfd, leaf, O_WRONLY | O_CREAT | O_NOFOLLOW |
               (absent ? O_EXCL : 0), S_IRUSR | S_IWUSR);
  close(dirfd);
  if(*fd < 0) {
    return errno == EEXIST || errno == ELOOP ? FILEOPS_CHANGED : FILEOPS_FAILED;
  }

  if(fstat(*fd, &st)) {
    close(*fd);
    return FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    close(*fd);
    return FILEOPS_PROTECTED;
  }
  if(!absent && ((uint64_t)st.st_dev != expected->dev ||
                 (uint64_t)st.st_ino != expected->ino)) {
    close(*fd);
    return FILEOPS_CHANGED;
  }
  if(!absent && ftruncate(*fd, 0)) {
    close(*fd);
    return FILEOPS_FAILED;
  }
  return FILEOPS_OK;
}


int
fileops_dir_open(const char *root, const char *path, int *fd) {
  return entry_open(root, path, 1, fd);
}


static int
write_full(int fd, const char *buf, size_t n) {
  while(n) {
    ssize_t written = write(fd, buf, n);

    if(written <= 0) {
      return -1;
    }
    buf += written;
    n -= (size_t)written;
  }
  return 0;
}


/**
 * Copy the regular file sleaf in sdir to a new file dleaf in ddir. The source
 * is opened first and must still be the expected object. The destination is
 * made exclusively, and removed again when the copy fails.
 **/
static int
copy_entry(int sdir, const char *sleaf, const expected_object_t *expected,
           int ddir, const char *dleaf) {
  char buf[8192];
  struct stat st;
  ssize_t got;
  int in;
  int out;
  int rc = FILEOPS_OK;

  in = openat(sdir, sleaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if(in < 0) {
    return errno == ELOOP || errno == ENOENT ? FILEOPS_CHANGED : FILEOPS_FAILED;
  }
  if(fstat(in, &st)) {
    close(in);
    return FILEOPS_FAILED;
  }
  // The descriptor is what matters: an entry swapped for a link to one of
  // Ariel's secrets between the scan and this open is caught here.
  if(protected_stat(&st)) {
    close(in);
    return FILEOPS_PROTECTED;
  }
  if(!S_ISREG(st.st_mode) || (uint64_t)st.st_dev != expected->dev ||
     (uint64_t)st.st_ino != expected->ino) {
    close(in);
    return FILEOPS_CHANGED;
  }

  out = openat(ddir, dleaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                            O_CLOEXEC, 0644);
  if(out < 0) {
    close(in);
    return errno == EEXIST ? FILEOPS_EXISTS : FILEOPS_FAILED;
  }

  while(rc == FILEOPS_OK && (got = read(in, buf, sizeof(buf))) != 0) {
    if(got < 0 || write_full(out, buf, (size_t)got)) {
      rc = FILEOPS_FAILED;
    }
  }
  if(rc == FILEOPS_OK && fsync(out)) {
    rc = FILEOPS_FAILED;
  }
  if(close(out) && rc == FILEOPS_OK) {
    rc = FILEOPS_FAILED;
  }
  close(in);

  if(rc) {
    unlinkat(ddir, dleaf, 0);
  }
  return rc;
}


/**
 * The host suite's stand-in for a call the filesystem refuses, named by an
 * environment variable. The console build never refuses one here.
 **/
static int
host_refuses(const char *name) {
#ifdef ARIEL_HOST_BUILD
  return getenv(name) != NULL;
#else
  (void)name;
  return 0;
#endif
}


static int
link_entry(int sdir, const char *sleaf, int ddir, const char *dleaf) {
  if(host_refuses("ARIEL_HOST_NO_LINK")) {
    errno = EPERM;
    return -1;
  }
  return linkat(sdir, sleaf, ddir, dleaf, 0);
}


static int
rename_entry(int sdir, const char *sleaf, int ddir, const char *dleaf) {
  if(host_refuses("ARIEL_HOST_RENAME_EXDEV")) {
    errno = EXDEV;
    return -1;
  }
  return renameat(sdir, sleaf, ddir, dleaf);
}


static int
symlink_entry(const char *target, int dirfd, const char *leaf) {
  if(host_refuses("ARIEL_HOST_NO_SYMLINK")) {
    errno = EOPNOTSUPP;
    return -1;
  }
  return symlinkat(target, dirfd, leaf);
}


/**
 * Give the source's file its new name in one rename, so the object is never
 * under two names. A rename across file systems answers EXDEV, and then the
 * object is copied and its source name removed. A rename never replaces an
 * existing name, so an existing destination is kept. The source is checked
 * again before its name goes; a different object there is put back.
 **/
static int
move_entry(int sdir, const char *sleaf, const expected_object_t *expected,
           int ddir, const char *dleaf) {
  struct stat st;
  int rc;

  if(!rename_entry(sdir, sleaf, ddir, dleaf)) {
    if(fstatat(ddir, dleaf, &st, AT_SYMLINK_NOFOLLOW) ||
       (uint64_t)st.st_dev != expected->dev ||
       (uint64_t)st.st_ino != expected->ino) {
      renameat(ddir, dleaf, sdir, sleaf);
      return FILEOPS_CHANGED;
    }
    return FILEOPS_OK;
  }
  if(errno != EXDEV) {
    return errno == EEXIST ? FILEOPS_EXISTS : FILEOPS_FAILED;
  }

  rc = copy_entry(sdir, sleaf, expected, ddir, dleaf);
  if(rc) {
    return rc;
  }
  if(fstatat(sdir, sleaf, &st, AT_SYMLINK_NOFOLLOW) ||
     (uint64_t)st.st_dev != expected->dev ||
     (uint64_t)st.st_ino != expected->ino) {
    unlinkat(ddir, dleaf, 0);
    return FILEOPS_CHANGED;
  }
  if(unlinkat(sdir, sleaf, 0)) {
    unlinkat(ddir, dleaf, 0);
    return FILEOPS_FAILED;
  }
  return FILEOPS_OK;
}


/**
 * Check the object a symbolic link names, as a read would reach it. Protected
 * objects answer FILEOPS_PROTECTED; a target that does not exist is no object
 * to protect and the link may hold its text.
 **/
static int
link_target_check(const char *root, const char *target) {
  approval_facts_t found;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  memset(&found, 0, sizeof(found));
  rc = inspect(root, target, &found, &dirfd, leaf, sizeof(leaf), 0);
  if(rc == FILEOPS_PROTECTED) {
    return FILEOPS_PROTECTED;
  }
  if(!rc) {
    close(dirfd);
  }
  return FILEOPS_OK;
}


int
fileops_transfer_check(const char *root, const char *source,
                       const char *destination, approval_facts_t *facts) {
  approval_facts_t into;
  char sleaf[PATH_MAX];
  char dleaf[PATH_MAX];
  int sdir;
  int ddir;
  int rc;

  rc = transfer_inspect(root, source, facts, &sdir, sleaf, sizeof(sleaf));
  if(rc) {
    return rc;
  }

  memset(&into, 0, sizeof(into));
  rc = transfer_inspect(root, destination, &into, &ddir, dleaf, sizeof(dleaf));
  if(rc) {
    close(sdir);
    return rc;
  }

  close(sdir);
  close(ddir);

  rc = transfer_source(facts->kind);
  if(rc) {
    return rc;
  }
  return strcmp(into.kind, "absent") ? FILEOPS_EXISTS : FILEOPS_OK;
}


int
fileops_transfer_act(const char *root, const char *command,
                     const char *source, const char *destination,
                     const approval_facts_t *expected) {
  approval_facts_t now;
  approval_facts_t into;
  expected_object_t object;
  char sleaf[PATH_MAX];
  char dleaf[PATH_MAX];
  int sdir;
  int ddir;
  int rc;

  object.dev = expected->dev;
  object.ino = expected->ino;

  memset(&now, 0, sizeof(now));
  rc = transfer_inspect(root, source, &now, &sdir, sleaf, sizeof(sleaf));
  if(rc) {
    return rc;
  }

  if(strcmp(now.kind, expected->kind) || now.dev != expected->dev ||
     now.ino != expected->ino) {
    close(sdir);
    return FILEOPS_CHANGED;
  }

  memset(&into, 0, sizeof(into));
  rc = transfer_inspect(root, destination, &into, &ddir, dleaf, sizeof(dleaf));
  if(rc) {
    close(sdir);
    return rc;
  }

  if(strcmp(into.kind, "absent")) {
    rc = FILEOPS_EXISTS;
  } else if(!strcmp(command, "cp")) {
    rc = copy_entry(sdir, sleaf, &object, ddir, dleaf);
  } else if(!strcmp(command, "mv")) {
    rc = move_entry(sdir, sleaf, &object, ddir, dleaf);
  } else {
    rc = link_entry(sdir, sleaf, ddir, dleaf) ?
         (errno == EEXIST ? FILEOPS_EXISTS : FILEOPS_FAILED) : FILEOPS_OK;
  }

  close(sdir);
  close(ddir);
  return rc;
}


int
fileops_symlink_check(const char *root, const char *target,
                      const char *path, approval_facts_t *facts) {
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  if(target[0] != '/' || !approval_target_valid(target)) {
    return FILEOPS_BAD_PATH;
  }

  rc = transfer_inspect(root, path, facts, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }
  close(dirfd);

  if(strcmp(facts->kind, "absent")) {
    return FILEOPS_EXISTS;
  }
  return link_target_check(root, target);
}


int
fileops_symlink_act(const char *root, const char *target, const char *path) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  rc = link_target_check(root, target);
  if(rc) {
    return rc;
  }

  memset(&now, 0, sizeof(now));
  rc = transfer_inspect(root, path, &now, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }
  if(strcmp(now.kind, "absent")) {
    close(dirfd);
    return FILEOPS_EXISTS;
  }

  if(symlink_entry(target, dirfd, leaf)) {
    rc = errno == EEXIST ? FILEOPS_EXISTS :
         errno == EOPNOTSUPP ? FILEOPS_LINK_UNSUPPORTED : FILEOPS_FAILED;
  } else {
    rc = FILEOPS_OK;
  }
  close(dirfd);
  return rc;
}


int
fileops_write_check(const char *root, const char *path,
                    approval_facts_t *facts) {
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  rc = transfer_inspect(root, path, facts, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }
  close(dirfd);
  return FILEOPS_OK;
}


int
fileops_write_act(const char *root, const char *path, const unsigned char *data,
                  size_t size) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  int dirfd;
  int fd;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = transfer_inspect(root, path, &now, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }
  if(strcmp(now.kind, "absent")) {
    close(dirfd);
    return FILEOPS_CHANGED;
  }

  fd = openat(dirfd, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                           O_CLOEXEC, S_IRUSR | S_IWUSR);
  if(fd < 0) {
    close(dirfd);
    return errno == EEXIST || errno == ELOOP ? FILEOPS_CHANGED : FILEOPS_FAILED;
  }

  rc = write_full(fd, (const char *)data, size) || fsync(fd) ? -1 : 0;
  if(close(fd) || rc) {
    unlinkat(dirfd, leaf, 0);
    close(dirfd);
    return FILEOPS_FAILED;
  }

  close(dirfd);
  return FILEOPS_OK;
}


#define TREE_DEPTH_MAX 64


/** Whether destination is source itself or below it, by path. **/
static int
inside(const char *source, const char *destination) {
  size_t n = strlen(source);

  return !strncmp(destination, source, n) &&
         (destination[n] == '/' || destination[n] == '\0');
}


/**
 * Check the entry at leaf below parent and everything in it, without following
 * a link. A link to a protected object answers protected, any other link
 * answers FILEOPS_LINK, and nothing is changed.
 **/
static int
tree_scan(int parent, const char *leaf, int depth) {
  struct stat st;
  struct stat target;
  struct dirent *ent;
  DIR *dir;
  int fd;
  int rc = FILEOPS_OK;

  if(fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW)) {
    return errno == ENOENT ? FILEOPS_CHANGED : FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    return FILEOPS_PROTECTED;
  }
  if(S_ISLNK(st.st_mode)) {
    if(!fstatat(parent, leaf, &target, 0) && protected_stat(&target)) {
      return FILEOPS_PROTECTED;
    }
    return FILEOPS_LINK;
  }
  if(S_ISREG(st.st_mode)) {
    return FILEOPS_OK;
  }
  if(!S_ISDIR(st.st_mode)) {
    return FILEOPS_NOT_FILE;
  }
  if(depth >= TREE_DEPTH_MAX) {
    return FILEOPS_FAILED;
  }

  fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(fd < 0) {
    return walk_refusal(errno);
  }
  if(!(dir=fdopendir(fd))) {
    close(fd);
    return FILEOPS_FAILED;
  }
  while(rc == FILEOPS_OK && (ent = readdir(dir))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    rc = tree_scan(dirfd(dir), ent->d_name, depth + 1);
  }
  closedir(dir);
  return rc;
}


/**
 * Remove the entry at leaf below parent, and everything in it, without
 * following a link. Each entry is checked for protection before it goes.
 **/
static int
tree_remove(int parent, const char *leaf, int depth) {
  struct stat st;
  struct dirent *ent;
  DIR *dir;
  int fd;
  int rc = FILEOPS_OK;

  if(fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW)) {
    return errno == ENOENT ? FILEOPS_CHANGED : FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    return FILEOPS_PROTECTED;
  }
  if(!S_ISDIR(st.st_mode)) {
    return unlinkat(parent, leaf, 0) ? FILEOPS_FAILED : FILEOPS_OK;
  }
  if(depth >= TREE_DEPTH_MAX) {
    return FILEOPS_FAILED;
  }

  fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(fd < 0) {
    return walk_refusal(errno);
  }
  if(!(dir=fdopendir(fd))) {
    close(fd);
    return FILEOPS_FAILED;
  }
  while(rc == FILEOPS_OK && (ent = readdir(dir))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    rc = tree_remove(dirfd(dir), ent->d_name, depth + 1);
  }
  closedir(dir);
  if(rc) {
    return rc;
  }
  return unlinkat(parent, leaf, AT_REMOVEDIR) ? FILEOPS_FAILED : FILEOPS_OK;
}


/**
 * Copy the entry at sleaf below from to a new entry dleaf below to: a regular
 * file, or a directory with everything in it. Links and other kinds refuse.
 * The destination is made exclusively; EXISTS means it was already there.
 * Each entry is checked for protection as it is opened, as tree_scan checked
 * it before the signature: an object swapped for one of Ariel's secrets in
 * between answers protected, and nothing of it is read.
 * created is set when this call made the destination root, so the caller
 * knows a failure here is its own to remove.
 **/
static int
tree_copy(int from, const char *sleaf, int to, const char *dleaf, int depth,
          int *created) {
  expected_object_t expected;
  struct dirent *ent;
  struct stat st;
  DIR *dir;
  int sfd;
  int dfd;
  int rc = FILEOPS_OK;

  if(fstatat(from, sleaf, &st, AT_SYMLINK_NOFOLLOW)) {
    return errno == ENOENT ? FILEOPS_CHANGED : FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    return FILEOPS_PROTECTED;
  }
  if(S_ISREG(st.st_mode)) {
    memset(&expected, 0, sizeof(expected));
    expected.dev = (uint64_t)st.st_dev;
    expected.ino = (uint64_t)st.st_ino;
    return copy_entry(from, sleaf, &expected, to, dleaf);
  }
  if(!S_ISDIR(st.st_mode)) {
    return FILEOPS_NOT_FILE;
  }
  if(depth >= TREE_DEPTH_MAX) {
    return FILEOPS_FAILED;
  }

  if(mkdirat(to, dleaf, 0755)) {
    return errno == EEXIST ? FILEOPS_EXISTS : FILEOPS_FAILED;
  }
  if(created) {
    *created = 1;
  }
  sfd = openat(from, sleaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(sfd < 0) {
    return FILEOPS_CHANGED;
  }
  if(fstat(sfd, &st)) {
    close(sfd);
    return FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    close(sfd);
    return FILEOPS_PROTECTED;
  }
  dfd = openat(to, dleaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if(dfd < 0) {
    close(sfd);
    return FILEOPS_FAILED;
  }
  if(!(dir=fdopendir(sfd))) {
    close(sfd);
    close(dfd);
    return FILEOPS_FAILED;
  }
  while(rc == FILEOPS_OK && (ent = readdir(dir))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    rc = tree_copy(dirfd(dir), ent->d_name, dfd, ent->d_name, depth + 1, NULL);
  }
  closedir(dir);
  close(dfd);
  return rc;
}


int
fileops_tree_check(const char *root, const char *path,
                   approval_facts_t *facts) {
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  rc = inspect(root, path, facts, &dirfd, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }
  if(!strcmp(facts->kind, "absent")) {
    close(dirfd);
    return FILEOPS_NO_FILE;
  }

  rc = tree_scan(dirfd, leaf, 0);
  close(dirfd);
  return rc;
}


int
fileops_tree_act(const char *root, const char *path,
                 const approval_facts_t *expected) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = inspect(root, path, &now, &dirfd, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }
  if(strcmp(now.kind, expected->kind) || now.dev != expected->dev ||
     now.ino != expected->ino) {
    close(dirfd);
    return FILEOPS_CHANGED;
  }

  rc = tree_scan(dirfd, leaf, 0);
  if(!rc) {
    rc = tree_remove(dirfd, leaf, 0);
  }
  close(dirfd);
  return rc;
}


int
fileops_tree_transfer_check(const char *root, const char *source,
                            const char *destination, approval_facts_t *facts) {
  approval_facts_t into;
  char sleaf[PATH_MAX];
  char dleaf[PATH_MAX];
  int sdir;
  int ddir;
  int rc;

  if(inside(source, destination)) {
    return FILEOPS_BAD_PATH;
  }

  rc = transfer_inspect(root, source, facts, &sdir, sleaf, sizeof(sleaf));
  if(rc) {
    return rc;
  }
  if(!strcmp(facts->kind, "absent")) {
    close(sdir);
    return FILEOPS_NO_FILE;
  }
  rc = tree_scan(sdir, sleaf, 0);
  close(sdir);
  if(rc) {
    return rc;
  }

  memset(&into, 0, sizeof(into));
  rc = transfer_inspect(root, destination, &into, &ddir, dleaf, sizeof(dleaf));
  if(rc) {
    return rc;
  }
  close(ddir);
  return strcmp(into.kind, "absent") ? FILEOPS_EXISTS : FILEOPS_OK;
}


int
fileops_tree_transfer_act(const char *root, const char *source,
                          const char *destination,
                          const approval_facts_t *expected) {
  approval_facts_t now;
  approval_facts_t into;
  char sleaf[PATH_MAX];
  char dleaf[PATH_MAX];
  int sdir;
  int ddir;
  int rc;

  if(inside(source, destination)) {
    return FILEOPS_BAD_PATH;
  }

  memset(&now, 0, sizeof(now));
  rc = transfer_inspect(root, source, &now, &sdir, sleaf, sizeof(sleaf));
  if(rc) {
    return rc;
  }
  if(strcmp(now.kind, expected->kind) || now.dev != expected->dev ||
     now.ino != expected->ino) {
    close(sdir);
    return FILEOPS_CHANGED;
  }

  memset(&into, 0, sizeof(into));
  rc = transfer_inspect(root, destination, &into, &ddir, dleaf, sizeof(dleaf));
  if(rc) {
    close(sdir);
    return rc;
  }

  if(strcmp(into.kind, "absent")) {
    rc = FILEOPS_EXISTS;
  } else {
    int created = 0;

    rc = tree_scan(sdir, sleaf, 0);
    if(!rc) {
      rc = tree_copy(sdir, sleaf, ddir, dleaf, 0, &created);
    }
    // Whatever failed, a destination this call made is taken away again: a
    // nested entry another writer created answers EXISTS like the root does,
    // and a half-built tree must not stay behind under the destination name.
    if(rc && created) {
      tree_remove(ddir, dleaf, 0);
    }
  }

  close(sdir);
  close(ddir);
  return rc;
}


/** Whether text fits in size bytes, its NUL included. **/
static int
fits(const char *text, size_t size) {
  return strlen(text) < size;
}


/** A file system type: one to fifteen lowercase letters or digits. **/
static int
fstype_ok(const char *text) {
  size_t i;

  if(!text[0] || !fits(text, 16)) {
    return 0;
  }
  for(i=0; text[i]; i++) {
    if(!((text[i] >= 'a' && text[i] <= 'z') ||
         (text[i] >= '0' && text[i] <= '9'))) {
      return 0;
    }
  }
  return 1;
}


/** A device number: decimal, from 0 to 255. **/
static int
device_number(const char *text, uint64_t *value) {
  uint64_t n = 0;
  size_t i;

  if(!text[0] || strlen(text) > 3) {
    return 0;
  }
  for(i=0; text[i]; i++) {
    if(text[i] < '0' || text[i] > '9') {
      return 0;
    }
    n = n * 10 + (uint64_t)(text[i] - '0');
  }
  if(n > 255) {
    return 0;
  }
  *value = n;
  return 1;
}


int
fileops_system_parse(int argc, char *argv[], approval_facts_t *facts) {
  const char *command = argv[0];
  const char *target;

  if(!strcmp(command, "mount")) {
    if(argc != 5 || strcmp(argv[1], "-t") || !fstype_ok(argv[2]) ||
       !fits(argv[3], APPROVAL_TARGET_MAX + 1)) {
      return FILEOPS_BAD_ARG;
    }
    snprintf(facts->fstype, sizeof(facts->fstype), "%s", argv[2]);
    snprintf(facts->from, sizeof(facts->from), "%s", argv[3]);
    target = argv[4];
  } else if(!strcmp(command, "mknod")) {
    if(argc != 5 || (strcmp(argv[2], "b") && strcmp(argv[2], "c")) ||
       !device_number(argv[3], &facts->major) ||
       !device_number(argv[4], &facts->minor)) {
      return FILEOPS_BAD_ARG;
    }
    snprintf(facts->type, sizeof(facts->type), "%s", argv[2]);
    target = argv[1];
  } else {
    if(argc != 2) {
      return FILEOPS_BAD_ARG;
    }
    target = argv[1];
  }

  if(!fits(target, APPROVAL_TARGET_MAX + 1)) {
    return FILEOPS_BAD_ARG;
  }
  snprintf(facts->command, sizeof(facts->command), "%s", command);
  snprintf(facts->target, sizeof(facts->target), "%s", target);
  return FILEOPS_OK;
}


int
fileops_system_check(const char *root, approval_facts_t *facts) {
  approval_facts_t source;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  rc = system_entry(root, facts->target, facts, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }
  close(dirfd);
  if(!facts->from[0]) {
    return FILEOPS_OK;
  }

  memset(&source, 0, sizeof(source));
  rc = system_entry(root, facts->from, &source, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }
  rc = precondition("mount", source.kind);
  close(dirfd);
  return rc;
}


int
fileops_system_recheck(const char *root, const approval_facts_t *expected) {
  approval_facts_t now;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = system_entry(root, expected->target, &now, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }

  if(strcmp(now.kind, expected->kind) || now.dev != expected->dev ||
     now.ino != expected->ino) {
    close(dirfd);
    return FILEOPS_CHANGED;
  }

  rc = precondition(expected->command, now.kind);
  close(dirfd);
  return rc;
}


/** The largest archive unzip reads into memory. **/
#define UNZIP_ARCHIVE_MAX (16UL * 1024 * 1024)


/**
 * Read the archive at archive under root into memory, and record its kind,
 * device, inode and sha256 in facts. The archive is followed through links, so
 * a link to a protected object answers protected before anything is read.
 **/
static int
archive_read(const char *root, const char *archive, approval_facts_t *facts,
             unsigned char **bytes, size_t *len) {
  unsigned char digest[SHA256_DIGEST_LEN];
  struct stat st;
  sha256_t ctx;
  size_t got = 0;
  ssize_t n;
  int fd;

  *bytes = NULL;
  if(archive[0] != '/') {
    return FILEOPS_RELATIVE;
  }
  if(!approval_target_valid(archive)) {
    return FILEOPS_BAD_PATH;
  }
  if(!below(root, archive)) {
    return FILEOPS_NO_FILE;
  }
  if(protected_path(archive)) {
    return FILEOPS_PROTECTED;
  }

  fd = open(archive, O_RDONLY | O_CLOEXEC);
  if(fd < 0) {
    return walk_refusal(errno);
  }
  if(fstat(fd, &st)) {
    close(fd);
    return FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    close(fd);
    return FILEOPS_PROTECTED;
  }
  if(!S_ISREG(st.st_mode)) {
    close(fd);
    return S_ISDIR(st.st_mode) ? FILEOPS_IS_DIR : FILEOPS_NOT_FILE;
  }
  if(st.st_size <= 0 || (unsigned long long)st.st_size > UNZIP_ARCHIVE_MAX) {
    close(fd);
    return FILEOPS_BAD_ARCHIVE;
  }

  *len = (size_t)st.st_size;
  *bytes = malloc(*len);
  if(!*bytes) {
    close(fd);
    return FILEOPS_FAILED;
  }
  while(got < *len) {
    n = read(fd, *bytes + got, *len - got);
    if(n <= 0) {
      free(*bytes);
      *bytes = NULL;
      close(fd);
      return FILEOPS_FAILED;
    }
    got += (size_t)n;
  }
  close(fd);

  sha256_init(&ctx);
  sha256_update(&ctx, *bytes, *len);
  sha256_final(&ctx, digest);
  sha256_hex(digest, facts->sha256);

  snprintf(facts->kind, sizeof(facts->kind), "%s", "file");
  facts->dev = (uint64_t)st.st_dev;
  facts->ino = (uint64_t)st.st_ino;
  return FILEOPS_OK;
}


/** Read the archive's central directory into members. **/
static int
archive_members(const unsigned char *bytes, size_t len,
                zip_member_t **members, size_t *count) {
  *members = malloc(ZIP_MEMBERS_MAX * sizeof(**members));
  if(!*members) {
    return FILEOPS_FAILED;
  }
  if(zip_members(bytes, len, *members, ZIP_MEMBERS_MAX, count)) {
    free(*members);
    *members = NULL;
    return FILEOPS_BAD_ARCHIVE;
  }
  return FILEOPS_OK;
}


/** Whether every member's name stays under the destination. **/
static int
members_safe(const zip_member_t *members, size_t count) {
  size_t i;

  for(i = 0; i < count; i++) {
    if(!zip_name_safe(members[i].name)) {
      return FILEOPS_UNSAFE_MEMBER;
    }
  }
  return FILEOPS_OK;
}


/**
 * Open the destination directory of an unzip. It must exist, be a directory
 * and sit in a writable root; the directory stays open in dirfd.
 **/
static int
destination_open(const char *root, const char *destination, int *dirfd) {
  approval_facts_t facts;
  char leaf[PATH_MAX];
  int parent;
  int rc;

  memset(&facts, 0, sizeof(facts));
  rc = inspect(root, destination, &facts, &parent, leaf, sizeof(leaf), 1);
  if(rc) {
    return rc;
  }
  if(strcmp(facts.kind, "dir")) {
    close(parent);
    return !strcmp(facts.kind, "absent") ? FILEOPS_NO_FILE :
           !strcmp(facts.kind, "link") ? FILEOPS_LINK : FILEOPS_NOT_DIR;
  }

  *dirfd = openat(parent, leaf,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  close(parent);
  return *dirfd < 0 ? walk_refusal(errno) : FILEOPS_OK;
}


/**
 * Step from directory fd into its child part. A missing child is made when
 * make is set, and otherwise leaves child at -1. A symbolic link or a protected
 * object on the way is refused, so nothing is written through it.
 **/
static int
descend(int fd, const char *part, int make, int *child) {
  struct stat st;

  *child = -1;
  if(fstatat(fd, part, &st, AT_SYMLINK_NOFOLLOW)) {
    if(errno != ENOENT) {
      return FILEOPS_FAILED;
    }
    if(!make) {
      return FILEOPS_OK;
    }
    if(mkdirat(fd, part, 0755)) {
      return FILEOPS_FAILED;
    }
  } else if(S_ISLNK(st.st_mode)) {
    return FILEOPS_UNSAFE_MEMBER;
  } else if(!S_ISDIR(st.st_mode)) {
    return FILEOPS_NOT_DIR;
  } else if(protected_stat(&st)) {
    return FILEOPS_PROTECTED;
  }

  *child = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  return *child < 0 ? walk_refusal(errno) : FILEOPS_OK;
}


/** Create one file member with O_EXCL, so nothing that exists is replaced. **/
static int
write_member(int fd, const char *leaf, const zip_member_t *member) {
  size_t done = 0;
  ssize_t n;
  int out;

  out = openat(fd, leaf,
               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
  if(out < 0) {
    return errno == EEXIST ? FILEOPS_EXISTS : FILEOPS_FAILED;
  }
  while(done < member->size) {
    n = write(out, member->data + done, member->size - done);
    if(n <= 0) {
      close(out);
      return FILEOPS_FAILED;
    }
    done += (size_t)n;
  }
  return close(out) ? FILEOPS_FAILED : FILEOPS_OK;
}


/**
 * The last name of one member, in directory fd. An existing entry is never
 * replaced: a directory member may meet a directory, anything else is exists.
 **/
static int
member_leaf(int fd, const char *leaf, const zip_member_t *member, int make) {
  struct stat st;

  if(fstatat(fd, leaf, &st, AT_SYMLINK_NOFOLLOW)) {
    if(errno != ENOENT) {
      return FILEOPS_FAILED;
    }
    if(!make) {
      return FILEOPS_OK;
    }
    if(member->dir) {
      return mkdirat(fd, leaf, 0755) ? FILEOPS_FAILED : FILEOPS_OK;
    }
    return write_member(fd, leaf, member);
  }
  if(protected_stat(&st)) {
    return FILEOPS_PROTECTED;
  }
  if(member->dir && S_ISDIR(st.st_mode)) {
    return FILEOPS_OK;
  }
  return FILEOPS_EXISTS;
}


/**
 * Check one member under the destination directory dest, and when make is set
 * create it. Names are checked by the caller; each parent is walked one part at
 * a time from dest, so no link can lead the walk out of it.
 **/
static int
member_apply(int dest, const zip_member_t *member, int make) {
  char key[ZIP_NAME_MAX + 1];
  char *part;
  char *slash;
  int fd;
  int next;
  int rc;

  snprintf(key, sizeof(key), "%s", member->name);
  if(member->dir) {
    key[strlen(key) - 1] = '\0';
  }

  fd = dup(dest);
  if(fd < 0) {
    return FILEOPS_FAILED;
  }
  part = key;
  while((slash = strchr(part, '/'))) {
    *slash = '\0';
    rc = descend(fd, part, make, &next);
    close(fd);
    if(rc || next < 0) {
      return rc;
    }
    fd = next;
    part = slash + 1;
  }

  rc = member_leaf(fd, part, member, make);
  close(fd);
  return rc;
}


/**
 * Check every member before the first is written: a member that exists or
 * sits under a link or a protected object refuses the whole archive. With make
 * set, the members are then created in order.
 **/
static int
members_apply(int dest, const zip_member_t *members, size_t count, int make) {
  size_t i;
  int rc;

  for(i = 0; i < count; i++) {
    rc = member_apply(dest, &members[i], 0);
    if(rc) {
      return rc;
    }
  }
  if(!make) {
    return FILEOPS_OK;
  }
  for(i = 0; i < count; i++) {
    rc = member_apply(dest, &members[i], 1);
    if(rc) {
      return rc;
    }
  }
  return FILEOPS_OK;
}


int
fileops_unzip_list(const char *root, const char *archive, char **text,
                   size_t *len) {
  unsigned char *bytes = NULL;
  zip_member_t *members = NULL;
  approval_facts_t facts;
  size_t size = 0;
  size_t count = 0;
  size_t cap;
  size_t i;
  int rc;

  *text = NULL;
  *len = 0;
  memset(&facts, 0, sizeof(facts));
  rc = archive_read(root, archive, &facts, &bytes, &size);
  if(rc) {
    return rc;
  }
  rc = archive_members(bytes, size, &members, &count);
  free(bytes);
  if(rc) {
    return rc;
  }

  cap = count * (ZIP_NAME_MAX + 32) + 1;
  *text = malloc(cap);
  if(!*text) {
    free(members);
    return FILEOPS_FAILED;
  }
  for(i = 0; i < count; i++) {
    *len += (size_t)snprintf(*text + *len, cap - *len, "%llu %s\n",
                             (unsigned long long)members[i].size,
                             members[i].name);
  }
  free(members);
  return FILEOPS_OK;
}


int
fileops_unzip_check(const char *root, const char *archive,
                    const char *destination, approval_facts_t *facts) {
  zip_member_t *members = NULL;
  unsigned char *bytes = NULL;
  size_t size = 0;
  size_t count = 0;
  int dest;
  int rc;

  if(protected_path(archive)) {
    return FILEOPS_PROTECTED;
  }
  rc = destination_open(root, destination, &dest);
  if(rc) {
    return rc;
  }

  memset(facts, 0, sizeof(*facts));
  rc = archive_read(root, archive, facts, &bytes, &size);
  if(!rc) {
    rc = archive_members(bytes, size, &members, &count);
  }
  if(!rc) {
    rc = members_safe(members, count);
  }
  if(!rc) {
    rc = members_apply(dest, members, count, 0);
  }

  free(members);
  free(bytes);
  close(dest);
  return rc;
}


int
fileops_unzip_act(const char *root, const char *archive,
                  const char *destination, const approval_facts_t *expected) {
  zip_member_t *members = NULL;
  approval_facts_t now;
  unsigned char *bytes = NULL;
  size_t size = 0;
  size_t count = 0;
  int dest;
  int rc;

  rc = destination_open(root, destination, &dest);
  if(rc) {
    return rc;
  }

  memset(&now, 0, sizeof(now));
  rc = archive_read(root, archive, &now, &bytes, &size);
  if(!rc && (now.dev != expected->dev || now.ino != expected->ino ||
             strcmp(now.sha256, expected->sha256))) {
    rc = FILEOPS_CHANGED;
  }
  if(!rc) {
    rc = archive_members(bytes, size, &members, &count);
  }
  if(!rc) {
    rc = members_safe(members, count);
  }
  if(!rc) {
    rc = members_apply(dest, members, count, 1);
  }

  free(members);
  free(bytes);
  close(dest);
  return rc;
}




/**
 * Read the entry leaf in dirfd, which must still be the one inspected, into
 * bytes, and hash those bytes into facts.
 **/
static int
read_run(int dirfd, const char *leaf, approval_facts_t *facts,
         unsigned char **bytes, size_t *size) {
  struct stat st;
  unsigned char *buf;
  unsigned char digest[SHA256_DIGEST_LEN];
  sha256_t hash;
  size_t len = 0;
  ssize_t n;
  int fd;

  fd = openat(dirfd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if(fd < 0) {
    return errno == ELOOP ? FILEOPS_LINK : FILEOPS_FAILED;
  }
  if(fstat(fd, &st)) {
    close(fd);
    return FILEOPS_FAILED;
  }
  if((uint64_t)st.st_dev != facts->dev || (uint64_t)st.st_ino != facts->ino) {
    close(fd);
    return FILEOPS_CHANGED;
  }
  if(st.st_size < 0) {
    close(fd);
    return FILEOPS_FAILED;
  }
  if((uint64_t)st.st_size > FILEOPS_RUN_MAX) {
    close(fd);
    return FILEOPS_TOO_LARGE;
  }

  buf = malloc((size_t)st.st_size + 1);
  if(!buf) {
    close(fd);
    return FILEOPS_FAILED;
  }
  while(len < (size_t)st.st_size) {
    n = read(fd, buf + len, (size_t)st.st_size - len);
    if(n <= 0) {
      free(buf);
      close(fd);
      return n < 0 ? FILEOPS_FAILED : FILEOPS_CHANGED;
    }
    len += (size_t)n;
  }
  close(fd);

  sha256_init(&hash);
  sha256_update(&hash, buf, len);
  sha256_final(&hash, digest);
  sha256_hex(digest, facts->sha256);

  *bytes = buf;
  *size = len;
  return FILEOPS_OK;
}


int
fileops_run_load(const char *root, const char *path, approval_facts_t *facts,
                 unsigned char **bytes, size_t *size) {
  struct stat st;
  char leaf[PATH_MAX];
  int dirfd;
  int rc;

  if(path[0] == '/' && approval_target_valid(path) && !below(root, path)) {
    return FILEOPS_NOT_RUNNABLE;
  }
  rc = inspect(root, path, facts, &dirfd, leaf, sizeof(leaf), 0);
  if(rc) {
    return rc;
  }

  if(!strcmp(facts->kind, "absent")) {
    rc = FILEOPS_NO_FILE;
  } else if(!strcmp(facts->kind, "link")) {
    rc = FILEOPS_LINK;
  } else if(strcmp(facts->kind, "file")) {
    rc = FILEOPS_NOT_FILE;
  } else if(fstatat(dirfd, leaf, &st, AT_SYMLINK_NOFOLLOW)) {
    rc = FILEOPS_FAILED;
  } else if(!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
    rc = FILEOPS_NOT_EXEC;
  } else {
    rc = read_run(dirfd, leaf, facts, bytes, size);
  }

  close(dirfd);
  return rc;
}


const char *
fileops_word(int rc) {
  switch(rc) {
  case FILEOPS_BAD_ARG:
    return "bad_argument";
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
  case FILEOPS_TOO_LARGE:
    return "too_large";
  case FILEOPS_BAD_MODE:
    return "bad_mode";
  case FILEOPS_BAD_OWNER:
    return "bad_owner";
  case FILEOPS_BAD_GROUP:
    return "bad_group";
  case FILEOPS_UNSAFE_MEMBER:
    return "unsafe_member";
  case FILEOPS_BAD_ARCHIVE:
    return "bad_archive";
  case FILEOPS_NOT_EXEC:
    return "not_executable";
  case FILEOPS_NOT_TAR:
    return "not_a_tar";
  case FILEOPS_ESCAPE:
    return "escaping_member";
  case FILEOPS_BAD_MEMBER:
    return "bad_member";
  case FILEOPS_BAD_OPTION:
    return "bad_option";
  case FILEOPS_LINK_UNSUPPORTED:
    return "link_unsupported";
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
