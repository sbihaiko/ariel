/* Ariel: the tar command, which lists an archive and extracts it after approval.

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
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fileops.h"
#include "protected.h"
#include "sha256.h"
#include "tar.h"

#define TAR_BLOCK 512

/** Whether the block is all zeros: the end-of-archive marker. **/
static int
zero_block(const unsigned char *block) {
  size_t i;

  for(i=0; i<TAR_BLOCK; i++) {
    if(block[i]) {
      return 0;
    }
  }
  return 1;
}


/** The octal number in a field of n bytes, or -1 when it is not one. **/
static int
octal_field(const unsigned char *field, size_t n, uint64_t *value) {
  uint64_t v = 0;
  size_t i;

  for(i=0; i<n && field[i] == ' '; i++) {
  }
  for(; i<n && field[i] != '\0' && field[i] != ' '; i++) {
    if(field[i] < '0' || field[i] > '7') {
      return -1;
    }
    v = v * 8 + (uint64_t)(field[i] - '0');
  }
  *value = v;
  return 0;
}


/** Whether the checksum is the sum of the header's bytes, its checksum field as spaces. **/
static int
checksum_ok(const unsigned char *block) {
  uint64_t sum = 0;
  uint64_t stored;
  size_t i;

  for(i=0; i<TAR_BLOCK; i++) {
    sum += (i >= 148 && i < 156) ? ' ' : block[i];
  }
  if(octal_field(block + 148, 8, &stored)) {
    return 0;
  }
  return sum == stored;
}


/** The member's name, prefixed by its ustar prefix when it has one. **/
static void
member_name(const unsigned char *block, char *name, size_t size) {
  const char *prefix = (const char *)block + 345;
  const char *leaf = (const char *)block;
  size_t plen = strnlen(prefix, 155);
  size_t llen = strnlen(leaf, 100);
  size_t n;

  if(!memcmp(block + 257, "ustar", 5) && plen) {
    snprintf(name, size, "%.*s/%.*s", (int)plen, prefix, (int)llen, leaf);
  } else {
    snprintf(name, size, "%.*s", (int)llen, leaf);
  }
  for(n=strlen(name); n>1 && name[n-1]=='/'; n--) {
    name[n-1] = '\0';
  }
}


int
tar_walk(int fd, tar_emit_fn emit, void *ctx) {
  unsigned char block[TAR_BLOCK];
  tar_member_t member;
  uint64_t blocks;
  ssize_t got;
  int rc;

  for(;;) {
    got = read(fd, block, sizeof(block));
    if(got == 0) {
      return FILEOPS_OK;
    }
    if(got != TAR_BLOCK || zero_block(block)) {
      return got == TAR_BLOCK ? FILEOPS_OK : FILEOPS_NOT_TAR;
    }
    if(!checksum_ok(block) || octal_field(block + 124, 12, &member.size)) {
      return FILEOPS_NOT_TAR;
    }

    member_name(block, member.name, sizeof(member.name));
    member.type = (char)block[156];
    snprintf(member.link, sizeof(member.link), "%.*s",
             (int)strnlen((const char *)block + 157, 100),
             (const char *)block + 157);
    member.offset = lseek(fd, 0, SEEK_CUR);

    rc = emit(ctx, &member);
    if(rc) {
      return rc;
    }

    blocks = (member.size + TAR_BLOCK - 1) / TAR_BLOCK;
    if(lseek(fd, (off_t)(blocks * TAR_BLOCK), SEEK_CUR) < 0) {
      return FILEOPS_FAILED;
    }
  }
}


/**
 * Walk path's segments from depth. Returns 0 when a ".." climbs above the
 * start; otherwise 1, with the final depth in out. *plain is cleared when a
 * segment is empty, "." or "..".
 **/
static int
resolve(const char *path, int depth, int *out, int *plain) {
  const char *p = path;

  *plain = 1;
  while(*p) {
    const char *seg = p;
    size_t n;

    while(*p && *p != '/') {
      p++;
    }
    n = (size_t)(p - seg);
    if(*p == '/') {
      p++;
    }

    if(n == 0 || (n == 1 && seg[0] == '.')) {
      *plain = 0;
    } else if(n == 2 && seg[0] == '.' && seg[1] == '.') {
      if(--depth < 0) {
        return 0;
      }
      *plain = 0;
    } else {
      depth++;
    }
  }
  *out = depth;
  return 1;
}


/** A member name: escaping, not extracted, or ordinary. **/
static int
name_class(const char *name, int *depth) {
  int plain;

  if(name[0] == '/' || !resolve(name, 0, depth, &plain)) {
    return FILEOPS_ESCAPE;
  }
  return plain ? FILEOPS_OK : FILEOPS_BAD_MEMBER;
}


/**
 * A link's target, resolved from depth: escaping when it is absolute or climbs
 * above the start. A link that stays inside is one this slice does not make.
 **/
static int
link_class(int depth, const char *target) {
  int out;
  int plain;

  if(target[0] == '/' || !resolve(target, depth, &out, &plain)) {
    return FILEOPS_ESCAPE;
  }
  return FILEOPS_BAD_MEMBER;
}


/**
 * Refuse an entry that already exists under dest, or that is or reaches a
 * protected object. A missing parent means nothing below it exists.
 **/
static int
exists_check(int dest, const char *name) {
  char walk[TAR_NAME_MAX + 1];
  char *part = walk;
  char *slash;
  struct stat st;
  int dirfd = dest;
  int own = 0;
  int missing = 0;
  int rc = FILEOPS_OK;

  snprintf(walk, sizeof(walk), "%s", name);
  while(!missing && rc == FILEOPS_OK && (slash = strchr(part, '/'))) {
    int next;

    *slash = '\0';
    if(fstatat(dirfd, part, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = errno == ENOENT ? FILEOPS_OK : FILEOPS_FAILED;
      missing = 1;
    } else if(protected_stat(&st)) {
      rc = FILEOPS_PROTECTED;
    } else if(!S_ISDIR(st.st_mode)) {
      rc = FILEOPS_EXISTS;
    } else {
      next = openat(dirfd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if(next < 0) {
        rc = FILEOPS_FAILED;
      } else {
        if(own) {
          close(dirfd);
        }
        dirfd = next;
        own = 1;
        part = slash + 1;
      }
    }
  }

  if(rc == FILEOPS_OK && !missing) {
    if(!fstatat(dirfd, part, &st, 0) && protected_stat(&st)) {
      rc = FILEOPS_PROTECTED;
    } else if(!fstatat(dirfd, part, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = FILEOPS_EXISTS;
    }
  }

  if(own) {
    close(dirfd);
  }
  return rc;
}


static int
member_check(int dest, const tar_member_t *member) {
  int depth = 0;
  int rc;

  rc = name_class(member->name, &depth);
  if(rc) {
    return rc;
  }

  switch(member->type) {
  case '0':
  case '\0':
  case '5':
    return exists_check(dest, member->name);
  case '1':
    return link_class(0, member->link);
  case '2':
    return depth < 1 ? FILEOPS_BAD_MEMBER : link_class(depth - 1, member->link);
  default:
    return FILEOPS_BAD_MEMBER;
  }
}


static int
vet_member(void *ctx, const tar_member_t *member) {
  const tar_job_t *job = ctx;

  return member_check(job->dest, member);
}


/** The directory that holds the member's last name, made where missing. **/
static int
parent_dir(int dest, const char *name, int *dirfd, char *leaf, size_t size) {
  char walk[TAR_NAME_MAX + 1];
  char *part = walk;
  char *slash;
  int cur = dest;
  int own = 0;
  int next;

  snprintf(walk, sizeof(walk), "%s", name);
  while((slash = strchr(part, '/'))) {
    *slash = '\0';
    if(mkdirat(cur, part, 0755) && errno != EEXIST) {
      break;
    }
    next = openat(cur, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if(own) {
      close(cur);
    }
    if(next < 0) {
      return FILEOPS_FAILED;
    }
    cur = next;
    own = 1;
    part = slash + 1;
  }
  if(slash) {
    if(own) {
      close(cur);
    }
    return FILEOPS_FAILED;
  }

  snprintf(leaf, size, "%s", part);
  *dirfd = cur;
  return FILEOPS_OK;
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


/** Write one regular file's data into a new file leaf in dirfd. **/
static int
copy_member(int archive, const tar_member_t *member, int dirfd,
            const char *leaf) {
  char buf[8192];
  uint64_t done = 0;
  size_t want;
  ssize_t got;
  int out;
  int rc = FILEOPS_OK;

  out = openat(dirfd, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                            O_CLOEXEC, 0644);
  if(out < 0) {
    return errno == EEXIST ? FILEOPS_EXISTS : FILEOPS_FAILED;
  }

  while(rc == FILEOPS_OK && done < member->size) {
    want = member->size - done < sizeof(buf) ? (size_t)(member->size - done)
                                             : sizeof(buf);
    got = pread(archive, buf, want, member->offset + (off_t)done);
    if(got <= 0 || write_full(out, buf, (size_t)got)) {
      rc = FILEOPS_FAILED;
    } else {
      done += (uint64_t)got;
    }
  }
  if(rc == FILEOPS_OK && fsync(out)) {
    rc = FILEOPS_FAILED;
  }
  if(close(out) && rc == FILEOPS_OK) {
    rc = FILEOPS_FAILED;
  }

  if(rc) {
    unlinkat(dirfd, leaf, 0);
  }
  return rc;
}


static int
write_member(void *ctx, const tar_member_t *member) {
  const tar_job_t *job = ctx;
  char leaf[TAR_NAME_MAX + 1];
  int dirfd;
  int rc;

  rc = parent_dir(job->dest, member->name, &dirfd, leaf, sizeof(leaf));
  if(rc) {
    return rc;
  }

  if(member->type == '5') {
    rc = mkdirat(dirfd, leaf, 0755) ? FILEOPS_FAILED : FILEOPS_OK;
  } else {
    rc = copy_member(job->archive, member, dirfd, leaf);
  }
  if(dirfd != job->dest) {
    close(dirfd);
  }
  return rc;
}


static void
rewind_archive(const tar_job_t *job) {
  lseek(job->archive, 0, SEEK_SET);
}


/** The sha256 of the open file, from its start, as lowercase hex. **/
static int
digest_fd(int fd, char hex[SHA256_HEX_LEN + 1]) {
  unsigned char digest[SHA256_DIGEST_LEN];
  unsigned char buf[8192];
  sha256_t hash;
  ssize_t got;

  if(lseek(fd, 0, SEEK_SET) < 0) {
    return -1;
  }
  sha256_init(&hash);
  while((got = read(fd, buf, sizeof(buf))) > 0) {
    sha256_update(&hash, buf, (size_t)got);
  }
  if(got < 0) {
    return -1;
  }
  sha256_final(&hash, digest);
  sha256_hex(digest, hex);
  return 0;
}


int
tar_open(const char *root, const char *archive, const char *dest,
         tar_job_t *job, approval_facts_t *facts) {
  struct stat st;
  int rc;

  if(archive[0] != '/' || dest[0] != '/') {
    return FILEOPS_RELATIVE;
  }

  rc = fileops_read_open(root, archive, &job->archive);
  if(rc) {
    return rc;
  }
  rc = fileops_dir_open(root, dest, &job->dest);
  if(rc) {
    close(job->archive);
    return rc;
  }

  if(fstat(job->archive, &st)) {
    tar_close(job);
    return FILEOPS_FAILED;
  }
  if(protected_stat(&st)) {
    tar_close(job);
    return FILEOPS_PROTECTED;
  }
  if(digest_fd(job->archive, facts->sha256)) {
    tar_close(job);
    return FILEOPS_FAILED;
  }

  snprintf(facts->kind, sizeof(facts->kind), "%s", "file");
  facts->dev = (uint64_t)st.st_dev;
  facts->ino = (uint64_t)st.st_ino;
  return FILEOPS_OK;
}


int
tar_vet(tar_job_t *job) {
  rewind_archive(job);
  return tar_walk(job->archive, vet_member, job);
}


int
tar_extract(const char *root, const char *archive, const char *dest,
            const approval_facts_t *expected) {
  approval_facts_t now;
  tar_job_t job;
  int rc;

  memset(&now, 0, sizeof(now));
  rc = tar_open(root, archive, dest, &job, &now);
  if(rc) {
    return rc;
  }

  if(now.dev != expected->dev || now.ino != expected->ino ||
     strcmp(now.sha256, expected->sha256)) {
    tar_close(&job);
    return FILEOPS_CHANGED;
  }

  rc = tar_vet(&job);
  if(rc == FILEOPS_OK) {
    rewind_archive(&job);
    rc = tar_walk(job.archive, write_member, &job);
  }

  tar_close(&job);
  return rc;
}


void
tar_close(tar_job_t *job) {
  if(job->archive >= 0) {
    close(job->archive);
  }
  if(job->dest >= 0) {
    close(job->dest);
  }
  job->archive = -1;
  job->dest = -1;
}
