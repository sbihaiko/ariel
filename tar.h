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

#ifndef ARIEL_TAR_H
#define ARIEL_TAR_H

#include <sys/types.h>

#include "platform.h"

#define TAR_NAME_MAX 256
#define TAR_LINK_MAX 101

/** One member of an archive: its name, type, link target and data. **/
typedef struct {
  char name[TAR_NAME_MAX + 1];
  char link[TAR_LINK_MAX];
  char type;
  uint64_t size;
  off_t offset;
} tar_member_t;

/** The two descriptors of one tar: the archive and the destination directory. **/
typedef struct {
  int archive;
  int dest;
} tar_job_t;

/**
 * Read a ustar archive from fd, from its current offset, and call emit with
 * each member in archive order. Returns FILEOPS_OK at the end of the archive,
 * FILEOPS_NOT_TAR when a header is not one, or the first non-OK result of
 * emit.
 **/
typedef int (*tar_emit_fn)(void *ctx, const tar_member_t *member);
int tar_walk(int fd, tar_emit_fn emit, void *ctx);

/**
 * Open the archive at archive and the directory at dest, both absolute, and
 * fill facts with the archive's kind, device, inode and sha256. Returns
 * FILEOPS_OK or the refusal that stops it; nothing is left open then.
 **/
int tar_open(const char *root, const char *archive, const char *dest,
             tar_job_t *job, approval_facts_t *facts);

/**
 * Check every member of an open archive without writing: a member that
 * escapes dest, a link or other member extraction does not make, and an entry
 * already under dest. Returns FILEOPS_OK or the first refusal.
 **/
int tar_vet(tar_job_t *job);

/**
 * Extract an approved archive into its destination. The archive and the
 * destination are opened again and must still be the expected object, then
 * every member is vetted before the first one is written.
 **/
int tar_extract(const char *root, const char *archive, const char *dest,
                const approval_facts_t *expected);

void tar_close(tar_job_t *job);

#endif /* ARIEL_TAR_H */
