/* Ariel: the gated file commands, mkdir, rmdir, touch and rm, and the gated
   system commands, mount, umount, chroot and mknod.

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

#ifndef ARIEL_FILEOPS_H
#define ARIEL_FILEOPS_H

#include "platform.h"

/** What one file command's check or action ended in. **/
#define FILEOPS_OK         0
#define FILEOPS_RELATIVE   1
#define FILEOPS_BAD_PATH   2
#define FILEOPS_PROTECTED  3
#define FILEOPS_EXISTS     4
#define FILEOPS_NO_FILE    5
#define FILEOPS_NOT_DIR    6
#define FILEOPS_IS_DIR     7
#define FILEOPS_NOT_FILE   8
#define FILEOPS_LINK       9
#define FILEOPS_CHANGED   10
#define FILEOPS_FAILED    11
#define FILEOPS_BAD_MODE  12
#define FILEOPS_BAD_OWNER 13
#define FILEOPS_BAD_GROUP 14
#define FILEOPS_BAD_ARG   15
#define FILEOPS_TOO_LARGE 16
#define FILEOPS_UNSAFE_MEMBER 17
#define FILEOPS_BAD_ARCHIVE   18

/**
 * Check one file command without acting. path must be absolute and inside a
 * writable root below root (root is "" on a console). operand is the mode,
 * owner or group of chmod, chown or chgrp, and NULL for the others. The
 * entry's kind, device and inode, and the canonical operand, go into facts.
 * Returns FILEOPS_OK when the command could run now, or the refusal that
 * stops it.
 **/
int fileops_check(const char *root, const char *command, const char *path,
                  const char *operand, approval_facts_t *facts);

/**
 * Perform one file command, after checking that the entry and the operand are
 * still the ones expected names. Returns FILEOPS_OK, FILEOPS_CHANGED when they
 * are no longer the expected ones, or the refusal that stops it.
 **/
int fileops_act(const char *root, const char *command, const char *path,
                const char *operand, const approval_facts_t *expected);

/**
 * Check one transfer, cp, mv or ln, from source to destination without acting.
 * Both paths are checked as fileops_check checks one. The source must be a
 * regular file and the destination must not exist. The source's kind, device
 * and inode go into facts. Returns FILEOPS_OK or the refusal that stops it.
 **/
int fileops_transfer_check(const char *root, const char *source,
                           const char *destination, approval_facts_t *facts);

/**
 * Perform one transfer after checking that the source is still the object
 * expected names and that the destination still does not exist. The
 * destination is never replaced. Returns FILEOPS_OK, FILEOPS_CHANGED,
 * FILEOPS_EXISTS or the refusal that stops it.
 **/
int fileops_transfer_act(const char *root, const char *command,
                         const char *source, const char *destination,
                         const approval_facts_t *expected);

/**
 * Parse one system command's arguments into facts: its command, target and
 * options. Returns FILEOPS_OK, or FILEOPS_BAD_ARG for a wrong count or shape.
 **/
int fileops_system_parse(int argc, char *argv[], approval_facts_t *facts);

/**
 * Check a parsed system command without acting: its target's path and
 * identity, a symbolic link to a protected object included, and a mount
 * source that must be a directory. The target's kind, device and inode go
 * into facts. What the target is, file or absent, is judged after the
 * signature, so a target changed since then answers FILEOPS_CHANGED.
 **/
int fileops_system_check(const char *root, approval_facts_t *facts);

/**
 * Check again, after the owner signed, that the target is still the entry
 * the facts name. Returns FILEOPS_OK, FILEOPS_CHANGED, or the refusal.
 **/
int fileops_system_recheck(const char *root, const approval_facts_t *expected);

/**
 * Read the program at path for exec, whole, and return its bytes in *bytes,
 * owned by the caller, with their length in *size. The same checks as
 * fileops_check apply, and a program over the size a store object may have is
 * FILEOPS_TOO_LARGE.
 **/
int fileops_program(const char *root, const char *path, unsigned char **bytes,
                    size_t *size);

/**
 * List the members of the archive at archive, one "<size> <name>" line each,
 * into a buffer of *len bytes that the caller frees. Nothing is written. Returns
 * FILEOPS_OK or the refusal that stops it.
 **/
int fileops_unzip_list(const char *root, const char *archive, char **text,
                       size_t *len);

/**
 * Check one unzip of the archive at archive into destination without acting.
 * The destination must be an existing directory in a writable root. The archive
 * must be a stored zip whose every member stays under destination and replaces
 * nothing. The archive's kind, device, inode and sha256 go into facts. Returns
 * FILEOPS_OK or the refusal that stops it.
 **/
int fileops_unzip_check(const char *root, const char *archive,
                        const char *destination, approval_facts_t *facts);

/**
 * Perform one unzip after checking that the archive is still the one expected
 * names, by identity and sha256. Every member is checked before the first one is
 * written. Returns FILEOPS_OK, FILEOPS_CHANGED or the refusal that stops it.
 **/
int fileops_unzip_act(const char *root, const char *archive,
                      const char *destination,
                      const approval_facts_t *expected);

/** The protocol word of a refusal, and its exit status. **/
const char *fileops_word(int rc);
int fileops_status(int rc);

#endif /* ARIEL_FILEOPS_H */
