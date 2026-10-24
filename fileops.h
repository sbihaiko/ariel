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

/**
 * Check one file command without acting. path must be absolute and inside a
 * writable root below root (root is "" on a console). The entry's kind, device
 * and inode go into facts. Returns FILEOPS_OK when the command could run now,
 * or the refusal that stops it.
 **/
int fileops_check(const char *root, const char *command, const char *path,
                  approval_facts_t *facts);

/**
 * Perform one file command, after checking that the entry is still the one
 * expected names. Returns FILEOPS_OK, FILEOPS_CHANGED when the entry is no
 * longer the expected one, or the refusal that stops it.
 **/
int fileops_act(const char *root, const char *command, const char *path,
                const approval_facts_t *expected);

/** The protocol word of a refusal, and its exit status. **/
const char *fileops_word(int rc);
int fileops_status(int rc);

#endif /* ARIEL_FILEOPS_H */
