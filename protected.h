/* Ariel: the objects no agent-port command may touch.

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

#ifndef ARIEL_PROTECTED_H
#define ARIEL_PROTECTED_H

#include <sys/stat.h>

/**
 * Record Ariel's state directory. The token, the approval state and the
 * consumed nonces below it are protected. Call once, before any command.
 **/
void protected_init(const char *state_dir);

/**
 * Whether the file behind fd is a protected object. The check compares the
 * device and inode of the open file, so a symbolic link or a hard link to a
 * protected file is the same object. Returns 1 when it is, 0 when it is not,
 * -1 on error.
 **/
int protected_object(int fd);

/**
 * Whether the object with the identity in file is a protected one, by the
 * same device and inode test as protected_object: the state directory itself,
 * the objects named below it, the addon directory and every object in it.
 * Returns 1 or 0.
 **/
int protected_stat(const struct stat *file);

/**
 * Whether the absolute path names a protected object, or passes through a
 * protected directory. Each prefix of path is statted, following links, so a
 * link into a protected directory counts. Returns 1 or 0.
 **/
int protected_path(const char *path);

#endif /* ARIEL_PROTECTED_H */
