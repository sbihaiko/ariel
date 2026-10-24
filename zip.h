/* Ariel: the zip archives unzip reads.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#ifndef ARIEL_ZIP_H
#define ARIEL_ZIP_H

#include <stddef.h>

/** The longest member name an archive may carry, and the most members. **/
#define ZIP_NAME_MAX    255
#define ZIP_MEMBERS_MAX 512

/** What reading an archive ended in. **/
#define ZIP_OK  0
#define ZIP_BAD 1

/**
 * One member of an archive held in memory: its name, its bytes and whether it
 * is a directory. Only stored members are read; any other method is ZIP_BAD.
 **/
typedef struct {
  char name[ZIP_NAME_MAX + 1];
  const unsigned char *data;
  size_t size;
  int dir;
} zip_member_t;

/**
 * Read the central directory of the archive in buf, len bytes, into members,
 * at most max of them, and set count. Returns ZIP_BAD for an archive this
 * reader does not trust: a damaged or zip64 record, a member outside the
 * archive, an encrypted or compressed member, a name with control characters,
 * or two names that clash. The members point into buf, which must outlive them.
 **/
int zip_members(const unsigned char *buf, size_t len, zip_member_t *members,
                size_t max, size_t *count);

/**
 * Whether name stays under the directory it is extracted into: relative, with
 * no empty, '.' or '..' component and no backslash. A trailing '/' is allowed.
 **/
int zip_name_safe(const char *name);

#endif /* ARIEL_ZIP_H */
