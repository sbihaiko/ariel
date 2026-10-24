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

#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "protected.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char *const protected_names[] = {
  "token", "approvals", "nonces", "audit.log", "state", "allowlist", "keyring"
};
static char state_dir[PATH_MAX];


void
protected_init(const char *dir) {
  snprintf(state_dir, sizeof(state_dir), "%s", dir);
}


int
protected_stat(const struct stat *file) {
  struct stat guard;
  char path[PATH_MAX];
  size_t i;

  if(!stat(state_dir, &guard) &&
     guard.st_dev == file->st_dev && guard.st_ino == file->st_ino) {
    return 1;
  }

  for(i=0; i<sizeof(protected_names)/sizeof(protected_names[0]); i++) {
    if(snprintf(path, sizeof(path), "%s/%s", state_dir, protected_names[i])
       >= (int)sizeof(path)) {
      return 1;
    }
    if(!stat(path, &guard) &&
       guard.st_dev == file->st_dev && guard.st_ino == file->st_ino) {
      return 1;
    }
  }

  return 0;
}


int
protected_object(int fd) {
  struct stat file;

  if(fstat(fd, &file)) {
    return -1;
  }

  return protected_stat(&file);
}
