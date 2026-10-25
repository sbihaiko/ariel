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

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "protected.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ADDON_DIR "addons"
#define ADDON_DEPTH_MAX 8

static const char *const protected_names[] = {
  "token", "approvals", "nonces", "audit.log", "state", "allowlist", "keyring",
  "grants", ADDON_DIR
};
static char state_dir[PATH_MAX];


void
protected_init(const char *dir) {
  snprintf(state_dir, sizeof(state_dir), "%s", dir);
}


/**
 * Whether dir holds the object file, at any depth up to ADDON_DEPTH_MAX. Links
 * are compared as the entries they are, never followed.
 **/
static int
addon_member(const char *dir, const struct stat *file, int depth) {
  struct dirent *ent;
  DIR *list;
  int found = 0;

  if(depth > ADDON_DEPTH_MAX || !(list=opendir(dir))) {
    return 0;
  }
  while(!found && (ent=readdir(list))) {
    char path[PATH_MAX];
    struct stat st;

    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name)
       >= (int)sizeof(path)) {
      found = 1;
      break;
    }
    if(lstat(path, &st)) {
      continue;
    }
    if(st.st_dev == file->st_dev && st.st_ino == file->st_ino) {
      found = 1;
    } else if(S_ISDIR(st.st_mode)) {
      found = addon_member(path, file, depth + 1);
    }
  }
  closedir(list);

  return found;
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

  if(snprintf(path, sizeof(path), "%s/%s", state_dir, ADDON_DIR)
     >= (int)sizeof(path)) {
    return 1;
  }
  return addon_member(path, file, 0);
}


int
protected_path(const char *path) {
  char prefix[PATH_MAX];
  struct stat st;
  size_t len = strlen(path);
  size_t i;

  for(i=1; i<=len; i++) {
    if(i < len && path[i] != '/') {
      continue;
    }
    if(i >= sizeof(prefix)) {
      return 1;
    }
    memcpy(prefix, path, i);
    prefix[i] = '\0';
    if(stat(prefix, &st)) {
      return 0;
    }
    if(protected_stat(&st)) {
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
