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
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "protected.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ADDON_DIR "addons"

static const char *const protected_names[] = {
  "token", "approvals", "nonces", "audit.log", "state", "allowlist", "keyring",
  "grants", ADDON_DIR
};
static char state_dir[PATH_MAX];


void
protected_init(const char *dir) {
  snprintf(state_dir, sizeof(state_dir), "%s", dir);
}


static int
push_dir(char ***todo, size_t *count, size_t *cap, const char *path) {
  char **grown;

  if(*count == *cap) {
    size_t next = *cap ? *cap * 2 : 8;

    if(!(grown=realloc(*todo, next * sizeof(*grown)))) {
      return -1;
    }
    *todo = grown;
    *cap = next;
  }
  if(!((*todo)[*count]=strdup(path))) {
    return -1;
  }
  (*count)++;

  return 0;
}


/**
 * Whether the object file is in the addon directory tree at any depth. The
 * walk keeps its own list of directories, and no link below root is followed.
 * Returns 1 when it is, 0 when it is not, and -1 when some part of the tree
 * could not be read, so the caller must treat the object as protected.
 **/
static int
addon_member(const char *root, const struct stat *file) {
  char **todo = NULL;
  size_t count = 0;
  size_t cap = 0;
  struct stat top;
  int found = 0;
  int failed = 0;
  size_t i;

  if(stat(root, &top)) {
    return errno == ENOENT ? 0 : -1;
  }
  if(!S_ISDIR(top.st_mode)) {
    return 0;
  }
  if(push_dir(&todo, &count, &cap, root)) {
    return -1;
  }

  while(count > 0 && !found && !failed) {
    char *here = todo[--count];
    struct dirent *ent;
    DIR *list = opendir(here);

    if(!list) {
      failed = 1;
    }
    while(list && !found && !failed) {
      char path[PATH_MAX];
      struct stat st;

      errno = 0;
      if(!(ent=readdir(list))) {
        failed = errno != 0;
        break;
      }
      if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
        continue;
      }
      if(snprintf(path, sizeof(path), "%s/%s", here, ent->d_name)
         >= (int)sizeof(path) || lstat(path, &st)) {
        failed = 1;
        break;
      }
      if(st.st_dev == file->st_dev && st.st_ino == file->st_ino) {
        found = 1;
      } else if(S_ISDIR(st.st_mode) && push_dir(&todo, &count, &cap, path)) {
        failed = 1;
      }
    }
    if(list) {
      closedir(list);
    }
    free(here);
  }

  for(i=0; i<count; i++) {
    free(todo[i]);
  }
  free(todo);

  if(found) {
    return 1;
  }
  return failed ? -1 : 0;
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
  return addon_member(path, file) != 0;
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
