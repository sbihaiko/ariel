/* Ariel: the noninteractive command runner.

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "runner.h"


static void
say(int fd, const char *text) {
  size_t len = strlen(text);

  while(len > 0) {
    ssize_t n = write(fd, text, len);

    if(n < 0) {
      if(errno == EINTR) {
        continue;
      }
      return;
    }
    text += n;
    len -= (size_t)n;
  }
}


static int
name_cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}


static int
run_ls(int argc, char *const argv[], int outfd, int errfd) {
  char **names = NULL;
  size_t count = 0;
  size_t cap = 0;
  struct dirent *ent;
  DIR *dir;
  size_t i;
  int rc = 0;

  if(argc != 2 || argv[1][0] != '/') {
    say(errfd, "relative_path\n");
    return 1;
  }

  if(!(dir = opendir(argv[1]))) {
    say(errfd, "ls: ");
    say(errfd, argv[1]);
    say(errfd, ": ");
    say(errfd, strerror(errno));
    say(errfd, "\n");
    return 1;
  }

  while((ent = readdir(dir))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
      continue;
    }
    if(count == cap) {
      char **grown = realloc(names, (cap ? cap * 2 : 64) * sizeof(*names));

      if(!grown) {
        rc = 1;
        break;
      }
      names = grown;
      cap = cap ? cap * 2 : 64;
    }
    if(!(names[count] = strdup(ent->d_name))) {
      rc = 1;
      break;
    }
    count++;
  }
  closedir(dir);

  if(rc) {
    say(errfd, "ls: out of memory\n");
  } else {
    qsort(names, count, sizeof(*names), name_cmp);
    for(i=0; i<count; i++) {
      say(outfd, names[i]);
      say(outfd, "\n");
    }
  }

  for(i=0; i<count; i++) {
    free(names[i]);
  }
  free(names);

  return rc;
}


int
runner_run(int argc, char *const argv[], int outfd, int errfd, int *status) {
  if(argc == 1 && !strcmp(argv[0], "pwd")) {
    say(outfd, "/\n");
    *status = 0;
    return 0;
  }

  if(argc >= 1 && !strcmp(argv[0], "ls")) {
    *status = run_ls(argc, argv, outfd, errfd);
    return 0;
  }

  if(argc >= 1 && !strcmp(argv[0], "cd")) {
    say(errfd, "no_working_directory\n");
    *status = 1;
    return 0;
  }

  return -1;
}
