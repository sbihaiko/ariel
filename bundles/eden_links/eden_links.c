/* Copyright (C) 2026 Sandro Bihaiko

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <http://www.gnu.org/licenses/>.  */

/*
 * eden_links: keep Eden pointed at the drive that holds its library.
 *
 * The drive's mount index changes between boots, so the library is found by
 * content - a marker file, or failing that, at least one .nsp - and Eden's
 * settings are given that folder as its game files folder.
 *
 * A symlink would have been the obvious answer, but this console's filesystem
 * answers EOPNOTSUPP to symlink() and to a nullfs mount, so the setting is
 * written instead. Only the value of "game_files" changes; every other byte of
 * the settings file is left as it was.
 *
 * Every run appends one line to /data/prosperoeden/eden-links.log.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#define USB_COUNT 8
#define PATH_LEN  1024
#define MARKER    ".ariel-eden"

/* Empty on the console; the host build points it at a fake tree. */
static const char *root = "";


static void
init_root(void) {
#ifdef ARIEL_HOST_BUILD
  const char *r = getenv("EDEN_LINKS_ROOT");
  if(r != NULL) {
    root = r;
  }
#endif
}


static int
has_suffix(const char *name, const char *suffix) {
  size_t n = strlen(name);
  size_t s = strlen(suffix);

  return n > s && !strcmp(name + n - s, suffix);
}


/*
 * A title is a directory holding its .nsp, so one level below the library is
 * the shallowest place a library's first title can be found.
 */
static int
holds_nsp(const char *path, int depth) {
  char child[PATH_LEN];
  struct dirent *ent;
  DIR *dir;

  if(depth <= 0 || (dir=opendir(path)) == NULL) {
    return 0;
  }
  while((ent=readdir(dir))) {
    if(ent->d_name[0] == '.') {
      continue;
    }
    if(has_suffix(ent->d_name, ".nsp") || has_suffix(ent->d_name, ".NSP")) {
      closedir(dir);
      return 1;
    }
    snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
    if(holds_nsp(child, depth - 1)) {
      closedir(dir);
      return 1;
    }
  }
  closedir(dir);
  return 0;
}


/*
 * A roms folder qualifies when it holds the marker, or failing that, at least
 * one .nsp, directly or in a title folder. This is what makes the mount index
 * stop mattering.
 */
static int
dir_qualifies(const char *path) {
  char probe[PATH_LEN];
  struct stat st;

  if(stat(path, &st) || !S_ISDIR(st.st_mode)) {
    return 0;
  }
  snprintf(probe, sizeof(probe), "%s/%s", path, MARKER);
  if(!access(probe, F_OK)) {
    return 1;
  }
  return holds_nsp(path, 2);
}


/*
 * Find the game files folder on the lowest qualifying mount: <usb>/eden/roms
 * first, then <usb>/roms, and the folder that holds roms is the one Eden is
 * given. Fills real (with the host root prefix) and shown (as the console
 * spells it).
 */
static int
find_library(char *real, size_t real_len, char *shown, size_t shown_len) {
  char candidate[PATH_LEN];
  char path[PATH_LEN];
  int i;

  for(i=0; i<USB_COUNT; i++) {
    snprintf(candidate, sizeof(candidate), "/mnt/usb%d/eden", i);
    snprintf(path, sizeof(path), "%s%s/roms", root, candidate);
    if(dir_qualifies(path)) {
      snprintf(real, real_len, "%s%s", root, candidate);
      snprintf(shown, shown_len, "%s", candidate);
      return 0;
    }
    snprintf(candidate, sizeof(candidate), "/mnt/usb%d", i);
    snprintf(path, sizeof(path), "%s%s/roms", root, candidate);
    if(dir_qualifies(path)) {
      snprintf(real, real_len, "%s%s", root, candidate);
      snprintf(shown, shown_len, "%s", candidate);
      return 0;
    }
  }
  return -1;
}


static char *
read_file(const char *path, long *len) {
  char *buf;
  FILE *file;
  long size;

  if((file=fopen(path, "rb")) == NULL) {
    return NULL;
  }
  if(fseek(file, 0, SEEK_END) || (size=ftell(file)) < 0 || fseek(file, 0, SEEK_SET)) {
    fclose(file);
    return NULL;
  }
  if((buf=malloc((size_t)size + 1)) == NULL) {
    fclose(file);
    return NULL;
  }
  if(fread(buf, 1, (size_t)size, file) != (size_t)size) {
    free(buf);
    fclose(file);
    return NULL;
  }
  fclose(file);
  buf[size] = '\0';
  *len = size;
  return buf;
}


static const char *
skip_space(const char *p) {
  while(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
    p++;
  }
  return p;
}


/*
 * Give "game_files" the value `folder`, leaving every other byte of the
 * settings file alone. Returns 0 when the file changed, 1 when it already said
 * so, -1 when it could not be written.
 */
static int
write_text(FILE *file, const char *text, size_t len) {
  if(len == 0) {
    return 0;
  }
  return fwrite(text, 1, len, file) == len ? 0 : -1;
}


static int
set_game_files(const char *path, const char *folder) {
  char temp[PATH_LEN];
  char quoted[PATH_LEN];
  const char *key = "\"game_files\"";
  const char *at;
  const char *open;
  const char *begin;
  const char *end;
  char *text;
  long len;
  FILE *file;
  int answer;

  if((text=read_file(path, &len)) == NULL) {
    return -1;
  }
  snprintf(quoted, sizeof(quoted), "\"%s\"", folder);
  snprintf(temp, sizeof(temp), "%s.ariel-tmp", path);

  if((at=strstr(text, key)) != NULL) {
    open = at + strlen(key);
    open = skip_space(open);
    if(*open != ':') {
      free(text);
      return -1;
    }
    open = skip_space(open + 1);
    if(*open != '"') {
      free(text);
      return -1;
    }
    begin = open + 1;
    if((end=strchr(begin, '"')) == NULL) {
      free(text);
      return -1;
    }
    if((size_t)(end - begin) == strlen(folder) &&
       !strncmp(begin, folder, (size_t)(end - begin))) {
      free(text);
      return 1;
    }
    if((file=fopen(temp, "wb")) == NULL) {
      free(text);
      return -1;
    }
    /* Up to the opening quote, the new quoted value, then from just past the
     * closing quote to the end of the file. */
    answer = write_text(file, text, (size_t)(open - text)) ||
             write_text(file, quoted, strlen(quoted)) ||
             write_text(file, end + 1, (size_t)(len - (end + 1 - text)));
  } else {
    /* The setting is absent: add it as the first member of the object. */
    char *brace = strchr(text, '{');

    if(brace == NULL) {
      free(text);
      return -1;
    }
    if((file=fopen(temp, "wb")) == NULL) {
      free(text);
      return -1;
    }
    answer = write_text(file, text, (size_t)(brace - text) + 1) ||
             fprintf(file, "\n  \"game_files\": %s,", quoted) < 0 ||
             write_text(file, brace + 1, (size_t)(len - (brace - text) - 1));
  }
  free(text);
  if(answer || fclose(file)) {
    unlink(temp);
    return -1;
  }
  if(rename(temp, path)) {
    unlink(temp);
    return -1;
  }
  return 0;
}


/*
 * Answer one line on stdout and in the log, when /data/prosperoeden exists.
 */
static void
answer(const char *format, const char *arg) {
  char line[PATH_LEN];
  char path[PATH_LEN];
  FILE *log;

  if(arg != NULL) {
    snprintf(line, sizeof(line), format, arg);
  } else {
    snprintf(line, sizeof(line), "%s", format);
  }
  printf("%s\n", line);
  fflush(stdout);

  snprintf(path, sizeof(path), "%s/data/prosperoeden/eden-links.log", root);
  if((log=fopen(path, "a")) != NULL) {
    fprintf(log, "%s\n", line);
    fclose(log);
  }
}


int
main(int argc, char **argv) {
  char target[PATH_LEN];
  char shown[PATH_LEN];
  char config[PATH_LEN];
  int rc;

  (void)argc;
  (void)argv;
  init_root();

  if(find_library(target, sizeof(target), shown, sizeof(shown))) {
    answer("eden-link no_usb_library", NULL);
    return 0;
  }

  snprintf(config, sizeof(config), "%s/data/prosperoeden/config/prosperoeden.json", root);
  rc = set_game_files(config, shown);
  if(rc < 0) {
    answer("eden-link failed settings %s", shown);
    return 1;
  }
  if(rc == 1) {
    answer("eden-link unchanged %s", shown);
    return 0;
  }
  answer("eden-link set %s", shown);
  return 0;
}
