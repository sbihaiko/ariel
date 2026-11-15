/* Copyright (C) 2026 Sandro Bihaiko

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <http://www.gnu.org/licenses/>.  */

/*
 * retro_links: keep RetroArch and ES-DE pointed at the drive that holds the
 * romset.
 *
 * RetroArch boots into ES-DE, and every ROM path it reads is absolute: the
 * three directories in config/retroarch.cfg, ROMDirectory in ES-DE's
 * settings, the ten <path> entries in its systems file, and one path per
 * playlist entry. The drive's mount index changes between boots, and this
 * console answers EOPNOTSUPP to symlink() and to a nullfs mount, so the paths
 * are rewritten instead.
 *
 * The romset is found by content - a marker file, or failing that a folder
 * with both arcade/ and nes/ - and only the paths that stopped resolving are
 * touched: a token /mnt/usbN<rest> that does not exist is replaced by
 * <found usb><rest>, then by <found root><rest>, and left alone when neither
 * exists. Every other byte of the file is kept, and each file is written
 * through a temp file and rename().
 *
 * Every run appends one line to <app>/retro-links.log.
 */

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define USB_COUNT 8
#define PATH_LEN  1024
#define MARKER    ".ariel-retroarch"
#define APP_NAME  "PPSA99169"

/* Empty on the console; the host build points it at a fake tree. */
static const char *root = "";


static void
init_root(void) {
#ifdef ARIEL_HOST_BUILD
  const char *r = getenv("RETRO_LINKS_ROOT");
  if(r != NULL) {
    root = r;
  }
#endif
}


static int
is_dir(const char *path) {
  struct stat st;

  return !stat(path, &st) && S_ISDIR(st.st_mode);
}


/* Whether a path the file spells exists, under the host build's root. */
static int
exists(const char *console_path) {
  char path[PATH_LEN];

  snprintf(path, sizeof(path), "%s%s", root, console_path);
  return !access(path, F_OK);
}


/* The console spelling of a path under the host build's root. */
static const char *
shown(const char *path) {
  size_t n = strlen(root);

  return n && !strncmp(path, root, n) ? path + n : path;
}


/*
 * A roms folder qualifies when it holds the marker, or failing that when it
 * carries both of the two folders every RetroArch-style set has. This is what
 * makes the mount index stop mattering.
 */
static int
dir_qualifies(const char *path) {
  char probe[PATH_LEN];

  if(!is_dir(path)) {
    return 0;
  }
  snprintf(probe, sizeof(probe), "%s/%s", path, MARKER);
  if(!access(probe, F_OK)) {
    return 1;
  }
  snprintf(probe, sizeof(probe), "%s/arcade", path);
  if(!is_dir(probe)) {
    return 0;
  }
  snprintf(probe, sizeof(probe), "%s/nes", path);
  return is_dir(probe);
}


/*
 * Find <usb>/retroarch on the lowest qualifying mount. Fills real (with the
 * host root prefix) and seen (as the console spells it), and dev with the
 * mount that holds it, because the systems file also names <drive>/arcade.
 */
static int
find_library(char *real, size_t real_len, char *seen, size_t seen_len,
             char *dev, size_t dev_len) {
  char candidate[PATH_LEN];
  char path[PATH_LEN];
  int i;

  for(i=0; i<USB_COUNT; i++) {
    snprintf(candidate, sizeof(candidate), "/mnt/usb%d/retroarch", i);
    snprintf(path, sizeof(path), "%s%s", root, candidate);
    if(dir_qualifies(path)) {
      snprintf(real, real_len, "%s", path);
      snprintf(seen, seen_len, "%s", candidate);
      snprintf(dev, dev_len, "/mnt/usb%d", i);
      return 0;
    }
  }
  return -1;
}


/*
 * The app folder is named after its version, which changes on update, so it
 * is found by the settings file it holds. Of several, the lowest name wins.
 */
static int
find_app(char *real, size_t real_len) {
  char base[PATH_LEN];
  char candidate[PATH_LEN];
  char probe[PATH_LEN];
  char best[PATH_LEN];
  struct dirent *ent;
  DIR *dir;
  int found = 0;

  snprintf(base, sizeof(base), "%s/data/homebrew", root);
  if((dir=opendir(base)) == NULL) {
    return -1;
  }
  best[0] = '\0';
  while((ent=readdir(dir))) {
    if(strncmp(ent->d_name, APP_NAME, strlen(APP_NAME))) {
      continue;
    }
    snprintf(candidate, sizeof(candidate), "%s/%s", base, ent->d_name);
    if(!is_dir(candidate)) {
      continue;
    }
    snprintf(probe, sizeof(probe), "%s/es-de/ES-DE/settings/es_settings.xml",
             candidate);
    if(access(probe, F_OK)) {
      continue;
    }
    if(!found || strcmp(ent->d_name, best) < 0) {
      snprintf(best, sizeof(best), "%s", ent->d_name);
      found = 1;
    }
  }
  closedir(dir);
  if(!found) {
    return -1;
  }
  snprintf(real, real_len, "%s/%s", base, best);
  return 0;
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


struct out {
  char *data;
  size_t len;
  size_t cap;
};


static int
out_add(struct out *o, const char *text, size_t n) {
  size_t want = o->len + n + 1;

  if(want > o->cap) {
    size_t cap = o->cap ? o->cap : 4096;
    char *grown;

    while(cap < want) {
      cap *= 2;
    }
    if((grown=realloc(o->data, cap)) == NULL) {
      return -1;
    }
    o->data = grown;
    o->cap = cap;
  }
  memcpy(o->data + o->len, text, n);
  o->len += n;
  o->data[o->len] = '\0';
  return 0;
}


/* The replacement for one path token, or NULL when it must stay as it is. */
static const char *
repair_token(const char *token, size_t token_len, const char *dev,
             const char *library, char *buffer, size_t buffer_len) {
  char current[PATH_LEN];
  char candidate[PATH_LEN];
  const char *rest;
  size_t skip;

  if(token_len >= sizeof(current)) {
    return NULL;
  }
  memcpy(current, token, token_len);
  current[token_len] = '\0';
  if(token[0] != '/' || strncmp(token, "/mnt/usb", 8) || token[8] < '0' || token[8] > '9') {
    return NULL;
  }
  if(exists(current)) {
    return NULL;
  }
  /* Past "/mnt/usb<digit>". */
  skip = 9;
  while(skip < token_len && token[skip] >= '0' && token[skip] <= '9') {
    skip++;
  }
  rest = current + skip;
  snprintf(candidate, sizeof(candidate), "%s%s", dev, rest);
  if(exists(candidate)) {
    snprintf(buffer, buffer_len, "%s", candidate);
    return buffer;
  }
  snprintf(candidate, sizeof(candidate), "%s%s", library, rest);
  if(exists(candidate)) {
    snprintf(buffer, buffer_len, "%s", candidate);
    return buffer;
  }
  return NULL;
}


/*
 * Rewrite every broken path token in `text`. Returns 0 with *changed set to
 * the number of tokens replaced, -1 when memory ran out.
 */
static int
repair_text(const char *text, size_t len, const char *dev, const char *library,
            char **result, size_t *result_len, int *changed) {
  struct out o = {NULL, 0, 0};
  size_t at = 0;
  size_t copy_from = 0;

  *changed = 0;
  while(at < len) {
    size_t begin;
    size_t end;
    char replacement[PATH_LEN];
    const char *fixed;

    if(text[at] != '/' || at + 8 >= len || strncmp(text + at, "/mnt/usb", 8)) {
      at++;
      continue;
    }
    begin = at + 8;
    if(text[begin] < '0' || text[begin] > '9') {
      at++;
      continue;
    }
    end = begin;
    while(end < len && text[end] != '"' && text[end] != '<' &&
          text[end] != '\n' && text[end] != '\r') {
      end++;
    }
    fixed = repair_token(text + at, end - at, dev, library,
                         replacement, sizeof(replacement));
    if(fixed == NULL) {
      at = end;
      continue;
    }
    if(out_add(&o, text + copy_from, at - copy_from) ||
       out_add(&o, fixed, strlen(fixed))) {
      free(o.data);
      return -1;
    }
    (*changed)++;
    copy_from = end;
    at = end;
  }
  if(out_add(&o, text + copy_from, len - copy_from)) {
    free(o.data);
    return -1;
  }
  *result = o.data;
  *result_len = o.len;
  return 0;
}


/*
 * One file through temp and rename, keeping the mode the app expects to write
 * it with. Returns 0 when unchanged or absent, 1 when rewritten, -1 on
 * failure. An absent file is not a failure: a version of the app may not
 * carry every file this one does.
 */
static int
repair_file(const char *path, const char *dev, const char *library,
            int *changed_paths) {
  char temp[PATH_LEN + 16];
  struct stat st;
  char *text;
  char *fixed;
  size_t fixed_len;
  long len;
  int changed;
  FILE *file;

  if(access(path, F_OK)) {
    return 0;
  }
  if((text=read_file(path, &len)) == NULL) {
    return -1;
  }
  if(repair_text(text, (size_t)len, dev, library, &fixed, &fixed_len, &changed)) {
    free(text);
    return -1;
  }
  free(text);
  if(changed == 0) {
    free(fixed);
    return 0;
  }
  *changed_paths += changed;
  if(snprintf(temp, sizeof(temp), "%s.ariel-tmp", path) >= (int)sizeof(temp)) {
    free(fixed);
    return -1;
  }
  if((file=fopen(temp, "wb")) == NULL) {
    free(fixed);
    return -1;
  }
  if(fwrite(fixed, 1, fixed_len, file) != fixed_len || fclose(file)) {
    free(fixed);
    unlink(temp);
    return -1;
  }
  if(!stat(path, &st)) {
    chmod(temp, st.st_mode & 07777);
  }
  free(fixed);
  if(rename(temp, path)) {
    unlink(temp);
    return -1;
  }
  return 1;
}


/*
 * Answer one line on stdout and in the log, when the app folder is known.
 */
static void
answer(const char *app, const char *format, ...) {
  char line[PATH_LEN * 2];
  char path[PATH_LEN];
  va_list args;
  FILE *log;

  va_start(args, format);
  vsnprintf(line, sizeof(line), format, args);
  va_end(args);
  printf("%s\n", line);
  fflush(stdout);

  if(app == NULL) {
    return;
  }
  snprintf(path, sizeof(path), "%s/retro-links.log", app);
  if((log=fopen(path, "a")) != NULL) {
    fprintf(log, "%s\n", line);
    fclose(log);
  }
}


int
main(int argc, char **argv) {
  char library[PATH_LEN];
  char seen[PATH_LEN];
  char dev[PATH_LEN];
  char app[PATH_LEN];
  char path[PATH_LEN];
  char base[PATH_LEN];
  int changed_paths = 0;
  struct dirent *ent;
  DIR *dir;

  (void)argc;
  (void)argv;
  init_root();

  if(find_library(library, sizeof(library), seen, sizeof(seen),
                  dev, sizeof(dev))) {
    answer(NULL, "retro-link no_usb_library");
    return 0;
  }
  if(find_app(app, sizeof(app))) {
    answer(NULL, "retro-link no_app");
    return 0;
  }

  snprintf(path, sizeof(path), "%s/config/retroarch.cfg", app);
  if(repair_file(path, dev, seen, &changed_paths) < 0) {
    answer(app, "retro-link failed %s", shown(path));
    return 1;
  }
  snprintf(path, sizeof(path), "%s/es-de/ES-DE/settings/es_settings.xml", app);
  if(repair_file(path, dev, seen, &changed_paths) < 0) {
    answer(app, "retro-link failed %s", shown(path));
    return 1;
  }
  snprintf(path, sizeof(path), "%s/es-de/ES-DE/custom_systems/es_systems.xml", app);
  if(repair_file(path, dev, seen, &changed_paths) < 0) {
    answer(app, "retro-link failed %s", shown(path));
    return 1;
  }

  snprintf(base, sizeof(base), "%s/playlists", app);
  if((dir=opendir(base)) != NULL) {
    while((ent=readdir(dir))) {
      size_t n = strlen(ent->d_name);

      if(n < 5 || strcmp(ent->d_name + n - 4, ".lpl")) {
        continue;
      }
      snprintf(path, sizeof(path), "%s/%s", base, ent->d_name);
      if(repair_file(path, dev, seen, &changed_paths) < 0) {
        closedir(dir);
        answer(app, "retro-link failed %s", shown(path));
        return 1;
      }
    }
    closedir(dir);
  }

  if(changed_paths == 0) {
    answer(app, "retro-link unchanged %s", seen);
    return 0;
  }
  answer(app, "retro-link set %s paths=%d", seen, changed_paths);
  return 0;
}
