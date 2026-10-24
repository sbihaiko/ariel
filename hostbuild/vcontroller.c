/* Ariel host build: the virtual controller, a host-only test aid.

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

/*
 * The virtual controller exists only in the host build. A PS5 build never
 * defines ARIEL_HOST_BUILD, so it cannot compile this file in: approvals
 * on a console are the owner's signature, and nothing a payload or the
 * network can drive.
 */
#ifndef ARIEL_HOST_BUILD
#error "the virtual controller is host-only"
#endif

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "store.h"
#include "testclock.h"
#include "vcontroller.h"

/** The longest prompt text the controller shows. **/
#define PROMPT_MAX 256

static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t started = PTHREAD_ONCE_INIT;


/**
 * Print one line, under the output lock, so lines from the request thread
 * and the controller thread never interleave.
 **/
static void
print_line(const char *fmt, ...) {
  va_list args;

  pthread_mutex_lock(&out_lock);
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  putchar('\n');
  fflush(stdout);
  pthread_mutex_unlock(&out_lock);
}


static void
deny(const char *id) {
  if(store_approval_deny(id)) {
    print_line("unknown_approval %s", id);
    return;
  }

  print_line("denied %s", id);
}


static void
handle_line(char *line) {
  char clock_reply[64];
  size_t len = strlen(line);

  while(len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
    line[--len] = '\0';
  }

  // The clock is the host build's other test aid: it shares this input.
  if(testclock_handle_line(line, clock_reply, sizeof(clock_reply))) {
    print_line("%s", clock_reply);
  } else if(!strncmp(line, "deny ", 5)) {
    deny(line + 5);
  } else if(len > 0) {
    print_line("unknown_command");
  }
}


static void *
read_commands(void *arg) {
  char *line = NULL;
  size_t cap = 0;

  (void)arg;

  while(getline(&line, &cap, stdin) >= 0) {
    handle_line(line);
  }

  free(line);
  return NULL;
}


static void
start_reader(void) {
  pthread_t thread;

  if(pthread_create(&thread, NULL, read_commands, NULL)) {
    fprintf(stderr, "vcontroller: cannot start the input reader\n");
    return;
  }
  pthread_detach(thread);
}


void
vcontroller_start(void) {
  pthread_once(&started, start_reader);
}


int
vcontroller_request(const approval_facts_t *facts,
                    approval_challenge_t *challenge) {
  char prompt[PROMPT_MAX];

  if(store_approval_request(facts, challenge, prompt, sizeof(prompt))) {
    return -1;
  }

  // Show the prompt the owner would see, and only then let the decision
  // arrive, so a test never answers an ID it could not have seen.
  print_line("prompt %s %s", challenge->id, prompt);

  return 0;
}
