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

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vcontroller.h"

/** At most this many approvals wait for a decision at once. **/
#define PENDING_MAX 3

/** The longest prompt text the controller shows. **/
#define PROMPT_MAX 256

#define DECISION_PENDING  0
#define DECISION_APPROVED 1
#define DECISION_DENIED  -1

struct pending {
  int used;
  int decision;
  char id[APPROVAL_ID_MAX];
  approval_facts_t facts;
};

static struct pending pending[PENDING_MAX];
static unsigned long request_count;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
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


static struct pending *
find_pending(const char *id) {
  int i;

  for(i=0; i<PENDING_MAX; i++) {
    if(pending[i].used && !strcmp(pending[i].id, id)) {
      return &pending[i];
    }
  }
  return NULL;
}


static void
decide(const char *id, int decision) {
  struct pending *request;

  pthread_mutex_lock(&lock);
  request = find_pending(id);

  if(!request || request->decision != DECISION_PENDING) {
    pthread_mutex_unlock(&lock);
    print_line("unknown_approval %s", id);
    return;
  }

  request->decision = decision;
  pthread_mutex_unlock(&lock);

  print_line("%s %s", decision == DECISION_APPROVED ? "approved" : "denied",
             id);
}


static void
handle_line(char *line) {
  size_t len = strlen(line);

  while(len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
    line[--len] = '\0';
  }

  if(!strncmp(line, "approve ", 8)) {
    decide(line + 8, DECISION_APPROVED);
  } else if(!strncmp(line, "deny ", 5)) {
    decide(line + 5, DECISION_DENIED);
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
vcontroller_request(const approval_facts_t *facts, char *id, size_t idlen) {
  char prompt[PROMPT_MAX];
  struct pending *slot = NULL;
  int i;

  if(snprintf(prompt, sizeof(prompt),
              "payload %s (%llu bytes, sha256 %s) will run",
              facts->name, (unsigned long long)facts->size,
              facts->sha256) >= (int)sizeof(prompt)) {
    return -1;
  }

  pthread_mutex_lock(&lock);

  for(i=0; i<PENDING_MAX; i++) {
    // A decided request no longer waits for an answer, so its slot is free.
    if(!pending[i].used || pending[i].decision != DECISION_PENDING) {
      slot = &pending[i];
      break;
    }
  }

  if(!slot) {
    pthread_mutex_unlock(&lock);
    return -1;
  }

  memset(slot, 0, sizeof(*slot));
  slot->used = 1;
  slot->decision = DECISION_PENDING;
  snprintf(slot->id, sizeof(slot->id), "a-%lx", ++request_count);
  slot->facts = *facts;

  // Show the prompt the owner would see, and only then let the decision
  // arrive, so a test never approves an ID it could not have seen.
  print_line("prompt %s %s", slot->id, prompt);

  if(snprintf(id, idlen, "%s", slot->id) >= (int)idlen) {
    slot->used = 0;
    pthread_mutex_unlock(&lock);
    return -1;
  }

  pthread_mutex_unlock(&lock);
  return 0;
}
