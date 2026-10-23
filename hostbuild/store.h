/* Ariel host build: staging, approvals and the hash-addressed store.

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

#ifndef ARIEL_STORE_H
#define ARIEL_STORE_H

#include <stddef.h>

#include "platform.h"

/**
 * Ariel's state: the staged objects, the pending approvals and the store
 * live in this process's memory under one mutex, so consuming an approval
 * is atomic and approvals die with the process. Nothing here survives a
 * restart except the store's files.
 **/

/** What one payload commit ended in. **/
#define STORE_INSTALLED         0
#define STORE_APPROVAL_REQUIRED 1
#define STORE_APPROVAL_DENIED   2
#define STORE_APPROVAL_STALE    3

/** What a successful commit installed. **/
typedef struct {
  char name[PAYLOAD_NAME_MAX + 1];
  char sha256[65];
} store_install_t;

/** How reading a payload back for a run ended. **/
#define STORE_RUN_OK      0
#define STORE_RUN_UNKNOWN 1
#define STORE_RUN_STALE   2

/** The verified bytes of one payload, held in memory until they are freed. **/
typedef struct {
  unsigned char *bytes;
  size_t size;
} store_object_t;

/** Whether name follows the payload-name grammar. Returns 1 when it does. **/
int store_name_valid(const char *name);

/**
 * Record the state directory, delete the staging objects a previous
 * process left behind and make the store's directories. Returns 0 on
 * success, -1 on error.
 **/
int store_init(const char *state_dir);

/** Take the next staging ID: s-1, s-2, and so on. **/
void store_staging_next_id(char *id, size_t size);

/**
 * Take a staging slot, create the staging object for a new upload and
 * return its descriptor, opened relative to Ariel's directory without
 * following symbolic links. Returns -1 when the staging slots are all
 * taken or on error.
 **/
int store_staging_create(const char *staging_id);

/** Delete a staging object that never got an approval. **/
void store_staging_discard(const char *staging_id);

/**
 * Ask the owner to approve facts. On success write the approval ID into
 * id and the text the owner would see into prompt, and take one pending
 * slot. Returns 0, or -1 when no approval can be requested now: at most
 * three approvals wait for a decision at once.
 **/
int store_approval_request(const approval_facts_t *facts, char *id,
                           size_t idlen, char *prompt, size_t promptlen);

/** Record the owner's decision. Returns 0, or -1 for an unknown ID. **/
int store_approval_decide(const char *id, int approved);

/** Bind a staged object to the approval that names it. **/
void store_stage(const char *staging_id, const approval_facts_t *facts,
                 const char *approval_id);

/**
 * Commit a staged object: ask after its approval, hash the object again,
 * consume the approval and move the object into the store. Returns one of
 * STORE_*; on STORE_INSTALLED install holds what was installed, and on
 * STORE_APPROVAL_REQUIRED approval_id holds the pending approval's ID.
 **/
int store_commit(const char *staging_id, store_install_t *install,
                 char *approval_id, size_t idlen);

/**
 * Read the current object of a payload name into memory once, hash those
 * bytes and compare the hash with the store's current record. The object
 * is opened through that record and never followed. Returns STORE_RUN_OK
 * with the verified bytes, STORE_RUN_UNKNOWN when the name has no record,
 * or STORE_RUN_STALE when the object no longer matches it.
 **/
int store_run_load(const char *name, store_object_t *object);

/** Free the bytes of an object store_run_load returned. **/
void store_object_free(store_object_t *object);

#endif /* ARIEL_STORE_H */
