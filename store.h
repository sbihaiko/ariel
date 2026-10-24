/* Ariel: staging, approvals and the hash-addressed store.

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
 * restart except the store's files and the consumed nonces.
 **/

/**
 * An approval is good for this long after it was requested. The platform
 * reads it too: a console shows the prompt for exactly this long.
 **/
#define APPROVAL_EXPIRY_MS 120000ULL

/** What one payload commit ended in. **/
#define STORE_INSTALLED         0
#define STORE_APPROVAL_REQUIRED 1
#define STORE_APPROVAL_DENIED   2
#define STORE_APPROVAL_STALE    3
#define STORE_APPROVAL_EXPIRED  4

/** What a successful commit installed. **/
typedef struct {
  char name[PAYLOAD_NAME_MAX + 1];
  char sha256[65];
  char path[256];
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
 * Record the state directory and the platform clock, delete the staging
 * objects a previous process left behind and make the store's directories.
 * Returns 0 on success, -1 on error.
 **/
int store_init(const char *state_dir, struct platform *platform);

/** Take the next staging ID: s-1, s-2, and so on. **/
void store_staging_next_id(char *id, size_t size);

/**
 * Take a staging slot, reserve size bytes of the staging quota, create the
 * staging object for a new upload and return its descriptor, opened
 * relative to Ariel's directory without following symbolic links. Returns
 * -1 when the staging slots are all taken, size does not fit the quota
 * (one upload and the total are both at most 64 MiB) or on error.
 **/
int store_staging_create(const char *staging_id, uint64_t size);

/** Delete a staging object that never got an approval. **/
void store_staging_discard(const char *staging_id);

/**
 * Ask the owner to approve facts. On success fill challenge with what the
 * owner signs (the approval ID, the console identity, the canonical action
 * bytes, a nonce from the platform's CSPRNG, issued-at and expiry) and
 * write the text the owner would see into prompt, and take one pending
 * slot. Returns 0, or -1 when no approval can be requested now: at most
 * three approvals wait for a decision at once.
 **/
int store_approval_request(const approval_facts_t *facts,
                           approval_challenge_t *challenge, char *prompt,
                           size_t promptlen);

/** What one signature submitted for an approval ended in. **/
#define STORE_GRANT_OK       0
#define STORE_GRANT_UNKNOWN  1
#define STORE_GRANT_EXPIRED  2
#define STORE_GRANT_INVALID  3
#define STORE_GRANT_REPLAYED 4
#define STORE_GRANT_DENIED   5
#define STORE_GRANT_ERROR    6
#define STORE_GRANT_WRONG_ACTION  7
#define STORE_GRANT_WRONG_CONSOLE 8

/**
 * Grant an approval with the owner's signature. The platform verifies it
 * over the exact message of this approval's challenge. A valid signature
 * records the nonce as consumed on disk, then marks the approval decided;
 * the record is on disk before anything runs. This is the only way an
 * approval becomes approved. signature is APPROVAL_SIG_LEN bytes.
 *
 * console and action_sha256 are the envelope: what the signer says it
 * signed, both NULL when the grant carries only a signature. They are not
 * trusted. A mismatch with this approval's challenge answers
 * STORE_GRANT_WRONG_CONSOLE or STORE_GRANT_WRONG_ACTION, so a client can
 * tell those from a forgery; a match decides nothing, the signature does.
 **/
int store_approval_grant(const char *id, const unsigned char *signature,
                         const char *console, const char *action_sha256);

/** Record a denial. Returns 0, or -1 for an unknown ID. **/
int store_approval_deny(const char *id);

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

/**
 * One installed payload, as the state file records it. A push has no release,
 * so release and asset are 0 and version is empty; running is 1 only while a
 * background run of it is alive, which Stage 2's later slices add.
 **/
typedef struct {
  char name[PAYLOAD_NAME_MAX + 1];
  char source[16];
  char version[64];
  uint64_t release;
  uint64_t asset;
  char sha256[65];
  char path[256];
  int running;
} store_payload_t;

/**
 * Read the state file: the single record of installed payloads. On the first
 * start of Stage 2, when no state file exists yet, it is built once from
 * Stage 1's per-name current records; a later start reads the file and never
 * touches those records again. Fills entries, at most max of them, and sets
 * count. Returns 0, or -1 when the record cannot be read.
 **/
int store_list(store_payload_t *entries, size_t max, size_t *count);

#endif /* ARIEL_STORE_H */
