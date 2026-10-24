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
#include "state.h"

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

/** What one rollback request ended in; STORE_INSTALLED is a rollback done. **/
#define STORE_APPROVAL_NEW      5
#define STORE_ROLLBACK_FAILED   6
#define STORE_APPROVAL_FROZEN   7

/** What a rollback target was: the build it restores, or why there is none. **/
#define STORE_ROLLBACK_OK          0
#define STORE_ROLLBACK_UNKNOWN     1
#define STORE_ROLLBACK_NO_PREVIOUS 2
#define STORE_ROLLBACK_ERROR       3

/** What a successful commit installed. **/
typedef struct {
  char name[PAYLOAD_NAME_MAX + 1];
  char sha256[65];
  char path[256];
  char tag[65];
  uint64_t release;
  uint64_t asset;
} store_install_t;

/** How reading a payload back for a run ended. **/
#define STORE_RUN_OK      0
#define STORE_RUN_UNKNOWN 1
#define STORE_RUN_STALE   2
#define STORE_RUN_FROZEN  3

/** The verified bytes of one payload, held in memory until they are freed. **/
typedef struct {
  unsigned char *bytes;
  size_t size;
  char sha256[65];
} store_object_t;

/** Whether name follows the payload-name grammar. Returns 1 when it does. **/
int store_name_valid(const char *name);

/**
 * Record the state directory and the platform clock, delete the staging
 * objects a previous process left behind, make the store's directories and
 * create the approval state and nonce files if they are missing.
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

/** What a gated command's check ended in. **/
#define STORE_GATE_GO      0
#define STORE_GATE_PENDING 1
#define STORE_GATE_NEW     2
#define STORE_GATE_STALE   3
#define STORE_GATE_DENIED  4
#define STORE_GATE_REFUSED 5
#define STORE_GATE_KEYRING 6
#define STORE_GATE_FROZEN  7

/**
 * Check a gated command against its approval, and spend the approval when it
 * is answered. GO: the owner signed these facts, and the approval is spent.
 * PENDING: the owner has not answered; challenge is the one to show. NEW: no
 * approval stands for these facts, so one must be requested, and the caller
 * does so with the platform. STALE: the entry changed after the owner signed.
 * DENIED: the owner refused. REFUSED: the facts cannot be signed. KEYRING: the
 * keyring state does not allow this command, so nothing is requested. challenge
 * holds the approval's challenge for every answer that has one.
 **/
int store_gate_check(const approval_facts_t *facts,
                     approval_challenge_t *challenge);

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
#define STORE_GRANT_FROZEN   9

/**
 * What one approval is, as a question sees it. Consumed wins over the
 * others: the action it allowed already ran. Expired wins over granted,
 * because a window that closed is what a later question reports. A denial
 * is its own state, not an unknown approval.
 **/
#define STORE_STATUS_UNKNOWN  0
#define STORE_STATUS_PENDING  1
#define STORE_STATUS_GRANTED  2
#define STORE_STATUS_EXPIRED  3
#define STORE_STATUS_CONSUMED 4
#define STORE_STATUS_DENIED   5

/**
 * Answer what state an approval is in. The record outlives the action it
 * allowed and the window it was good for, so a consumed, expired or denied
 * approval still answers, until the table needs its row. Returns one of
 * STORE_STATUS_*.
 **/
int store_approval_status(const char *id);

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

/**
 * The facts an approval was bound to, for the audit log. Returns 0 when id
 * names an approval, or -1 when it does not.
 **/
int store_approval_facts(const char *id, approval_facts_t *facts);

/** What one autoload edit ended in. **/
#define STORE_AUTOLOAD_APPLIED 0
#define STORE_AUTOLOAD_PENDING 1
#define STORE_AUTOLOAD_DENIED  2
#define STORE_AUTOLOAD_EXPIRED 3
#define STORE_AUTOLOAD_STALE   4
#define STORE_AUTOLOAD_UNKNOWN 5
#define STORE_AUTOLOAD_FAILED  6
#define STORE_AUTOLOAD_UNRECORDED 7

/** What one key rotation ended in. **/
#define STORE_KEY_ROTATED    0
#define STORE_KEY_STALE      1
#define STORE_KEY_FAILED     2
#define STORE_KEY_UNRECORDED 3
#define STORE_KEY_ADOPTED    4
#define STORE_KEY_REFUSED    5

/** The keyring role a rotation replaces. **/
#define STORE_KEY_ROLE_PRIMARY  0
#define STORE_KEY_ROLE_RECOVERY 1

#define STORE_UNFREEZE_OK         0
#define STORE_UNFREEZE_STALE      1
#define STORE_UNFREEZE_FAILED     2
#define STORE_UNFREEZE_UNRECORDED 3

/**
 * Whether hex is a public key this build accepts as a new primary or recovery
 * key: 64 hex digits, a key the pinning checks allow, and neither the active
 * primary, the active recovery key nor a retired key. Returns 0 or -1.
 **/
int store_key_check(const char *hex);

/**
 * Move the keyring to the next generation with hex as the key of role, for the
 * granted approval challenge. The challenge must be for the current generation,
 * or the answer is STORE_KEY_STALE. The key it replaces is retired. On success
 * generation is the new one.
 **/
int store_key_rotate(const approval_challenge_t *challenge, const char *hex,
                     int role, uint32_t *generation);

/** Whether the owner's freeze is in force. A freeze file not yet recorded is recorded now. **/
int store_frozen(void);

/**
 * Lift the freeze for the granted recovery-signed challenge, and remove the
 * freeze file. Returns one of STORE_UNFREEZE_*; generation is the current one.
 **/
int store_key_unfreeze(const approval_challenge_t *challenge, uint32_t *generation);

/**
 * Adopt the build's anchor as the keyring, for the granted approval challenge
 * of key adopt-anchor, while the keyring is under another anchor. The keyring
 * moves to the next generation with the anchor's keys as its active keys; the
 * keys it held are retired. The answer is STORE_KEY_REFUSED when an anchor key
 * is one that is retired or active, and STORE_KEY_STALE when the challenge is
 * not for the current generation or the keyring is not waiting for an anchor.
 **/
int store_key_adopt(const approval_challenge_t *challenge,
                    uint32_t *generation);

/**
 * Copy the autoload list into buf, NUL-terminated: one payload name per line,
 * Ariel first. Returns its length, or -1 when it cannot be read.
 **/
int store_autoload_show(char *buf, size_t size);

/**
 * Apply the granted approval id to the autoload edit command names, for name.
 * The list must still be the one the approval was asked about, or the answer
 * is STORE_AUTOLOAD_STALE. A pending approval fills challenge with what the
 * owner signs. Returns one of STORE_AUTOLOAD_*.
 **/
int store_autoload_apply(const char *id, const char *command, const char *name,
                         approval_challenge_t *challenge);

/** What one autoload safe-boot ended in. **/
#define STORE_SAFE_BOOT_OK         0
#define STORE_SAFE_BOOT_STALE      1
#define STORE_SAFE_BOOT_PENDING    2
#define STORE_SAFE_BOOT_FAILED     3
#define STORE_SAFE_BOOT_UNRECORDED 4

/**
 * Whether a safe-boot's skip is still owed: its list is set aside and the next
 * start restores it. Returns 1 or 0, or -1 when the state cannot be read.
 **/
int store_autoload_skip_pending(void);

/**
 * Apply a granted autoload safe-boot whose approval is id, for the boot list
 * whose sha256 is sha256. The list must still be that one, or the answer is
 * STORE_SAFE_BOOT_STALE. The list is copied aside and reduced to Ariel, so the
 * next start restores the copy. Returns one of STORE_SAFE_BOOT_*.
 **/
int store_autoload_safe_boot(const char *id, const char *sha256);

/**
 * Restore the boot list a safe-boot set aside, at a start. Call it once the
 * boot's autoload entries are decided, so the skipped boot runs none of them.
 * Returns 0 when there is nothing to restore or it is restored, -1 on error.
 **/
int store_autoload_restore(void);

/**
 * Commit a staged object whose install needs no approval, because the
 * allowlist already pins its hash. Returns one of STORE_*.
 **/
int store_commit_pinned(const char *staging_id, store_install_t *install);

/**
 * Copy the allowlist text into text, empty when it is missing, unreadable or
 * too large. Returns 0, or -1 when the state directory cannot be opened.
 **/
int store_allowlist_read(char *text, size_t size);

/**
 * Pin sha256 to name in the allowlist. Returns 0 when the pin is written or
 * already holds sha256, and -1 otherwise.
 **/
int store_allowlist_pin(const char *name, const char *sha256);

/** Add name to the autoload list. Returns 0, or -1. **/
int store_autoload_join(const char *name);

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
 * Work out the rollback of a payload name: the previous build becomes
 * current and the current one becomes previous. Fills facts with the
 * rollback's action, which is what an approval of it is bound to. Returns
 * one of STORE_ROLLBACK_*.
 **/
int store_rollback_target(const char *name, approval_facts_t *facts);

/**
 * Roll back a payload name under its open approval, the newest one that is
 * neither spent nor released. Returns STORE_APPROVAL_NEW when there is none
 * (the caller asks for one), STORE_APPROVAL_REQUIRED with approval_id set
 * while it waits, STORE_APPROVAL_DENIED once it was refused, STORE_APPROVAL_STALE
 * when the store no longer holds the facts the owner approved, STORE_INSTALLED
 * when the rollback is done, or STORE_ROLLBACK_FAILED with the grant kept
 * open. approval_id is set whenever an approval is found.
 **/
int store_rollback(const char *name, char *approval_id, size_t idlen,
                   store_install_t *install);

/**
 * Read the current object of a payload name into memory once, hash those
 * bytes and compare the hash with the store's current record. The object
 * is opened through that record and never followed. Returns STORE_RUN_OK
 * with the verified bytes, STORE_RUN_UNKNOWN when the name has no record,
 * or STORE_RUN_STALE when the object no longer matches it.
 **/
int store_run_load(const char *name, store_object_t *object);

/** The one-shot health timeout, in seconds, until payload config sets one. **/
#define HEALTH_TIMEOUT_S 30

/**
 * The longest one-shot health timeout payload config accepts, in seconds. A
 * check runs on the connection that activates the build, so it is bounded.
 **/
#define HEALTH_TIMEOUT_MAX_S 3600

/** What a failed one-shot health check changed. **/
#define STORE_HEALTH_REPLACED  0
#define STORE_HEALTH_MARKED    1
#define STORE_HEALTH_FAILED    2
#define STORE_HEALTH_UNAUDITED 3
#define STORE_HEALTH_PARTIAL   4

/**
 * Answer a failed one-shot health check of the build failed, which is the
 * current build of name. With a previous build, that build becomes current
 * and its hash is copied into restored (STORE_HEALTH_REPLACED). With none, the
 * payload is taken out of autoload when it is listed there and marked failed
 * (STORE_HEALTH_MARKED). STORE_HEALTH_UNAUDITED is a marking whose autoload
 * removal took effect but whose audit line failed. STORE_HEALTH_PARTIAL is a
 * removal from autoload whose marking failed. STORE_HEALTH_FAILED leaves the
 * store as it was.
 **/
int store_health_failed(const char *name, const char *failed, char *restored,
                        size_t size);

/** Free the bytes of an object store_run_load returned. **/
void store_object_free(store_object_t *object);

/**
 * Open the log of one payload name, relative to Ariel's directory without
 * following symbolic links. With create set the log is made, or emptied
 * when it exists; otherwise it is opened to read. Returns the descriptor, or
 * -1 when it cannot be opened. The name must follow the payload-name grammar.
 **/
int store_log_open(const char *name, int create);

/** One audit line is at most this long; a tail shows at most AUDIT_TAIL_MAX. **/
#define AUDIT_LINE_MAX 320
#define AUDIT_TAIL_MAX 64

/**
 * The installed payloads, as the state file records them. Fills entries, at
 * most max of them, and sets count. Returns 0, or -1 when the record cannot
 * be read.
 **/
int store_list(state_payload_t *entries, size_t max, size_t *count);

/**
 * Append one line to the audit log: "<ms> <kind> <name> <id> <sha256>". The
 * log is append-only; nothing here can clear or rewrite it. Returns 0, or -1
 * when the line could not be recorded.
 **/
int store_audit_append(const char *kind, const char *name, const char *id,
                       const char *sha256);

/**
 * Copy the newest n lines of the audit log into buf, each ending in a
 * newline, in the order they were appended. n is capped at AUDIT_TAIL_MAX,
 * so 0 and any larger n both give the newest AUDIT_TAIL_MAX lines. Returns
 * the number of bytes copied, or -1 on error, including a buf too small for
 * them.
 **/
int store_audit_tail(unsigned long n, char *buf, size_t size);

#endif /* ARIEL_STORE_H */
