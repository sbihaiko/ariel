/* Ariel: the owner's signature as the approval source.

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

#ifndef ARIEL_APPROVAL_H
#define ARIEL_APPROVAL_H

#include <stddef.h>
#include <stdint.h>

/**
 * ADR-0006: an approval is an Ed25519 signature, made by a key the owner
 * holds, over a domain-separated message that names one console, one
 * action, one nonce and one validity window. This file is shared by both
 * builds and by the offline signer, so the bytes the owner signs and the
 * bytes the console verifies come from the same code.
 **/

#define APPROVAL_NONCE_LEN   16
#define APPROVAL_SIG_LEN     64
#define APPROVAL_PUBKEY_LEN  32
#define APPROVAL_SEED_LEN    32

/** The longest canonical action text, and the longest console identity. **/
#define APPROVAL_ACTION_MAX  512
#define APPROVAL_CONSOLE_MAX 64

/** The longest command name an action can carry. **/
#define APPROVAL_COMMAND_MAX 32

/** The longest message a signature covers. **/
#define APPROVAL_MESSAGE_MAX 1024

/** At most this many options belong to one action. **/
#define APPROVAL_OPTIONS_MAX 12

/** The longest option value the encoder carries. **/
#define APPROVAL_VALUE_MAX   64
#define APPROVAL_URL_MAX     256

/** The hash of an action with no content behind it. **/
#define APPROVAL_NO_HASH "none"

/**
 * The public half of the host build's test key. The host build pins it;
 * the PS5 build refuses it (approval_pin). Its private half is
 * hostbuild/tests/testkey, which is public on purpose.
 **/
#define APPROVAL_TEST_PUBKEY_HEX \
  "299e18435f88e321120e74f83f1b3f3f530ca0d51cad39f3ed45b86b8007f922"

/** One option of an action: a lowercase key and a value. **/
typedef struct {
  const char *key;
  const char *value;
} approval_option_t;

/**
 * What the owner approves. Nothing else is signed. destination is NULL for an
 * action with one path; a transfer names its destination too.
 **/
typedef struct {
  const char *command;
  const char *target;
  const char *sha256;
  const approval_option_t *options;
  size_t noptions;
  const char *destination;
} approval_action_t;

/**
 * Turn an action into the bytes the owner reads and signs. This is the one
 * function that does so. Anything that could read two ways is refused, not
 * normalized: a target with a '..', an empty or '.' segment, a trailing
 * '/', a target of only '/', bytes outside ASCII, a repeated option, an
 * omitted field, a hash that is neither 64 lowercase hex digits nor none
 * (the hash of an action with no content), and any newline or space that
 * would smuggle in a line. A leading '/' is one spelling of a path, so an
 * absolute target encodes as written. Options are written in key order.
 * Returns the length of the NUL-terminated text in out, or -1 when the
 * action is refused or does not fit in size.
 **/
int approval_canonical(const approval_action_t *action, char *out,
                       size_t size);

/** Whether target is one the encoder accepts. Returns 1 when it is. **/
int approval_target_valid(const char *target);

/** Whether value is an option value the encoder accepts. Returns 1 when it is. **/
int approval_value_valid(const char *value);

/**
 * Build the message a signature covers: a domain tag, the console
 * identity, the canonical action bytes, the nonce, issued-at and expiry
 * (both in milliseconds on the platform clock), each field framed by its
 * length. Returns the length written to out, or -1.
 **/
int approval_message(const char *console, const char *action,
                     size_t action_len,
                     const unsigned char nonce[APPROVAL_NONCE_LEN],
                     uint64_t issued_ms, uint64_t expires_ms,
                     unsigned char *out, size_t size);

/** Write n bytes as 2n lowercase hex digits and a NUL. **/
void approval_hex_encode(const unsigned char *bytes, size_t n, char *out);

/**
 * Read exactly n bytes from 2n lowercase hex digits and nothing else.
 * Returns 0, or -1 for any other text.
 **/
int approval_hex_decode(const char *hex, unsigned char *out, size_t n);

/** Read a public key from 64 hex digits. Returns 0, or -1. **/
int approval_pubkey_parse(const char *hex,
                          unsigned char key[APPROVAL_PUBKEY_LEN]);

/**
 * Whether this build may pin key as its approval key. The PS5 build, which
 * never defines ARIEL_HOST_BUILD, refuses the host test key. Returns 0 when
 * the key may be pinned and -1 when it is refused.
 **/
int approval_pin(const unsigned char key[APPROVAL_PUBKEY_LEN]);

/** Verify sig over msg with key. Returns 0 only for a valid signature. **/
int approval_verify(const unsigned char key[APPROVAL_PUBKEY_LEN],
                    const unsigned char *msg, size_t len,
                    const unsigned char sig[APPROVAL_SIG_LEN]);

#endif /* ARIEL_APPROVAL_H */
