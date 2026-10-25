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

#include <stdlib.h>
#include <string.h>

#include "approval.h"
#include "tweetnacl.h"

/** The tag that keeps an Ariel approval from verifying as anything else. **/
#define MESSAGE_TAG "ARIEL-APPROVAL-V1"

#define TARGET_MAX   128
#define KEY_MAX      16
#define HASH_LEN     64

#ifndef ARIEL_SIGNER
/**
 * TweetNaCl asks for a random source to make keys, and only to make keys.
 * Neither build makes one: the key is the owner's, made offline by the
 * signer, which brings its own source.
 **/
void
randombytes(unsigned char *buf, unsigned long long len) {
  (void)buf;
  (void)len;
  abort();
}
#endif


static int
is_lower(int c) {
  return c >= 'a' && c <= 'z';
}


static int
is_digit(int c) {
  return c >= '0' && c <= '9';
}


static int
is_alnum(int c) {
  return is_lower(c) || is_digit(c) || (c >= 'A' && c <= 'Z');
}


/** The only bytes a command, a target and a value are built from. Bytes
    outside ASCII, controls, spaces and '=' are never among them. **/
static int
in_set(const char *text, size_t min, size_t max, const char *extra,
       int lower_only) {
  size_t i;
  size_t len;

  if(!text) {
    return 0;
  }

  len = strlen(text);
  if(len < min || len > max) {
    return 0;
  }

  for(i=0; i<len; i++) {
    int c = (unsigned char)text[i];

    if(lower_only ? !(is_lower(c) || is_digit(c)) : !is_alnum(c)) {
      if(!c || !strchr(extra, c)) {
        return 0;
      }
    }
  }

  return 1;
}


static int
command_ok(const char *command) {
  return in_set(command, 1, APPROVAL_COMMAND_MAX, "._-", 1) &&
         is_lower(command[0]);
}


/** Whether every byte is printable ASCII, 0x20 to 0x7E. **/
static int
printable(const char *text) {
  for(; *text; text++) {
    int c = (unsigned char)*text;

    if(c < 0x20 || c > 0x7e) {
      return 0;
    }
  }

  return 1;
}


/** A segment is the bytes between two slashes. A leading slash is one
    spelling of an absolute path, not a segment, so it is not empty. A
    segment of '.', '..' or no bytes at all is refused: escaping makes a
    byte expressible, never traversal. **/
static int
target_ok(const char *target) {
  size_t len;
  size_t i;
  size_t start;
  size_t seg;

  if(!target || !(len=strlen(target)) || len > TARGET_MAX ||
     !printable(target)) {
    return 0;
  }

  start = target[0] == '/' ? 1 : 0;
  if(start == len) {
    return 0;
  }

  seg = start;
  for(i=start; i<=len; i++) {
    int c = i == len ? 0 : (unsigned char)target[i];

    if(!c || c == '/') {
      size_t n = i - seg;

      if(!n || (n == 1 && target[seg] == '.') ||
         (n == 2 && target[seg] == '.' && target[seg + 1] == '.')) {
        return 0;
      }
      seg = i + 1;
    }
  }

  return 1;
}


int
approval_target_valid(const char *target) {
  return target_ok(target);
}


int
approval_text_valid(const char *value, size_t max) {
  size_t len;

  return value && (len=strlen(value)) >= 1 && len <= max && printable(value);
}


static int
value_ok(const char *value) {
  return approval_text_valid(value, APPROVAL_VALUE_MAX);
}


int
approval_value_valid(const char *value) {
  return value_ok(value);
}


/** A content hash, or none for an action with no content behind it. **/
static int
hash_ok(const char *hash) {
  size_t i;

  if(hash && !strcmp(hash, APPROVAL_NO_HASH)) {
    return 1;
  }

  if(!hash || strlen(hash) != HASH_LEN) {
    return 0;
  }

  for(i=0; i<HASH_LEN; i++) {
    if(!is_digit(hash[i]) && !(hash[i] >= 'a' && hash[i] <= 'f')) {
      return 0;
    }
  }

  return 1;
}


static int
option_key_ok(const char *key) {
  size_t i;

  if(!key || !is_lower((unsigned char)key[0]) || strlen(key) > KEY_MAX) {
    return 0;
  }

  for(i=0; key[i]; i++) {
    int c = (unsigned char)key[i];

    if(!is_lower(c) && !is_digit(c) && c != '_') {
      return 0;
    }
  }

  return 1;
}


/**
 * An option value is any printable ASCII word, or the absolute path of a
 * mount source, which is a target. Values are escaped in the action, so a
 * space or a bracket is expressible; a URL keeps its own validity rule.
 **/
static int
url_ok(const char *value) {
  return !strncmp(value, "http://", 7) &&
         in_set(value, 8, APPROVAL_URL_MAX, "._-/:?=&%~+", 0);
}


static int
option_value_ok(const approval_option_t *option) {
  if(!strcmp(option->key, "from")) {
    return option->value[0] == '/' && target_ok(option->value);
  }
  if(!strcmp(option->key, "url")) {
    return url_ok(option->value);
  }
  return value_ok(option->value);
}


/** Append text at *pos, never past the NUL that ends out. **/
static int
put(char *out, size_t size, size_t *pos, const char *text) {
  size_t len = strlen(text);

  if(*pos + len >= size) {
    return -1;
  }

  memcpy(out + *pos, text, len + 1);
  *pos += len;
  return 0;
}


/**
 * Append one target, destination or option value, escaping every byte
 * outside letters, digits, '.', '_' and '-' as %XX in uppercase hex. '%'
 * itself is outside the set, so a literal percent is %25 and the encoding
 * is injective. The caller has already established printable ASCII.
 **/
static int
put_escaped(char *out, size_t size, size_t *pos, const char *text) {
  static const char digits[] = "0123456789ABCDEF";
  const unsigned char *p = (const unsigned char *)text;

  for(; *p; p++) {
    int c = *p;

    if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
      if(*pos + 1 >= size) {
        return -1;
      }
      out[(*pos)++] = (char)c;
    } else {
      if(*pos + 3 >= size) {
        return -1;
      }
      out[(*pos)++] = '%';
      out[(*pos)++] = digits[c >> 4];
      out[(*pos)++] = digits[c & 15];
    }
  }

  out[*pos] = '\0';
  return 0;
}


int
approval_canonical(const approval_action_t *action, char *out, size_t size) {
  size_t order[APPROVAL_OPTIONS_MAX];
  size_t pos = 0;
  size_t i;
  size_t j;

  if(!action || !out || !size || action->noptions > APPROVAL_OPTIONS_MAX ||
     (action->noptions && !action->options)) {
    return -1;
  }

  if(!command_ok(action->command) || !target_ok(action->target) ||
     !hash_ok(action->sha256) ||
     (action->destination && !target_ok(action->destination))) {
    return -1;
  }

  // Options are written in key order, so the order they are given in is not
  // part of the action. A repeated key has no single meaning: refuse it.
  for(i=0; i<action->noptions; i++) {
    const approval_option_t *option = &action->options[i];

    if(!option_key_ok(option->key) || !option_value_ok(option)) {
      return -1;
    }

    for(j=i; j>0 && strcmp(action->options[order[j-1]].key,
                           option->key) >= 0; j--) {
      if(!strcmp(action->options[order[j-1]].key, option->key)) {
        return -1;
      }
      order[j] = order[j-1];
    }
    order[j] = i;
  }

  out[0] = '\0';

  if(put(out, size, &pos, "ariel-action-v1\ncommand=") ||
     put(out, size, &pos, action->command) ||
     put(out, size, &pos, "\ntarget=") ||
     put_escaped(out, size, &pos, action->target) ||
     put(out, size, &pos, "\n") ||
     (action->destination &&
      (put(out, size, &pos, "destination=") ||
       put_escaped(out, size, &pos, action->destination) ||
       put(out, size, &pos, "\n"))) ||
     put(out, size, &pos, "sha256=") ||
     put(out, size, &pos, action->sha256) ||
     put(out, size, &pos, "\n")) {
    return -1;
  }

  for(i=0; i<action->noptions; i++) {
    const approval_option_t *option = &action->options[order[i]];

    if(put(out, size, &pos, "option.") ||
       put(out, size, &pos, option->key) ||
       put(out, size, &pos, "=") ||
       put_escaped(out, size, &pos, option->value) ||
       put(out, size, &pos, "\n")) {
      return -1;
    }
  }

  return (int)pos;
}


static void
put_be(unsigned char *out, uint64_t value, size_t bytes) {
  size_t i;

  for(i=0; i<bytes; i++) {
    out[i] = (unsigned char)(value >> (8 * (bytes - 1 - i)));
  }
}


int
approval_message(const char *console, const char *action, size_t action_len,
                 uint32_t generation,
                 const unsigned char nonce[APPROVAL_NONCE_LEN],
                 uint64_t issued_ms, uint64_t expires_ms,
                 unsigned char *out, size_t size) {
  size_t console_len;
  size_t pos = 0;
  size_t need;

  if(!console || !action || !nonce || !out) {
    return -1;
  }

  console_len = strlen(console);
  if(!console_len || console_len > APPROVAL_CONSOLE_MAX ||
     !action_len || action_len > APPROVAL_ACTION_MAX) {
    return -1;
  }

  need = sizeof(MESSAGE_TAG) + 2 + console_len + 4 + action_len + 4 +
         APPROVAL_NONCE_LEN + 8 + 8;
  if(need > size || need > APPROVAL_MESSAGE_MAX) {
    return -1;
  }

  // The tag's own NUL ends it, so no console name can run into it.
  memcpy(out + pos, MESSAGE_TAG, sizeof(MESSAGE_TAG));
  pos += sizeof(MESSAGE_TAG);
  put_be(out + pos, console_len, 2);
  pos += 2;
  memcpy(out + pos, console, console_len);
  pos += console_len;
  put_be(out + pos, action_len, 4);
  pos += 4;
  memcpy(out + pos, action, action_len);
  pos += action_len;
  put_be(out + pos, generation, 4);
  pos += 4;
  memcpy(out + pos, nonce, APPROVAL_NONCE_LEN);
  pos += APPROVAL_NONCE_LEN;
  put_be(out + pos, issued_ms, 8);
  pos += 8;
  put_be(out + pos, expires_ms, 8);
  pos += 8;

  return (int)pos;
}


void
approval_hex_encode(const unsigned char *bytes, size_t n, char *out) {
  static const char digits[] = "0123456789abcdef";
  size_t i;

  for(i=0; i<n; i++) {
    out[2*i] = digits[bytes[i] >> 4];
    out[2*i + 1] = digits[bytes[i] & 15];
  }
  out[2*n] = '\0';
}


static int
hex_value(int c) {
  if(is_digit(c)) {
    return c - '0';
  }
  if(c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}


int
approval_hex_decode(const char *hex, unsigned char *out, size_t n) {
  size_t i;

  if(!hex || strlen(hex) != 2 * n) {
    return -1;
  }

  for(i=0; i<n; i++) {
    int hi = hex_value((unsigned char)hex[2*i]);
    int lo = hex_value((unsigned char)hex[2*i + 1]);

    if(hi < 0 || lo < 0) {
      return -1;
    }
    out[i] = (unsigned char)(hi << 4 | lo);
  }

  return 0;
}


int
approval_pubkey_parse(const char *hex, unsigned char key[APPROVAL_PUBKEY_LEN]) {
  return approval_hex_decode(hex, key, APPROVAL_PUBKEY_LEN);
}


int
approval_pin(const unsigned char key[APPROVAL_PUBKEY_LEN]) {
  static const unsigned char zero[APPROVAL_PUBKEY_LEN];

  if(!memcmp(key, zero, sizeof(zero))) {
    return -1;
  }

#ifndef ARIEL_HOST_BUILD
  {
    // The test key's private half is in the repository. A console that
    // pinned it would accept anyone's approval.
    unsigned char test[APPROVAL_PUBKEY_LEN];

    if(approval_pubkey_parse(APPROVAL_TEST_PUBKEY_HEX, test) ||
       !memcmp(key, test, sizeof(test))) {
      return -1;
    }
  }
#endif

  return 0;
}


int
approval_key_admissible(const unsigned char key[APPROVAL_PUBKEY_LEN],
                        const unsigned char primary[APPROVAL_PUBKEY_LEN],
                        const unsigned char recovery[APPROVAL_PUBKEY_LEN],
                        unsigned char (*revoked)[APPROVAL_PUBKEY_LEN],
                        size_t revoked_count) {
  size_t i;

  if(approval_pin(key) || !memcmp(key, primary, APPROVAL_PUBKEY_LEN) ||
     !memcmp(key, recovery, APPROVAL_PUBKEY_LEN)) {
    return -1;
  }

  for(i = 0; i < revoked_count; i++) {
    if(!memcmp(key, revoked[i], APPROVAL_PUBKEY_LEN)) {
      return -1;
    }
  }
  return 0;
}


int
approval_verify(const unsigned char key[APPROVAL_PUBKEY_LEN],
                const unsigned char *msg, size_t len,
                const unsigned char sig[APPROVAL_SIG_LEN]) {
  unsigned char signed_msg[APPROVAL_SIG_LEN + APPROVAL_MESSAGE_MAX];
  unsigned char opened[APPROVAL_SIG_LEN + APPROVAL_MESSAGE_MAX];
  unsigned long long opened_len = 0;

  if(!msg || !len || len > APPROVAL_MESSAGE_MAX) {
    return -1;
  }

  // TweetNaCl verifies a signed message: the signature, then the message.
  memcpy(signed_msg, sig, APPROVAL_SIG_LEN);
  memcpy(signed_msg + APPROVAL_SIG_LEN, msg, len);

  if(crypto_sign_open(opened, &opened_len, signed_msg,
                      APPROVAL_SIG_LEN + len, key)) {
    return -1;
  }

  return opened_len == len && !memcmp(opened, msg, len) ? 0 : -1;
}
