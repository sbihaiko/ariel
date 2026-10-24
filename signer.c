/* Ariel: the offline signer.

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
 * The owner's signer, for tests and for the owner. It never touches the
 * network and it runs where the key is:
 *
 *   ariel-sign keygen <keyfile>        make a key, print its public key
 *   ariel-sign pubkey <keyfile>        print the public key of a key
 *   ariel-sign sign <keyfile> [--yes]  read one challenge line on standard
 *                                      input, show the action, sign it
 *
 * A key file holds the 32-byte seed as 64 hex digits. A challenge is the
 * line Ariel answers a gated push with:
 *
 *   challenge <id> <console> <nonce> <issued-ms> <expires-ms> <action-hex>
 *
 * The signer prints the canonical action text on standard error exactly as
 * the bytes it is about to sign, not a summary of them, and asks the owner
 * to confirm on the terminal unless --yes is given. The signature, 128 hex
 * digits, goes to standard output followed by the console and the action's
 * SHA-256, so Ariel can tell a wrong console or action from a forged
 * signature; paste the whole line after `approval grant <id>`.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "approval.h"
#include "sha256.h"
#include "tweetnacl.h"

#define LINE_MAX_LEN 4096

/** The seed the next crypto_sign_keypair call takes as its randomness. **/
static unsigned char key_seed[APPROVAL_SEED_LEN];


/**
 * TweetNaCl takes the secret key's 32 random bytes from here. The signer
 * hands it the key file's seed, so the public key follows from the seed
 * and a key file is all the owner has to keep.
 **/
void
randombytes(unsigned char *buf, unsigned long long len) {
  memcpy(buf, key_seed, len < sizeof(key_seed) ? len : sizeof(key_seed));
}


static int
random_seed(unsigned char *seed) {
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  ssize_t n = -1;

  if(fd >= 0) {
    n = read(fd, seed, APPROVAL_SEED_LEN);
    close(fd);
  }

  return n == APPROVAL_SEED_LEN ? 0 : -1;
}


/** Derive the key pair of the seed in key_seed. **/
static void
keypair(unsigned char pk[APPROVAL_PUBKEY_LEN],
        unsigned char sk[crypto_sign_SECRETKEYBYTES]) {
  crypto_sign_keypair(pk, sk);
}


static int
read_key(const char *path, unsigned char pk[APPROVAL_PUBKEY_LEN],
         unsigned char sk[crypto_sign_SECRETKEYBYTES]) {
  char line[LINE_MAX_LEN];
  FILE *file = fopen(path, "r");
  size_t len;

  if(!file) {
    perror(path);
    return -1;
  }

  if(!fgets(line, sizeof(line), file)) {
    fclose(file);
    fprintf(stderr, "%s: empty key file\n", path);
    return -1;
  }
  fclose(file);

  len = strlen(line);
  while(len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
    line[--len] = '\0';
  }

  if(approval_hex_decode(line, key_seed, APPROVAL_SEED_LEN)) {
    fprintf(stderr, "%s: a key file holds 64 lowercase hex digits\n", path);
    return -1;
  }

  keypair(pk, sk);
  return 0;
}


static int
cmd_keygen(const char *path) {
  unsigned char pk[APPROVAL_PUBKEY_LEN];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  char hex[2 * APPROVAL_PUBKEY_LEN + 1];
  FILE *file;
  int fd;

  if(random_seed(key_seed)) {
    fprintf(stderr, "cannot read /dev/urandom\n");
    return 1;
  }

  // A key file belongs to its owner alone, and never replaces another.
  if((fd=open(path, O_WRONLY | O_CREAT | O_EXCL, 0600)) < 0) {
    perror(path);
    return 1;
  }

  file = fdopen(fd, "w");
  approval_hex_encode(key_seed, APPROVAL_SEED_LEN, hex);
  if(!file || fprintf(file, "%.64s\n", hex) < 0 || fclose(file)) {
    perror(path);
    return 1;
  }

  keypair(pk, sk);
  approval_hex_encode(pk, sizeof(pk), hex);
  printf("%s\n", hex);
  return 0;
}


static int
cmd_pubkey(const char *path) {
  unsigned char pk[APPROVAL_PUBKEY_LEN];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  char hex[2 * APPROVAL_PUBKEY_LEN + 1];

  if(read_key(path, pk, sk)) {
    return 1;
  }

  approval_hex_encode(pk, sizeof(pk), hex);
  printf("%s\n", hex);
  return 0;
}


/** Ask the owner on the terminal. Returns 1 for a yes. **/
static int
confirm(void) {
  char answer[16];
  FILE *tty = fopen("/dev/tty", "r+");
  int yes = 0;

  if(!tty) {
    fprintf(stderr, "no terminal to confirm on; use --yes to sign\n");
    return 0;
  }

  fprintf(tty, "Sign this action? Type yes to sign: ");
  fflush(tty);
  if(fgets(answer, sizeof(answer), tty)) {
    yes = !strcmp(answer, "yes\n");
  }
  fclose(tty);

  return yes;
}


/**
 * Zero when every byte is printable ASCII or a newline, which is all a
 * canonical action holds. Anything else could be hidden by a terminal.
 **/
static int
action_shown_whole(const unsigned char *bytes, size_t len) {
  size_t i;

  for(i=0; i<len; i++) {
    if(bytes[i] != '\n' && (bytes[i] < 0x20 || bytes[i] > 0x7e)) {
      return -1;
    }
  }
  return 0;
}


static int
cmd_sign(const char *path, int assume_yes) {
  unsigned char pk[APPROVAL_PUBKEY_LEN];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  unsigned char nonce[APPROVAL_NONCE_LEN];
  unsigned char action_bytes[APPROVAL_ACTION_MAX + 1];
  unsigned char message[APPROVAL_MESSAGE_MAX];
  unsigned char signed_msg[APPROVAL_SIG_LEN + APPROVAL_MESSAGE_MAX];
  unsigned long long signed_len = 0;
  char line[LINE_MAX_LEN];
  unsigned char digest[SHA256_DIGEST_LEN];
  char digest_hex[2 * SHA256_DIGEST_LEN + 1];
  char sig_hex[2 * APPROVAL_SIG_LEN + 1];
  sha256_t hash;
  char *fields[7];
  char *save = NULL;
  char *end = NULL;
  unsigned long long issued;
  unsigned long long expires;
  size_t action_len;
  size_t i;
  int len;

  if(read_key(path, pk, sk)) {
    return 1;
  }

  if(!fgets(line, sizeof(line), stdin)) {
    fprintf(stderr, "no challenge on standard input\n");
    return 1;
  }

  fields[0] = strtok_r(line, " \r\n", &save);
  for(i=1; i<7; i++) {
    fields[i] = fields[i-1] ? strtok_r(NULL, " \r\n", &save) : NULL;
  }

  if(!fields[6] || strtok_r(NULL, " \r\n", &save) ||
     strcmp(fields[0], "challenge") ||
     approval_hex_decode(fields[3], nonce, APPROVAL_NONCE_LEN)) {
    fprintf(stderr, "not a challenge line\n");
    return 1;
  }

  errno = 0;
  issued = strtoull(fields[4], &end, 10);
  if(errno || !*fields[4] || *end) {
    fprintf(stderr, "not a challenge line: issued-at\n");
    return 1;
  }
  expires = strtoull(fields[5], &end, 10);
  if(errno || !*fields[5] || *end) {
    fprintf(stderr, "not a challenge line: expiry\n");
    return 1;
  }

  action_len = strlen(fields[6]) / 2;
  if(action_len > APPROVAL_ACTION_MAX ||
     approval_hex_decode(fields[6], action_bytes, action_len)) {
    fprintf(stderr, "not a challenge line: action\n");
    return 1;
  }
  action_bytes[action_len] = '\0';

  // Show only what can be shown: a NUL or a control byte would hide part of
  // the signed bytes from the owner.
  if(!action_len || action_shown_whole(action_bytes, action_len)) {
    fprintf(stderr, "the action has bytes that cannot be shown; not signed\n");
    return 1;
  }

  len = approval_message(fields[2], (const char*)action_bytes, action_len,
                         nonce, issued, expires, message, sizeof(message));
  if(len < 0) {
    fprintf(stderr, "the challenge does not fit a message\n");
    return 1;
  }

  // What the owner reads is the byte string that gets signed.
  fprintf(stderr, "console %s, approval %s, valid %llu to %llu ms\n",
          fields[2], fields[1], issued, expires);
  fwrite(action_bytes, 1, action_len, stderr);
  fflush(stderr);

  if(!assume_yes && !confirm()) {
    fprintf(stderr, "not signed\n");
    return 1;
  }

  crypto_sign(signed_msg, &signed_len, message, (unsigned long long)len, sk);
  approval_hex_encode(signed_msg, APPROVAL_SIG_LEN, sig_hex);

  // The envelope tells Ariel which console and action the owner signed, so
  // it can say which one is wrong; the signature alone decides the grant.
  sha256_init(&hash);
  sha256_update(&hash, action_bytes, action_len);
  sha256_final(&hash, digest);
  sha256_hex(digest, digest_hex);
  printf("%s %s %s\n", sig_hex, fields[2], digest_hex);
  return 0;
}


int
main(int argc, char **argv) {
  if(argc == 3 && !strcmp(argv[1], "keygen")) {
    return cmd_keygen(argv[2]);
  }

  if(argc == 3 && !strcmp(argv[1], "pubkey")) {
    return cmd_pubkey(argv[2]);
  }

  if((argc == 3 || argc == 4) && !strcmp(argv[1], "sign") &&
     (argc == 3 || !strcmp(argv[3], "--yes"))) {
    return cmd_sign(argv[2], argc == 4);
  }

  fprintf(stderr,
          "usage: %s keygen <keyfile>\n"
          "       %s pubkey <keyfile>\n"
          "       %s sign <keyfile> [--yes] < challenge\n",
          argv[0], argv[0], argv[0]);
  return 2;
}
