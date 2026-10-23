/* SHA-256, a small vendored implementation shared by both builds.

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

#ifndef ARIEL_SHA256_H
#define ARIEL_SHA256_H

#include <stddef.h>
#include <stdint.h>

/** A SHA-256 digest is 32 bytes, or 64 lowercase hex digits. **/
#define SHA256_DIGEST_LEN 32
#define SHA256_HEX_LEN    64

typedef struct sha256 {
  uint32_t state[8];
  uint64_t bits;
  unsigned char block[64];
  size_t block_len;
} sha256_t;

/** Start a new digest. **/
void sha256_init(sha256_t *ctx);

/** Feed the next len bytes into the digest. **/
void sha256_update(sha256_t *ctx, const void *data, size_t len);

/** Finish the digest into out, which holds SHA256_DIGEST_LEN bytes. **/
void sha256_final(sha256_t *ctx, unsigned char out[SHA256_DIGEST_LEN]);

/** Write digest as SHA256_HEX_LEN lowercase hex digits and a NUL. **/
void sha256_hex(const unsigned char digest[SHA256_DIGEST_LEN],
                char hex[SHA256_HEX_LEN + 1]);

#endif /* ARIEL_SHA256_H */
