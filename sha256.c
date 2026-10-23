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

#include <string.h>

#include "sha256.h"

static const uint32_t round_constants[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};


static uint32_t
rotate_right(uint32_t value, unsigned bits) {
  return (value >> bits) | (value << (32 - bits));
}


static void
compress(sha256_t *ctx, const unsigned char block[64]) {
  uint32_t schedule[64];
  uint32_t a, b, c, d, e, f, g, h;
  int i;

  for(i=0; i<16; i++) {
    schedule[i] = ((uint32_t)block[4*i    ] << 24) |
                  ((uint32_t)block[4*i + 1] << 16) |
                  ((uint32_t)block[4*i + 2] <<  8) |
                  ((uint32_t)block[4*i + 3]);
  }

  for(i=16; i<64; i++) {
    uint32_t s0 = rotate_right(schedule[i - 15],  7) ^
                  rotate_right(schedule[i - 15], 18) ^
                  (schedule[i - 15] >>  3);
    uint32_t s1 = rotate_right(schedule[i -  2], 17) ^
                  rotate_right(schedule[i -  2], 19) ^
                  (schedule[i -  2] >> 10);

    schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for(i=0; i<64; i++) {
    uint32_t s1 = rotate_right(e,  6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + s1 + ch + round_constants[i] + schedule[i];
    uint32_t s0 = rotate_right(a,  2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}


void
sha256_init(sha256_t *ctx) {
  static const uint32_t initial[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  };

  memcpy(ctx->state, initial, sizeof(initial));
  ctx->bits = 0;
  ctx->block_len = 0;
  memset(ctx->block, 0, sizeof(ctx->block));
}


void
sha256_update(sha256_t *ctx, const void *data, size_t len) {
  const unsigned char *p = data;

  ctx->bits += (uint64_t)len * 8;

  while(len > 0) {
    size_t room = sizeof(ctx->block) - ctx->block_len;
    size_t take = len < room ? len : room;

    memcpy(ctx->block + ctx->block_len, p, take);
    ctx->block_len += take;
    p += take;
    len -= take;

    if(ctx->block_len == sizeof(ctx->block)) {
      compress(ctx, ctx->block);
      ctx->block_len = 0;
    }
  }
}


void
sha256_final(sha256_t *ctx, unsigned char out[SHA256_DIGEST_LEN]) {
  uint64_t bits = ctx->bits;
  int i;

  ctx->block[ctx->block_len++] = 0x80;

  if(ctx->block_len > 56) {
    memset(ctx->block + ctx->block_len, 0, sizeof(ctx->block) - ctx->block_len);
    compress(ctx, ctx->block);
    ctx->block_len = 0;
  }

  memset(ctx->block + ctx->block_len, 0, 56 - ctx->block_len);

  // The message length in bits, big-endian, closes the block.
  for(i=0; i<8; i++) {
    ctx->block[56 + i] = (unsigned char)(bits >> (56 - 8*i));
  }

  compress(ctx, ctx->block);

  for(i=0; i<8; i++) {
    out[4*i    ] = (unsigned char)(ctx->state[i] >> 24);
    out[4*i + 1] = (unsigned char)(ctx->state[i] >> 16);
    out[4*i + 2] = (unsigned char)(ctx->state[i] >>  8);
    out[4*i + 3] = (unsigned char)(ctx->state[i]);
  }

  memset(ctx, 0, sizeof(*ctx));
}


void
sha256_hex(const unsigned char digest[SHA256_DIGEST_LEN],
           char hex[SHA256_HEX_LEN + 1]) {
  static const char digits[] = "0123456789abcdef";
  int i;

  for(i=0; i<SHA256_DIGEST_LEN; i++) {
    hex[2*i    ] = digits[digest[i] >> 4];
    hex[2*i + 1] = digits[digest[i] & 0x0f];
  }
  hex[SHA256_HEX_LEN] = '\0';
}
