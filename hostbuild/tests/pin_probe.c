/* Ariel host build: probe of the key pinning policy.

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
 * Pins the public key given as 64 hex digits the way a platform does, and
 * exits 0 when the build configuration it was compiled with allows that
 * key, 1 when it refuses it and 2 on a bad argument. The suite compiles it
 * twice: as the host build, and as the PS5 build, which never defines
 * ARIEL_HOST_BUILD.
 */

#include <stdio.h>

#include "approval.h"

int
main(int argc, char **argv) {
  unsigned char key[APPROVAL_PUBKEY_LEN];

  if(argc != 2 || approval_pubkey_parse(argv[1], key)) {
    return 2;
  }

  if(approval_pin(key)) {
    puts("refused");
    return 1;
  }

  puts("pinned");
  return 0;
}
