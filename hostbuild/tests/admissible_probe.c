/* Ariel host build: probe of the admission rule for a new primary key.

Takes the candidate key, the active primary and the recovery key as 64 hex
digits each, with no retired keys. Exits 0 when the build configuration it
was compiled with admits the candidate as a primary, 1 when it refuses it and
2 on a bad argument. The suite compiles it as the PS5 build, which never
defines ARIEL_HOST_BUILD, and as the host build.
*/

#include <stdio.h>

#include "approval.h"

int
main(int argc, char **argv) {
  unsigned char key[APPROVAL_PUBKEY_LEN];
  unsigned char primary[APPROVAL_PUBKEY_LEN];
  unsigned char recovery[APPROVAL_PUBKEY_LEN];
  unsigned char none[1][APPROVAL_PUBKEY_LEN] = {{0}};

  if(argc != 4 || approval_pubkey_parse(argv[1], key) ||
     approval_pubkey_parse(argv[2], primary) ||
     approval_pubkey_parse(argv[3], recovery)) {
    return 2;
  }

  if(approval_key_admissible(key, primary, recovery, none, 0)) {
    puts("refused");
    return 1;
  }

  puts("admitted");
  return 0;
}
