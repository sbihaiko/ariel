/* Ariel host build: each finding a title's checks can emit names its install part.

   A finding without a mapping answers `unknown`, so a finding added later is
   reported as its own part and never as a missing package. */

#include <stdio.h>
#include <string.h>

#include "runner.h"

static int failures;


static void
expect_part(const char *finding, const char *part) {
  const char *got = runner_title_part(finding);

  if(strcmp(got, part)) {
    printf("FAIL %s: part %s, want %s\n", finding, got, part);
    failures++;
  } else {
    printf("PASS %s: %s\n", finding, part);
  }
}


int
main(void) {
  expect_part("missing app.pkg", "package");
  expect_part("empty app.pkg", "package");
  expect_part("missing app.pbm", "package");
  expect_part("empty app.pbm", "package");
  expect_part("missing app.json", "package");
  expect_part("empty app.json", "package");
  expect_part("missing app.xml", "package");
  expect_part("empty app.xml", "package");
  expect_part("size_mismatch app.pkg 12", "package");
  expect_part("hash_mismatch app.pkg", "package");
  expect_part("missing sce_sys/param.sfo", "sfo");
  expect_part("empty sce_sys/param.sfo", "sfo");
  expect_part("missing content_id", "sfo");
  expect_part("missing appmeta", "appmeta");
  expect_part("licence_missing CUSA04730", "licence");
  expect_part("licence_mismatch fakeUP9000-CUSA04730_00.rif", "licence");
  expect_part("missing app.bin", "unknown");
  expect_part("some_future_kind app.pkg", "unknown");

  if(failures) {
    printf("%d finding(s) without their part\n", failures);
    return 1;
  }
  printf("all findings name a part\n");
  return 0;
}
