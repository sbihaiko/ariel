/* Ariel host build: every finding a title's checks can emit names an install part. */

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


static void
expect_mapped(const char *finding) {
  const char *got = runner_title_part(finding);

  if(!strcmp(got, "unknown")) {
    printf("FAIL %s: no install part is assigned to it\n", finding);
    failures++;
  } else {
    printf("PASS %s: %s\n", finding, got);
  }
}


int
main(void) {
  const char *const *entries;
  char finding[128];
  size_t count = 0;
  size_t i;

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
  expect_part("some_future_kind app.pkg", "unknown");

  entries = runner_title_entries(&count);
  if(!count) {
    printf("FAIL the title's checks name no entries\n");
    return 1;
  }
  for(i=0; i<count; i++) {
    snprintf(finding, sizeof(finding), "missing %s", entries[i]);
    expect_mapped(finding);
    snprintf(finding, sizeof(finding), "empty %s", entries[i]);
    expect_mapped(finding);
  }

  expect_mapped("missing appmeta");
  expect_mapped("missing content_id");
  expect_mapped("licence_missing CUSA04730");
  expect_mapped("licence_mismatch fakeUP9000-CUSA04730_00.rif");
  expect_mapped("size_mismatch app.pkg 12");
  expect_mapped("hash_mismatch app.pkg");

  if(failures) {
    printf("%d finding(s) without their part\n", failures);
    return 1;
  }
  printf("all findings name a part\n");
  return 0;
}
