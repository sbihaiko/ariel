/* Ariel host build: tests of the canonical action encoder.

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
 * The encoder turns an action into the bytes the owner signs, and it is
 * the only function that does. An input that could read two ways is a
 * defect there, so each ambiguous input below must be refused, and the
 * accepted ones must come out as the literal bytes the owner would see.
 */

#include <stdio.h>
#include <string.h>

#include "approval.h"

#define HASH "3b1f0c9e5a7d2b4c6e8f0a1b3c5d7e9f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d"

static int failures;


static void
expect(int ok, const char *what) {
  if(!ok) {
    printf("FAIL %s\n", what);
    failures++;
  } else {
    printf("PASS %s\n", what);
  }
}


static int
encode(const approval_action_t *action, char *out, size_t size) {
  return approval_canonical(action, out, size);
}


static void
refused(const approval_action_t *action, const char *what) {
  char out[APPROVAL_ACTION_MAX];

  expect(encode(action, out, sizeof(out)) < 0, what);
}


int
main(void) {
  static const approval_option_t two[] = {{"size", "12"}, {"run", "1"}};
  static const approval_option_t swapped[] = {{"run", "1"}, {"size", "12"}};
  static const approval_option_t repeated[] = {{"run", "1"}, {"run", "0"}};
  static const approval_option_t injected[] = {{"run", "1\ncommand=rm"}};
  static const approval_option_t spaced[] = {{"run", "1 2"}};
  static const approval_option_t bad_key[] = {{"Run", "1"}};
  static const approval_option_t no_value[] = {{"run", ""}};
  static const approval_option_t unicode[] = {{"run", "caf\xc3\xa9"}};
  approval_action_t action = {"payload.commit", "helloworld", HASH, two, 2};
  approval_action_t other;
  char out[APPROVAL_ACTION_MAX];
  char again[APPROVAL_ACTION_MAX];
  int len;

  // The literal is the specification: the lines the owner reads, options
  // in key order, every line ending in a newline.
  len = encode(&action, out, sizeof(out));
  expect(len > 0 && !strcmp(out,
         "ariel-action-v1\n"
         "command=payload.commit\n"
         "target=helloworld\n"
         "sha256=" HASH "\n"
         "option.run=1\n"
         "option.size=12\n") && (size_t)len == strlen(out),
         "an action encodes to the literal canonical text");

  // Option order is not part of the action.
  other = action;
  other.options = swapped;
  expect(encode(&other, again, sizeof(again)) == len && !strcmp(out, again),
         "the order of the options does not change the bytes");

  // A path that climbs, or one that hides an empty or dot segment.
  other = action;
  other.target = "../helloworld";
  refused(&other, "a '..' at the start of a target is refused");
  other.target = "a/../b";
  refused(&other, "a '..' inside a target is refused");
  other.target = "a/./b";
  refused(&other, "a '.' segment in a target is refused");
  other.target = "a//b";
  refused(&other, "an empty segment in a target is refused");
  other.target = "/etc/passwd";
  refused(&other, "an absolute target is refused");
  other.target = "helloworld/";
  refused(&other, "a trailing slash in a target is refused");

  // Unicode has more than one spelling of the same text.
  other.target = "caf\xc3\xa9";
  refused(&other, "a Unicode target is refused");
  other.target = "cafe\xcc\x81";
  refused(&other, "a combining mark in a target is refused");
  other.target = "evil\xe2\x80\xaegpj";
  refused(&other, "a right-to-left override in a target is refused");
  other = action;
  other.command = "payload.c\xc3\xb6mmit";
  refused(&other, "a Unicode command is refused");
  other = action;
  other.options = unicode;
  other.noptions = 1;
  refused(&other, "a Unicode option value is refused");

  // Repeated options and everything that smuggles a second line in.
  other = action;
  other.options = repeated;
  refused(&other, "a repeated option is refused");
  other.options = injected;
  other.noptions = 1;
  refused(&other, "a newline in an option value is refused");
  other.options = spaced;
  refused(&other, "a space in an option value is refused");
  other.options = bad_key;
  refused(&other, "an option key outside the grammar is refused");
  other.options = no_value;
  refused(&other, "an option with no value is refused");
  other = action;
  other.target = "hello\nworld";
  refused(&other, "a newline in a target is refused");

  // An omitted field must not encode as an empty one.
  other = action;
  other.command = NULL;
  refused(&other, "an omitted command is refused");
  other.command = "";
  refused(&other, "an empty command is refused");
  other = action;
  other.target = NULL;
  refused(&other, "an omitted target is refused");
  other.target = "";
  refused(&other, "an empty target is refused");
  other = action;
  other.sha256 = NULL;
  refused(&other, "an omitted hash is refused");
  other.sha256 = "";
  refused(&other, "an empty hash is refused");

  // The hash is 64 lowercase hex digits and nothing else.
  other = action;
  other.sha256 = "3B1F";
  refused(&other, "a short hash is refused");
  other.sha256 = "3B1F0C9E5A7D2B4C6E8F0A1B3C5D7E9F1A2B4C6D8E0F1A3B5C7D9E1F2A4B6C8D";
  refused(&other, "an uppercase hash is refused");
  other.sha256 = HASH "0";
  refused(&other, "a hash that is too long is refused");

  // No action ever encodes into a buffer that cannot hold all of it.
  expect(encode(&action, out, (size_t)len) < 0,
         "a buffer without room for the final NUL is refused");
  expect(encode(&action, out, 8) < 0, "a short buffer is refused");

  // Without options an action still encodes, with no option lines.
  other = action;
  other.options = NULL;
  other.noptions = 0;
  expect(encode(&other, out, sizeof(out)) > 0 &&
         !strstr(out, "option."), "an action with no options encodes");

  printf(failures ? "\n%d check(s) failed\n" : "\nall checks passed\n",
         failures);
  return failures ? 1 : 0;
}
