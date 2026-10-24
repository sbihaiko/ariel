# ADR-0012: The agent port's line grammar

## Status

Accepted. 2026-10-24.

## Context

The agent port is line-oriented: one command per connection, its arguments split on spaces, and every answer ending with `exit <status>`. Three things about that grammar have become load-bearing and were never decided in one place.

- **Arguments.** `split_args` cuts on spaces and tabs and nothing else. On the console, `ls "/data"` answers `No such file or directory`, because the quotes are part of the name; a path holding a space cannot be addressed at all.
- **The canonical action.** [ADR-0006](0006-the-controller-is-the-approval-source.md) decision 6 requires one encoder for the action the owner signs, and its `target_ok` accepts only letters, digits, `_`, `-` and `.` per segment. A gated command naming a path with a space, a bracket or any other byte cannot be encoded, so it is refused before the owner ever sees it. The console holds such paths: `/data/homebrew/PPSA03671 Marvels Wolverine.ffpfsc.part` was on it on 2026-10-24.
- **Bytes.** `payload push <name> <size> <sha256>` already moves a binary body on the same connection: the command line carries the size and the hash, then exactly that many bytes follow.

Stage 3 adds `write`, a binary `read` and bounded readers, and [ADR-0010](0010-an-addon-is-a-process-of-its-own.md) needs an output cap for addons. Each of those would otherwise invent its own rules.

## Decision

1. **One parser, one grammar.** A command line is tokens separated by spaces or tabs. Double quotes and single quotes group a token and are removed; inside double quotes `\"` and `\\` escape; inside single quotes nothing escapes. No globbing, no variable expansion and no redirection: a `*` is a literal byte. A line holds at most 64 tokens and 4096 bytes; more answers `too_many_arguments` (exit 1), and an unbalanced quote answers `bad_quoting` (exit 1), both before any command runs.
2. **The canonical action carries arbitrary bytes.** In `target`, `destination` and every option value, a byte outside `[A-Za-z0-9._-]` is written `%XX` in uppercase hex, and `%` itself is written `%25`, so the encoding is injective. The owner's signer decodes it before showing the action, so the owner reads the real path. Paths stay absolute, and a segment that decodes to `.`, to `..` or to nothing is refused: escaping makes bytes expressible, never traversal.
3. **This replaces the character rule of ADR-0006 decision 6**, which allowed only letters, digits, `_`, `-` and `.`. The encoder stays one function and remains the only one.
4. **One frame for every byte movement.** A command line carries `<size> <sha256>`, then exactly `<size>` bytes follow on the same connection. `payload push` already does this; `write` adopts it. `read` answers `bytes <size> <sha256>` followed by `<size>` bytes. A body whose size or hash does not match is refused and nothing is kept.
5. **One output cap: 64 KiB per answer**, as one constant. A reader that would exceed it cuts, prints `truncated <shown> of <total>` and exits 0; it never refuses for being large. An addon's output is capped by the same constant (ADR-0010).
6. **One deadline: 60 seconds per connection.** A command still running at the deadline is stopped and the answer is `timed_out` (exit 1). `sleep` keeps its own ceiling below it.
7. **JSON is one object per line**, with stable keys, and the `exit <status>` line stays the last line of every answer, so a client can tell a complete answer from a cut one.
8. **The word list is closed** and lives in `docs/exit-codes.md` before any code uses a word: `bad_quoting`, `too_many_arguments`, `bad_option`, `too_large`, `bad_range`, `timed_out`, and the marker `truncated`, which is not an error.

## Consequences

- A path with a space becomes addressable and gated; before this decision it could not be named at all, not even to be refused with a reason.
- The signer's display grows one step: decode, then show. A signature is still over exactly one action.
- 64 KiB is small enough not to flood an agent's context and large enough for a page of text; a screenshot arrives in ranges instead of one answer.
- Every command shares one parser. A command that splits its own arguments is a defect, not a variation.
- An answer that ends without `exit <status>` is a cut answer, and clients may rely on that.

## Guard

None yet. This rule is a draft until a named guard test exists. The test to write with the parser: a quoted path with a space runs and appears decoded in the canonical action, an unbalanced quote and a 65th token are refused with their words, and no command splits arguments outside the one parser.
