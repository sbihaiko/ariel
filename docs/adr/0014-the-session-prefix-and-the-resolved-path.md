# ADR-0014: The session prefix, and the path the gate signs

## Status

Accepted. 2026-10-25.

## Context

The agent port is one command per connection ([ADR-0012](0012-the-agent-port-line-grammar.md)), which is the right shape for an agent and the wrong one for state: a working directory and an environment cannot survive between two connections unless something names them. Stage 5 adds sessions, and two questions follow that touch the line grammar rather than the session table.

- **How a line names a session.** It could be an option on every command (`--session <id>`), a new field on the auth line, or a prefix on the command. An option would mean every command parses it, and a second parser is exactly what ADR-0012 decision 1 forbids.
- **What a relative path means.** Until now a path was absolute, and a relative one answered `relative_path` before any check. A session's directory makes a relative path meaningful, which asks where the join happens and which path the owner is shown.
- **What an unknown session costs.** The unlisted-command path asks the owner for a signature (a `unlisted` approval naming the word). A typo in a session ID must not reach it: the owner would be asked to sign a command that is not what the agent meant to send.

## Decision

1. **The first token decides.** A command line whose first token begins with `@` carries a session prefix: the token is `@` followed by the session ID, and the remaining tokens are the command. Any other first token is an ordinary command, so nothing changes for a client that never uses a session.
2. **A prefix that is not a live session is refused as a session.** A token that begins with `@` and is not `@` plus exactly 32 lowercase hex characters, or that names a session which is not live, answers `session_expired` (exit 93) before the rest of the line is read as a command and before any gate. It never reaches the unlisted-command path, so it never asks the owner. One word covers malformed, unknown and expired: the client's next step is the same for all three.
3. **The prefix carries no authority.** It names state, not permission. A gated command inside a session asks the owner exactly as it does outside one, and the session ID never enters the canonical action, so the owner signs the command and not a handle.
4. **A relative path is resolved before the gate.** Inside a session, a path that does not begin with `/` is joined to the session's directory before any check, any staging and any gate, and everything afterwards — the protection check, the allowed roots, the canonical action — sees the absolute path. The owner therefore signs the path that will actually be acted on.
5. **The join is lexical.** No `realpath` and no symbolic link following: `.` and `..` are normalised as text, so a segment the canonical action may not carry ([ADR-0012](0012-the-agent-port-line-grammar.md) decision 2) never reaches it, and a symbolic link keeps the refusal it already had. An `..` that would leave the root answers `bad_path`.
6. **A client without a session keeps today's grammar exactly.** A relative path answers `relative_path`, `cd` answers `no_working_directory` and `pwd` answers `/`.

## Consequences

- The grammar gains one token shape and one rule about where a path is resolved; both live in the one parser and the one path check, not in each command.
- A misspelled session ID is cheaper than any other mistake on the port: one reply, and the owner is not disturbed.
- A path in a session is signed in its absolute form, so a grant for `bin/x` in `/data/pkg` is a grant for `/data/pkg/bin/x` and for nothing else.
- Sessions stay optional: nothing about the grammar or the gate changes for a client that ignores them.

## Guard

None yet. This rule is a draft until a named guard test exists. The test to write with the prefix: a malformed or unknown prefix answers `session_expired` and raises no approval prompt, a gated command through the prefix signs the absolute path and no session ID, and a relative path with no session still answers `relative_path`.
