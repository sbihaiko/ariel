# ADR-0018: A repeat request for a pending approval answers its ID alone

## Status

Accepted. 2026-10-29.

## Context

A gated command answers `approval_required` with exit 75. The first request for an action opens an approval and carries the challenge the owner signs. Before this decision, a repeat of the same request while that approval was still pending answered the challenge again. [SPEC #136](https://github.com/sbihaiko/ariel/issues/136) fixes the reply in two shapes, and both must reach an MCP client the same way: with a `challenge` line when the request opens an approval, and alone when one is already pending.

[ADR-0012](0012-the-agent-port-line-grammar.md) fixes the line grammar and the closed word list, but not the shape of the approval reply. [ADR-0017](0017-the-mcp-server-is-a-host-process-that-never-signs.md) fixes what the MCP server returns. Neither records this shape, and clients written against `docs/exit-codes.md` expected a challenge on every exit 75.

## Decision

1. A request that opens an approval answers `approval_required <id>`, then the `challenge` line, then `exit 75`.
2. A request for the same action while that approval is pending answers `approval_required <id>`, then `exit 75`. It carries no `challenge` line and no second challenge is issued.
3. The approval expires 120 s after it was opened (`APPROVAL_EXPIRY_MS`). A request after that opens a new approval and answers its own challenge.
4. The MCP server accepts both shapes and returns each as `isError: true` with `approval_id`. The `challenge` field is present only in the first shape.
5. The agent port adds no command for reading a pending challenge. A word added to the closed list in `docs/exit-codes.md` is a separate decision.

## Consequences

- A client that lost the first reply cannot get the challenge back on the agent port. It waits for the approval to expire and repeats the request.
- A pending approval still counts toward the pending limit until it expires, so repeats do not multiply the count.
- A challenge is sent once per approval, on the reply that opens it.

## Guard

The scenarios `a second call while the approval is pending answers approval_id and no challenge line` and `a repeat after the approval expires opens a new approval with its challenge` in `hostbuild/tests/mcp_acceptance.py` guard decisions 2 and 3 through the agent port and the MCP server.
