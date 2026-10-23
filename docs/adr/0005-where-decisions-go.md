# ADR-0005: Where decisions go

## Status

Accepted.

## Context

A decision with no fixed place gets lost, or lands in `CLAUDE.md` and turns it into a ledger.

## Decision

1. A durable engineering decision goes in an ADR in `docs/adr/`.
2. A decision for one ticket goes in a comment on that ticket in GitHub Issues (sbihaiko/ariel).
3. A one-off fact or grant goes in a memory file. `MEMORY.md` is the index.
4. Anything else goes in the commit message.
5. `CLAUDE.md` holds rules and pointers only. It never holds a status, a date, or a count.

## Guard

None yet. This rule is a draft until a named guard test exists.
