# ADR-0008: The telnet shell stays outside the gate

## Status

Accepted. The owner decided it on 2026-10-23, during the review of Stage 2 (#2).

## Context

ADR-0006 decision 10 limits the approval gate to the agent port. The first draft of Stage 2 went further: it gated every telnet command that changes the system and required the access token on telnet, reads included.

The approval source is now the owner's key. If telnet were gated, a lost key would also lock the owner out of the one path that can repair the console without the key. No recovery or revocation path for the key exists yet (#15).

## Decision

1. In Stage 2 the telnet shell on port 2323 stays as in upstream shsrv: no token, no approval, every command it has today.
2. Stage 2 gates commands on the agent port only. The copies of those commands on telnet stay ungated.
3. The trusted-network rule is the only protection on telnet. The README safety model and `docs/telnet-boundary.md` say so, and the manual check in that page is run once per release that touches the shell or the agent port.
4. Gating telnet, or requiring a token on it, needs a new ADR, and it cannot come before the key recovery path in #15.

## Consequences

- Anyone who can reach port 2323 can do anything the shell offers, including reading Ariel's token and approval state. Stage 2's secrets and self-protection rules hold on the agent port only.
- The owner keeps a way into the console that works without the key.

## Guard

None yet. This rule is a draft until a named guard test exists.
