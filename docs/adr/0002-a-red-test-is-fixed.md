# ADR-0002: A red test is fixed, whoever broke it

## Status

Accepted.

## Context

A red test in ariel blocks trust in the suite. An agent that finds a red test it did not cause can skip it. Then the suite rots.

## Decision

1. **A red test is fixed, whoever broke it.** Do not skip, delete, or mark it expected-to-fail to get past it.
2. Run the gate, `sh tools/gate.sh`, before every commit: the payload build and the host suite, each named ([ADR-0015](0015-the-gate-is-one-command.md)).
3. If the cause is outside the change, fix it in its own commit, or open a ticket in GitHub Issues (sbihaiko/ariel) and say so.

## Guard

None yet. This rule is a draft until a named guard test exists.
