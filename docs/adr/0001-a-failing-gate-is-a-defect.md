# ADR-0001: A failing gate is a defect; a gate is a stop condition

## Status

Accepted.

## Context

ariel uses gates: checks that stop work when they fail. A gate that is retuned until it passes no longer protects anything.

## Decision

1. **A failing gate is a defect.** Find the cause. Do not retune the expectation to make it pass.
2. **A gate is a stop condition, never a target.** Do not optimize work to satisfy the gate. Verify the instrument first.
3. Re-anchor an expectation only with evidence that the old one was wrong.

## Guard

None yet. This rule is a draft until a named guard test exists.
