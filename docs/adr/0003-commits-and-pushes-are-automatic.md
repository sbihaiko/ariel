# ADR-0003: Commits and pushes are automatic

## Status

Accepted.

## Context

ariel works with agents. Asking for leave after every change slows each change and adds no safety.

## Decision

1. **Commit and push after every change. Do not ask.**
2. Each commit holds one change and a message that states why.
3. The owner can stop this rule at any time. Then the rule is rewritten or deleted (ADR-0000).

## Guard

None yet. This rule is a draft until a named guard test exists.
