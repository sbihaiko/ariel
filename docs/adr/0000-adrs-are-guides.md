# ADR-0000: ADRs are guides, not locks

## Status

Accepted.

## Context

An ADR records why ariel took a decision. The next change then starts from that reasoning. It does not rediscover it.

A project that treats every past decision as binding becomes locked into old rules. Old rules slow development and delay delivery.

## Decision

1. **An ADR is a guide for the evolution of ariel. It must not stand in the way.** The code, the facts, or the product direction can outgrow an ADR. Then update, rewrite, or delete that ADR in the change that outgrows it. The commit states the fact that forced the change.
2. **Git keeps the history.** Do not keep a superseded ADR alive for reference. An amendment rewrites the ADR it amends. An ADR that replaces another deletes it in the same commit. Citations that named the old ADR move in that commit.
3. **`CLAUDE.md` follows the same rule.** Keep it current in the change that makes it stale.
4. **The owner's own words outrank every ADR.**
5. **Follow a guide while it stands.** You are free to change an ADR. You are never free to ignore it. A red guard is still a defect.
6. **ADRs and instruction files are never ledgers.** They hold no dates, counts, statuses, issue numbers, run ids or amendment logs. A changed decision is rewritten in place.

## Guard

None yet. This rule is a draft until a named guard test exists.
