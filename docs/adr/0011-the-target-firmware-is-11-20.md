# ADR-0011: The target firmware is 11.20, and only 11.20 for now

## Status

Accepted. 2026-10-24. Deliberately narrow while the shell is young; this decision is meant to be replaced, not amended, when a second firmware is adopted.

## Context

Ariel reaches the kernel and the system modules through a platform port, and every firmware release moves symbols, offsets and behaviour under it. [ADR-0007](0007-ps5-at-calls-use-the-compat-header.md) already narrows that surface to one compat header, which keeps a firmware change to one file instead of a hundred call sites — but it does not make the port portable by itself.

One console is in hand. It runs 11.20: `kern.version` answers `r223898/releases/11.20 Apr 17 2025`. Every console validation this project has — the Stage 1 suite, the telnet boundary check, the controller spike, the key run and the 36/36 console suite — happened on it. Nothing here has ever been run on another firmware, and no one has a second console to run it on.

A claim of firmware support is not a claim about code that compiles. It is a claim about a console run, and this project cannot produce that run for any version but one.

## Decision

1. **Ariel targets firmware 11.20 and claims nothing about any other firmware.** The README says so at the top, in the terms of this decision.
2. **A behaviour reported on another firmware is not a defect until that firmware is adopted.** It is not reproduced, not worked around, and not defended against speculatively.
3. **Adopting another firmware is a decision with its own console evidence**, not a patch: it replaces this ADR, and it is done when the console suite passes on the new firmware and `docs/console-findings.md` says what changed.
4. **The build records its target firmware, and a run on another version is visible.** It is recorded and visible in the audit and the log; Ariel does not refuse to start, because a refusal would turn a laboratory fact into a lockout.
5. **No code claims portability across firmware in a comment.** A remark such as "per firmware" that no run backs is a promise the project cannot keep, and it reads as tested when it is not.

## Consequences

- The console suite's evidence is firmware-scoped: "green" means green on 11.20, and a future port is a new collection of runs, not a checkbox.
- The compat header of ADR-0007 stays the one place a call is pinned. A second firmware starts there.
- A jailbreak that moves to another firmware leaves this project behind on purpose until the new console evidence exists; that is cheaper than maintaining a claim nobody can test.
- Recovery advice and console findings carry the version they were observed on, so a reader on another firmware knows what does not apply to them.

## Guard

None yet. This rule is a draft until a named guard test exists.
