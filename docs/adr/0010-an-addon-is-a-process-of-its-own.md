# ADR-0010: A capability beyond the gate is an addon in a process of its own

## Status

Accepted. 2026-10-24.

## Context

Stage 4 gives the agent sight, and the first capability it needs is a screenshot. The owner asked for more than one command: a way to add capabilities to Ariel without rebuilding the payload each time.

Three shapes were on the table, and the first two were rejected on the trust model this repository already states.

- **Loaded into Ariel's process.** Code inside the payload runs in the same trust domain as the gate. It reaches the token, the keyring, the grants and the state directory directly; `protected.c` refuses those to *gated commands*, and says nothing to code that is already inside. A loaded addon would also be able to answer the agent port itself. Rejected: the addon set would silently become the gate.
- **Compile-time modules.** Honest and small, but every capability becomes a rebuild by the owner, and the payload grows with every one of them. Kept for a capability that cannot afford a process, not adopted as the general answer.
- **A process of its own.** The platform port already spawns an ELF payload with a pipe for its output, polls it and kills it (`ps5_spawn_start`, `ps5_spawn_poll`, `ps5_spawn_kill`), behind one process-wide loader lock. The isolation this needs is the one that already exists.

## Decision

1. **An addon is an ELF and a manifest, and it runs in its own process.** Ariel never loads addon code into its own address space.
2. **Ariel is the gate and the router.** An addon's command is registered on the agent port and goes through the one existing gate: `approval_required` (75), a single-use approval of the canonical action (the addon's name, the manifest's SHA-256 and the arguments), audit words of the same shape as every other gated command, and exit codes drawn from `docs/exit-codes.md`. There is no second gate and no second approval source.
3. **The agent cannot install, replace or remove an addon.** Addons live in a protected directory that the file commands refuse like the token, and they enter only by the owner, out of band. `payload push` and `commit` remain the agent's path to its own code and never reach the addon set.
4. **A mismatch is refused before the gate.** The manifest declares the addon's name, the shape of its arguments, the Ariel ABI version it was built against and its platform tag. An addon built for another ABI or another platform is refused by name, and nothing is asked of the owner.
5. **The process boundary is the isolation, and it is bounded on three sides**: a timeout, an output cap, and a kill. Ariel survives an addon that crashes, hangs or floods, and reports each as its own refusal.
6. **An addon never receives Ariel's credentials.** It gets its arguments on its own descriptors. The token, the keyring and the state directory are not passed, and an addon's result is a file under `/data`, never inside the protected state directory.
7. **One spawn at a time**, through the loader lock the platform port already holds.

## Consequences

- Every addon is a second ELF to keep compatible, and the manifest is the contract between them.
- A capability that cannot afford a process — one inside a timing-sensitive path — stays built in. That is a decision for that capability, not a new gate.
- The protocol and the manifest are proven by a real capability: the screenshot is the first addon, and the capture API is measured on the console before either is built.
- An addon's failure is the gate's business, not the console's: a timeout and a kill replace a reboot.

## Guard

None yet. This rule is a draft until a named guard test exists. The test to write with the first addon: the agent port offers no path that installs, replaces or removes an addon, and an addon's command answers 75, audits like every other gated command, and answers with a code from `docs/exit-codes.md`.
