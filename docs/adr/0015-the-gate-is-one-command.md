# ADR-0015: The gate is one command, and it names each half

## Status

Accepted. The owner asked for #118 to be fixed on 2026-10-26.

## Context

Every Stage 6 ticket carried the same acceptance command:

```
make clean all && { [ ! -d hostbuild ] || make -C hostbuild clean all test; }
```

It measured the machine, not the change. `make clean all` stops at
`Makefile:59: *** PS5_PAYLOAD_SDK is undefined ***` on a machine that has no
SDK exported, and because of the `&&` the host suite never ran either, so a
branch whose 425 headless scenarios were green reported `ac-verify:ac_failed`
(#113, `run-20261025-205944-b127d4`; the same command names #97). The
installer already knew three build routes (#110); the gate used none of them.

## Decision

1. **One command is the gate: `sh tools/gate.sh`.** It builds the payload and
   runs the host suite, in that order, and never lets one half hide the other:
   a red payload build still runs the suite, and a red suite is still reported
   beside a good build.
2. **It picks the route the installer picks**, without being told: an exported
   `PS5_PAYLOAD_SDK` with LLVM, otherwise the SDK in `~/.local/share`, otherwise
   a container built from `tools/install/Dockerfile.sdk`. The gate therefore
   measures the change on a Mac with Docker and no LLVM as it does on CI.
3. **It names each half on its own line**, `payload:` and `hostbuild:`, and
   ends with `gate: PASS` or `gate: FAIL (payload=<n> hostbuild=<n>)`, so a
   transcript says which half failed without anyone reading an exit status.
4. **A half that cannot run is `unavailable` and is not green.** It exits 3.
   ADR-0001 makes a gate a stop condition; a gate that could not measure the
   change stops it too, and saying so is the point.
5. **Nothing in the gate deploys, sends or reboots.** `make test` stays the one
   command that touches a console, and it still refuses without
   `ARIEL_DEPLOY=yes` ([ADR-0008](0008-the-telnet-shell-stays-outside-the-gate.md)).
6. Tickets and the delivery loop write `sh tools/gate.sh` as their acceptance
   command; a ticket that carries the old `make clean all && ...` is corrected
   when it is picked up.

## Consequences

- The gate needs one of: an SDK with LLVM, or Docker. A machine with neither
  gets a red gate that says `unavailable`, which is honest and fixable, rather
  than a green gate that tested half the change.
- The build runs without keys pinned: the gate proves the payload compiles, not
  that a particular owner's build is deployable. Keys stay the installer's job.
- Two commands changed meaning for the loop: the exit status now separates a
  red suite (1), a red payload build (2) and an unavailable build (3).

## Guard

`tools/test-gate.sh`: a throwaway repository with a stub `make`, a stub
`docker` and a stub `llvm-config`, proving each route, that the suite runs
beside a red or unavailable payload half, and each exit status.
