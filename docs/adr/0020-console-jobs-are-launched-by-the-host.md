# ADR-0020: The host launches console jobs; an app job never forks and never launches

## Status

Accepted. 2026-11-02. Supersedes the first draft of this record, which
attributed the crashes to `os.fork` alone.

## Context

The CPU evidence for the PS5 Git spike ([SPEC #149](https://github.com/sbihaiko/ariel/issues/149))
needs at least two CPU-bound workers running at the same time, with distinct
PIDs, matching digests and CPU time that exceeds the enclosing wall interval.

Three attempts took the console down:

- probe 1 (`1 worker, 8 rounds`): the test forked with `os.fork`. The trace
  ended at `child pid=99 end`, and the line for the parent's reap never
  arrived. The console stopped answering.
- probe 2 (`1 worker, 64 rounds`, pipe replaced by file IPC): the console went
  down again in the same place, after the child finished and before the parent
  reaped it. The pipe was not the cause.
- probe 3 (no fork at all): an aggregator job launched the worker jobs through
  the launcher's `/api/launch`, polled `/api/status`, and the console went
  down again. The host lost port 8090 mid-run.

So a second-level fork is not the whole story. The third probe has neither a
fork nor a pipe, but it does have one job asking the console to start more
homebrew while itself is running. Upstream documents that shape as unsafe:

- `ps5-payload-dev/websrv` reports, under Known Issues, "Homebrew sometimes
  crashes when there is already a previous homebrew running." Its loader
  rewrites kernel process structures that the previous process still
  references, and its `sys_set_butget(0)` was disabled because
  `SceSysCore.elf` crashes when the loaded child terminates.
- The same platform notes record that the console's services stop answering
  and the console shuts down when every allowed CPU is busy-waiting, and that
  only CPUs 9, 11, 13, 14 and 15 (affinity `0xea00`) are available.

The frozen console returned only on a power cycle, and one of the freezes
happened during the jailbreak itself, which the exploit's own notes attribute
to its race and not to any payload.

## Decision

1. An app job never calls `os.fork`, `os.posix_spawn` or any other
   process-creation call. The supervisor forks a process per job in C, and
   that is the only fork the spike uses.
2. An app job never launches another job. The host or the operator starts
   every job; the console side reads state from files, never from the
   launcher's API.
3. The CPU test is two worker jobs the host launches side by side, plus one
   aggregator job that only reads the workers' JSONs. Each worker records its
   own monotonic start and end, so the aggregator computes wall, overlap and
   the CPU-to-wall ratio without any clock crossing the host boundary.
4. A test keeps at most two CPU-bound workers, and no worker spins in a
   busy-wait: every allowed CPU busy is a documented way to shut the console
   down.

## Consequences

- The console is never the orchestrator. It runs what the host starts, and
  reports by file.
- The aggregator cannot see a worker that never wrote its file; a missing
  result is a failed run, not a retry.
- The CPU evidence measures real parallelism only if the host's two launches
  overlap, which the workers' monotonic intervals prove or disprove in the
  report itself.
- If the platform later makes concurrent homebrew safe, this rule may be
  revisited; until then a nested launch is a defect.

## Guard

None yet. This rule is a draft until a named guard test exists; when one
exists it will refuse a CPU test that imports `os.fork` or reaches the
launcher's API.
