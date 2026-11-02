# ADR-0020: The host launches console jobs; an app job never forks, threads or launches

## Status

Accepted. 2026-11-02. Rewritten twice as the traces came in; the decisions
below are the ones the console proved.

## Context

The CPU evidence for the PS5 Git spike ([SPEC #149](https://github.com/sbihaiko/ariel/issues/149))
needs at least two CPU-bound workers running at the same time, with distinct
identities, matching digests and CPU time that exceeds the enclosing wall
interval.

Seven attempts took the console down. Every one left a durable line in
`/data/ps5-git/log/cpu-trace.txt`, written with `fsync` per line, so the last
line says where it stopped:

| Probe | Shape | Trace ends at |
|---|---|---|
| 1 | one job, `os.fork`, pipe | child finished, parent never reaped |
| 2 | one job, `os.fork`, file IPC | same place, so the pipe was innocent |
| 3 | a job launching jobs over the launcher API | mid-run, host loses 8090 |
| 4 | host launches two workers, then an aggregator | both workers exit 0; the third job dies at its first line |
| 5 | one job, two threads, 2048 rounds | during the threads |
| 6 | one job, two threads, 128 rounds | during the threads |
| 7 | one job, one **idle** thread | between `probe start` and `idle thread ok` |

After each one the console stops answering at the IP level, so these are
system shutdowns. Probe 7 is the one that names the trigger: creating a
single idle thread inside an app job is enough. The two worker processes of
probe 4, which created no threads, hashed 2 GiB each and both exited 0.

Upstream agrees on the surrounding ground:

- `ps5-payload-dev/websrv` reports, under Known Issues, "Homebrew sometimes
  crashes when there is already a previous homebrew running"; its loader
  rewrites kernel process structures the previous process still references,
  and its `sys_set_butget(0)` was removed because the syscore crashes when the
  bigapp child terminates.
- On PS5, `exit()` and `_Exit` raise `SIGSYS`, and a title that calls
  `fork`/`posix_spawn` crashes on real hardware; `waitpid` has no real
  children to reap.
- Only CPUs 9, 11, 13, 14 and 15 (affinity `0xea00`) are usable, and starving
  them shuts the console down.

## Decision

1. An app job never calls `os.fork`, `os.posix_spawn` or any other
   process-creation call. The supervisor forks a process per job in C, and
   that is the only fork the spike uses.
2. An app job never creates a thread. This one is measured, not inferred:
   one idle thread is enough to take the console down.
3. An app job never launches another job. The host or the operator starts
   every job.
4. The CPU test is therefore two worker processes the host launches side by
   side. Each hashes its share, records PID, CPU time, digest and its own
   monotonic start and end, and writes a JSON. Worker 0 then polls for its
   sibling's file and writes the run's report, computing wall, overlap and
   the CPU-to-wall ratio from the two intervals. The aggregation is a file
   read inside an existing process, not a new job.
5. A test keeps at most two CPU-bound processes and a burst of about two
   gigabytes each, the longest one proven on this console.

## Consequences

- The console is never the orchestrator and never the place where work is
  split; it runs what the host starts, and reports by file.
- The workers' monotonic intervals prove overlap without host timing, so the
  CPU evidence stands on the console's own clock.
- A worker that dies before writing its file makes worker 0 fail with a named
  reason; there is no retry loop on the console.
- Burst length is a tuning parameter on a platform that shuts down under
  sustained load.

## Guard

`tools/ps5python/check_cpu_report.py` reads `tests/cpu_report.py` as source
and refuses a `fork`, a spawn call, a thread import or an import of the
launcher's API. It then runs two worker processes on the host and refuses a
report that is malformed or whose worker PIDs are not distinct. It prints
`GUARD OK` or `GUARD FAIL <reason>`.
