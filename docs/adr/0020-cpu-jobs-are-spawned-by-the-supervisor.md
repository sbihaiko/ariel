# ADR-0020: CPU jobs are spawned by the supervisor, never by an app's fork

## Status

Accepted. 2026-11-02.

## Context

The CPU evidence for the PS5 Git spike ([SPEC #149](https://github.com/sbihaiko/ariel/issues/149))
needs at least two CPU-bound workers running at the same time, with distinct
PIDs, exit codes and matching digests. The first version of
`tests/cpu_report.py` forked them itself with `os.fork` and joined them with a
pipe.

That version took the console down three times. The second-level fork lives
inside an app job, which the supervisor already forked once in C. The app's
traces were the evidence:

- probe 1 (`1 worker, 8 rounds`): `parent pid=98 begin`, `parent forked
  child=99`, `child pid=99 start`, `child pid=99 end cpu=0.001`, and then no
  `parent reaped` line. The console stopped answering and came back only to
  Safe Mode.
- probe 2 (`1 worker, 64 rounds`): the pipe was removed and the children wrote
  their results to files instead. The console went down again in the same
  place, after the child finished and before the parent reaped it. So the pipe
  was not the cause; the fork inside the job was.

Every app job the launcher has ever started is a fork the supervisor performs
in C, and none of them has done this. The supervisor's fork is safe; a fork
performed by Python inside a job is not.

## Decision

1. An app never calls `os.fork`, `os.posix_spawn` or any process-creation call
   to obtain parallelism on this console. Parallelism comes from the
   supervisor, which starts one job per worker through the launcher's
   `/api/launch` endpoint.
2. The CPU test has two modes. `--index N` is one worker: it hashes, records
   its CPU time, PID and digest, writes its JSON and exits. `--aggregate`
   launches the worker jobs, waits for their `job_id`s in `/api/status`,
   verifies distinct PIDs, exit 0 and matching digests, and writes the run's
   report.
3. The app's `--cpu` mode is the aggregator and `--cpu-worker <path>` is the
   worker. The audit hook stays installed in both, so a process-creation call
   inside the test is refused rather than attempted.
4. Evidence that a run's workers overlapped comes from the sum of the workers'
   CPU seconds against one enclosing wall interval, taken by the aggregator,
   not from any timing a worker reports about itself.

## Consequences

- A hung console now needs no explanation from a fork: the failure surface is
  the supervisor, already exercised by every job.
- A worker's cost includes the launcher's job start, so tiny round counts
  measure process start rather than CPU. Rounds stay high enough that the
  hashing dominates.
- The aggregator must be able to reach `127.0.0.1:8090` while its own job
  runs. The launcher already serves other jobs while one runs.
- If a console's kernel is later fixed for second-level forks, this rule may
  be revisited; until then a fork in an app job is a defect.

## Guard

None yet. This rule is a draft until a named guard test exists; when one
exists it will refuse a `tests/cpu_report.py` that calls `os.fork`.
