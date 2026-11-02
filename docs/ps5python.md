# Python on the console

The spike in ticket #149 asks one question: can the console clone a
repository, run its CPU test, commit the result and push it back, with no
process spawn anywhere in the loop? The console side of that answer lives in
`ps5git/`; the host side in `tools/ps5python/`.

## What the console carries

- `/data/python/runtime/python-web.elf` — the CPython 3.14.7 web launcher.
- `/data/python/runtime/python-app-supervisor.elf` — the app supervisor.
- `/data/python/runtime/cpython-lib/` — the pure-Python standard library.
- `/data/python/web/` — the launcher's browser assets.
- `/data/python/apps/ps5-git/` — the spike app, with `lib/` holding the pinned
  dependencies.
- `/data/ps5-git/` — state: `config.json`, the test-only bad CA, `results/`
  and `log/`.

The console's loader port (9021) is closed on the current firmware setup, so
the two ELFs are started by the telnet shell (2323), which runs a path through
`elfldr_spawn`. A payload started that way survives the disconnect and is
adopted by init. Application jobs are then started over the launcher's HTTP
API on 8090, which is the only path the tickets allow for the app itself.

## Host commands

```sh
python3 tools/ps5python/deploy.py app ps5-git ps5git
python3 tools/ps5python/bootstrap.py --build BUILD --state STATE
python3 tools/ps5python/make_bundle.py --python-build CHECKOUT
python3 tools/ps5python/check_bundle.py dist/ps5-python
python3 tools/ps5python/compare_bundles.py dist/a dist/b
python3 tools/ps5python/run_cpu.py --run-id manual1 --workers 2
python3 tools/ps5python/e2e_check.py --repo sbihaiko/ps5-git-spike --run-id ID
```

`run_cpu.py` launches the `--cpu` mode of the app, waits for the job, fetches
the report over ftpsrv and judges it. Two steps still need the owner; they are
written down in `docs/ps5python-owner-steps.md`.

`bootstrap.py` uploads the runtime, the app and the state over ftpsrv and then
starts the supervisor and the launcher. `make_bundle.py` assembles the
reproducible bundle and writes `PINS.json` and `MANIFEST.json`;
`check_bundle.py` refuses a bundle with a changed byte, an unexpected file or
a native library.

## The CPU test

`tests/cpu_report.py` runs as one job per worker. Each worker hashes a fixed
buffer, records its PID, CPU time, digest and the monotonic start and end of
its work, and writes its JSON. Worker 0 then polls for its sibling's file,
checks PIDs, digests and overlap, and writes `results/cpu-<run-id>.json`.

The host launches both workers (`--cpu-worker <path> --index N`); no job
launches another job, no job forks and no job creates a thread. All three are
ways this console goes down, and the thread one is measured: an idle thread
inside a job was enough ([ADR-0020](adr/0020-console-jobs-are-launched-by-the-host.md)).
A run with the defaults reports `cpu_count=16`, two distinct PIDs, a ratio near
1.95 and `CPU OK`.

## The end-to-end run

Three host steps, because a console job may not launch another job: `--clone`
records the tested SHA in `/data/ps5-git/state/clone.json`, one
`--cpu-worker` job per worker writes its result, and `--run` checks the report
against the clone (status, `test_sha256`, `tested_sha`, memory floor) and
pushes the commit. `tools/ps5python/e2e_run.py` drives the three steps.

The workers execute the copy under `/data/ps5-git/tests/` rather than the
clone's own file, which is byte-identical; the report's `test_sha256` is
checked against the clone, so the evidence still belongs to the tested tree.

## Why the console's Git writes bypass dulwich's lock file

Dulwich writes a loose object by calling `os.utime(path)` and returning early
when it does not raise, then writing `<path>.lock` and renaming it into place.
On this console both calls answer success and leave no file: `utime` on a
missing path neither raises nor creates anything, and the rename leaves
neither name behind. A commit therefore reported a SHA and pushed nothing
(`COMMIT READBACK MISSING`), which is the same stub behaviour ADR-0007
records for the C agent.

`git_runner` patches dulwich when it is imported: a loose object is written
straight to its final path with `open`/`write`/`fsync`, and every other
`GitFile` write copies the lock file's bytes over the target instead of
renaming it. Both check that the target exists afterwards
([ADR-0021](adr/0021-console-git-writes-avoid-rename.md)).

A full run prints `E2E OK <tested> <result commit> 2` from
`tools/ps5python/e2e_check.py`.

## The self-test

`main.py --selftest` prints one line per capability:

```text
PYTHON OK 3.14.7 freebsd
AUDIT OK subprocess blocked ...
FORK OK parent=<pid> child=<pid> status=0
HTTPS OK verified github.com CN=...
```

The two negative modes (`--selftest-negative-ca`, `--selftest-negative-host`)
are expected to fail the handshake: they print `HTTPS FAIL verified ...` and
exit non-zero. An unexpected acceptance prints `accepted wrong` and exits
zero, so the pair never reports success for the failure it exists to catch.

## Build gotchas found on macOS

- The upstream scripts assume Linux tooling. Run them with the GNUsed and
  sha256sum shims on `PATH`, and with `/opt/homebrew/opt/llvm/bin` there too:
  the `prospero-*` wrappers resolve `llvm-ar` and friends from `PATH`.
- `make clean` in the CPython build directory empties the dependency
  prefixes under `deps/*/lib`. Back those up before cleaning, or the next
  link fails with `unable to find library -lssl` or `-lffi`.
- The SDK ships no `libm`: an empty `libm.a` plus `-lSceLibcInternal` at the
  end of each link is what makes `--with-libm=no` work.
- zlib and sqlite must be archived with `prospero-ar`; the host `ar` writes an
  archive lld cannot read, and it fails only at the final link.

## Dependencies

Dulwich 1.2.20, urllib3 2.8.0 and certifi are fetched as sdists and checked
against their pinned SHA-256, never installed with pip on the console and
never taken from a native wheel. Dulwich's clean/smudge filters would spawn a
process; the audit hook installed in the app blocks `subprocess.Popen`, `exec`
and the spawn family for the whole run.
