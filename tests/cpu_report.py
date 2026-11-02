"""A CPU test for the console, run by the console.

One app job runs N worker threads. Each hashes a fixed buffer and records its
own thread id, CPU time, digest and the monotonic start and end of its work;
the job then writes the run's report.

There are no processes here on purpose. Every attempt to run two console homebrew
processes at once took this console down (#153), with or without a fork and with
or without one job launching another, which matches the platform note that
homebrew crashes when previous homebrew is running. hashlib releases the GIL
for a buffer this size, so two threads hash on two cores inside one process.
"""

import hashlib
import json
import os
import sys
import threading
import time

BUFFER = b"ps5-cpu-report/" * (1024 * 1024 // 15 + 1)  # just over 1 MiB
ROUNDS = 512  # ~0.5 GiB of hashing per worker: short bursts, the platform
# shuts the console down after sustained load on all of its allowed CPUs
TRACE_PATH = os.environ.get("PS5GIT_TRACE", "/data/ps5-git/log/cpu-trace.txt")


def trace(message):
    """Append one line and flush it to the disk before returning.

    A crash takes the console off the network, so the trace has to be durable
    at every line, not buffered until exit.
    """
    try:
        os.makedirs(os.path.dirname(TRACE_PATH), exist_ok=True)
        fd = os.open(TRACE_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            line = "%s pid=%d %s\n" % (time.strftime("%H:%M:%S"), os.getpid(), message)
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def digest_for(rounds):
    digest = hashlib.sha256()
    for i in range(rounds):
        digest.update(BUFFER)
        digest.update(i.to_bytes(4, "little"))
    return digest.hexdigest()


def sample_memory(stop, out):
    while not stop.is_set():
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        out.append(int(line.split()[1]))
                        break
        except OSError:
            out.append(None)
        stop.wait(1.0)


def write_json(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def thread_cpu():
    # CLOCK_THREAD_CPUTIME_ID where the platform has it; the process clock is
    # the honest fallback and the report says which one was used.
    if hasattr(time, "thread_time"):
        return time.thread_time(), "thread"
    return time.process_time(), "process"


def worker(index, rounds, results, clock):
    trace("worker %d start rounds=%d" % (index, rounds))
    start_monotonic = time.monotonic()
    start_cpu, _ = thread_cpu()
    digest = digest_for(rounds)
    cpu = thread_cpu()[0] - start_cpu
    end_monotonic = time.monotonic()
    results[index] = {
        "index": index,
        "thread_id": threading.get_ident(),
        "pid": os.getpid(),
        "rounds": rounds,
        "cpu_seconds": cpu,
        "start_monotonic": start_monotonic,
        "end_monotonic": end_monotonic,
        "result_digest": digest,
        "clock": clock,
    }
    trace("worker %d done cpu=%.3f" % (index, cpu))


def run(rounds, workers, tested_sha, run_id, out_dir):
    trace("run start workers=%d rounds=%d" % (workers, rounds))
    expected_digest = digest_for(rounds)
    trace("expected digest computed")

    stop = threading.Event()
    mem = []
    sampler = threading.Thread(target=sample_memory, args=(stop, mem), daemon=True)
    sampler.start()

    clock = "thread" if hasattr(time, "thread_time") else "process"
    results = {}
    threads = []
    for index in range(workers):
        t = threading.Thread(target=worker, args=(index, rounds, results, clock))
        threads.append(t)
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    finished = time.monotonic()
    trace("threads joined")

    stop.set()
    sampler.join(timeout=2)

    ordered = [results[i] for i in sorted(results)]
    thread_ids = [r["thread_id"] for r in ordered]
    cpu = sum(r["cpu_seconds"] for r in ordered)
    wall = finished - started
    overlap = 0.0
    if ordered:
        overlap = min(r["end_monotonic"] for r in ordered) - max(
            r["start_monotonic"] for r in ordered
        )

    failures = []
    if len(ordered) != workers:
        failures.append("only %d of %d workers reported" % (len(ordered), workers))
    if len(set(thread_ids)) != len(thread_ids):
        failures.append("worker thread ids are not distinct")
    if any(r["result_digest"] != expected_digest for r in ordered):
        failures.append("a worker digest does not match the expected digest")
    if overlap <= 0:
        failures.append("the workers did not run at the same time")
    if not wall or cpu <= 1.5 * wall:
        failures.append("the workers did not overlap enough to use two cores")

    available = [value for value in mem if value is not None]
    memory = {
        "mem_available_kb": min(available) if available else "unavailable",
        "interval_seconds": 1,
        "samples": len(mem),
    }

    with open(__file__, "rb") as f:
        test_sha256 = hashlib.sha256(f.read()).hexdigest()

    report = {
        "run_id": run_id,
        "tested_sha": tested_sha,
        "test_sha256": test_sha256,
        "cpu_count": os.cpu_count(),
        "affinity_count": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else "unavailable",
        "platform": "%s %s" % (sys.platform, os.uname().machine),
        "rounds": rounds,
        "wall_seconds": wall,
        "overlap_seconds": overlap,
        "cpu_seconds_total": cpu,
        "cpu_wall_ratio": (cpu / wall) if wall else 0,
        "expected_digest": expected_digest,
        "workers": ordered,
        "memory": memory,
        "status": "ok" if not failures else "failed",
        "failures": failures,
    }
    write_json(os.path.join(out_dir, "cpu-%s.json" % run_id), report)
    trace("run written status=%s failures=%d" % (report["status"], len(failures)))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failures else 1


def main(argv):
    def value(name, default=None):
        return argv[argv.index(name) + 1] if name in argv else default

    run_id = value("--run-id") or "%s-%06x" % (
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        int.from_bytes(os.urandom(3), "big"),
    )
    out_dir = value("--out-dir", "/data/ps5-git/results")
    os.makedirs(out_dir, exist_ok=True)
    return run(
        int(value("--rounds", ROUNDS)),
        int(value("--workers", 2)),
        value("--tested-sha", "unknown"),
        run_id,
        out_dir,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
