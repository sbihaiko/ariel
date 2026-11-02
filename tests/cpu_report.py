"""A CPU test for the console, run by the console.

The host launches one app job per worker. Each hashes a fixed buffer, records
its PID, CPU time, digest and the monotonic start and end of its work, and
writes its JSON. Worker 0 then waits for its siblings' files, checks PIDs,
digests and overlap, and writes the run's report.

No threads and no forks: creating a thread inside an app job takes this
console down (#153), while two plain processes ran side by side and exited 0.
Worker 0 aggregates by polling files, so no job launches another job either.
"""

import hashlib
import json
import os
import sys
import time

BUFFER = b"ps5-cpu-report/" * (1024 * 1024 // 15 + 1)  # just over 1 MiB
ROUNDS = 2048  # ~2 GiB of hashing per worker: about 1.6 s of CPU each, the
# longest burst proven on this console; sustained load on all of its allowed
# CPUs is a documented way to shut it down
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


def mem_available():
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def write_json(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def worker(out_dir, run_id, index, rounds):
    trace("worker %d start rounds=%d" % (index, rounds))
    mem_samples = [mem_available()]
    start_monotonic = time.monotonic()
    start_cpu = time.process_time()
    digest = digest_for(rounds)
    cpu = time.process_time() - start_cpu
    end_monotonic = time.monotonic()
    mem_samples.append(mem_available())
    write_json(os.path.join(out_dir, "cpu-%s-w%d.json" % (run_id, index)), {
        "run_id": run_id,
        "index": index,
        "pid": os.getpid(),
        "rounds": rounds,
        "cpu_seconds": cpu,
        "start_monotonic": start_monotonic,
        "end_monotonic": end_monotonic,
        "result_digest": digest,
        "mem_available_kb": [value for value in mem_samples if value is not None],
    })
    trace("worker %d written cpu=%.3f" % (index, cpu))
    return 0


def platform_string():
    # This CPython port has no os.uname(); the report says so rather than
    # failing after the work is already done.
    try:
        return "%s %s" % (sys.platform, os.uname().machine)
    except AttributeError:
        return "%s unknown" % sys.platform


def read_results(out_dir, run_id, workers, timeout):
    """Worker 0 waits for every sibling's file; a missing one is a failure.

    Each poll also samples free memory, so the report carries the minimum seen
    while the workers were running rather than one reading at the end.
    """
    paths = [os.path.join(out_dir, "cpu-%s-w%d.json" % (run_id, i)) for i in range(workers)]
    deadline = time.time() + timeout
    mem_samples = []
    while time.time() < deadline:
        sample = mem_available()
        if sample is not None:
            mem_samples.append(sample)
        if all(os.path.isfile(p) for p in paths):
            break
        time.sleep(0.2)
    results = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                results.append(json.load(f))
        except OSError:
            pass
    return results, mem_samples


def aggregate(out_dir, run_id, workers, rounds, tested_sha, timeout):
    trace("aggregate start workers=%d rounds=%d" % (workers, rounds))
    expected_digest = digest_for(rounds)
    results, mem_samples = read_results(out_dir, run_id, workers, timeout)
    for item in results:
        mem_samples.extend(item.get("mem_available_kb") or [])
    trace("aggregate read %d results" % len(results))

    pids = [r.get("pid") for r in results]
    cpu = sum(float(r.get("cpu_seconds", 0)) for r in results)
    wall = 0.0
    overlap = 0.0
    if results:
        wall = max(float(r["end_monotonic"]) for r in results) - min(
            float(r["start_monotonic"]) for r in results
        )
        overlap = min(float(r["end_monotonic"]) for r in results) - max(
            float(r["start_monotonic"]) for r in results
        )

    failures = []
    if len(results) != workers:
        failures.append("only %d of %d workers reported" % (len(results), workers))
    if len(set(pids)) != len(pids):
        failures.append("worker pids are not distinct")
    if any(r.get("result_digest") != expected_digest for r in results):
        failures.append("a worker digest does not match the expected digest")
    if overlap <= 0:
        failures.append("the workers did not run at the same time")
    if not wall or cpu <= 1.5 * wall:
        failures.append("the workers did not overlap enough to use two cores")
    minimum_memory = min(mem_samples) if mem_samples else None
    if minimum_memory is not None and minimum_memory < 200 * 1024:
        failures.append("free memory fell below 200 MB: %d KB" % minimum_memory)

    with open(__file__, "rb") as f:
        test_sha256 = hashlib.sha256(f.read()).hexdigest()

    report = {
        "run_id": run_id,
        "tested_sha": tested_sha,
        "test_sha256": test_sha256,
        "cpu_count": os.cpu_count(),
        "affinity_count": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else "unavailable",
        "platform": platform_string(),
        "rounds": rounds,
        "wall_seconds": wall,
        "overlap_seconds": overlap,
        "cpu_seconds_total": cpu,
        "cpu_wall_ratio": (cpu / wall) if wall else 0,
        "expected_digest": expected_digest,
        "workers": results,
        "memory": {"mem_available_kb": minimum_memory, "samples": len(mem_samples)},
        "status": "ok" if not failures else "failed",
        "failures": failures,
    }
    write_json(os.path.join(out_dir, "cpu-%s.json" % run_id), report)
    trace("aggregate written status=%s failures=%d" % (report["status"], len(failures)))
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
    workers = int(value("--workers", 2))
    rounds = int(value("--rounds", ROUNDS))
    if "--index" in argv:
        code = worker(out_dir, run_id, int(value("--index")), rounds)
        if int(value("--index")) == 0:
            # The last word comes from the worker that started first, after it
            # has seen every sibling's file; no job launches another job.
            code = aggregate(out_dir, run_id, workers, rounds,
                             value("--tested-sha", "unknown"),
                             float(value("--timeout", 120)))
        return code
    return aggregate(out_dir, run_id, workers, rounds,
                     value("--tested-sha", "unknown"),
                     float(value("--timeout", 120)))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
