"""A CPU test for the console, run by the console.

Two roles, both inside the launcher's normal app jobs:

  --index N     one CPU-bound worker: hashes a fixed buffer, records its own
                CPU time, PID, digest and the monotonic start and end of its
                work, writes its JSON and exits.
  --aggregate   reads the workers' JSONs, checks PIDs, digests and overlap,
                and writes the run's report.

No job launches another job and no app forks. Upstream documents two ways this
console goes down: a second-level fork inside a job, and homebrew starting
while other homebrew runs (#153). The parallelism here is two worker jobs the
host launches side by side, and the aggregator only reads their files.
"""

import hashlib
import json
import os
import sys
import threading
import time

BUFFER = b"ps5-cpu-report/" * (1024 * 1024 // 15 + 1)  # just over 1 MiB
ROUNDS = 8192  # ~8 GiB of hashing per worker
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


def worker(out_dir, run_id, index, rounds):
    trace("worker %d start rounds=%d" % (index, rounds))
    start_monotonic = time.monotonic()
    start_cpu = time.process_time()
    digest = digest_for(rounds)
    cpu = time.process_time() - start_cpu
    end_monotonic = time.monotonic()
    payload = {
        "run_id": run_id,
        "index": index,
        "pid": os.getpid(),
        "rounds": rounds,
        "cpu_seconds": cpu,
        "start_monotonic": start_monotonic,
        "end_monotonic": end_monotonic,
        "result_digest": digest,
    }
    write_json(os.path.join(out_dir, "cpu-%s-w%d.json" % (run_id, index)), payload)
    trace("worker %d written cpu=%.3f" % (index, cpu))
    print("WORKER %d pid=%d cpu=%.3f" % (index, payload["pid"], cpu))
    return 0


def aggregate(out_dir, run_id, workers, rounds, tested_sha):
    trace("aggregate start workers=%d rounds=%d" % (workers, rounds))
    expected_digest = digest_for(rounds)

    stop = threading.Event()
    mem = []
    sampler = threading.Thread(target=sample_memory, args=(stop, mem), daemon=True)
    sampler.start()

    results = []
    failures = []
    for index in range(workers):
        path = os.path.join(out_dir, "cpu-%s-w%d.json" % (run_id, index))
        try:
            with open(path, "r", encoding="utf-8") as f:
                results.append(json.load(f))
        except OSError:
            failures.append("worker %d wrote no result" % index)

    stop.set()
    sampler.join(timeout=2)

    pids = [r.get("pid") for r in results]
    if len(results) != workers:
        failures.append("only %d of %d workers reported" % (len(results), workers))
    if len(set(pids)) != len(pids):
        failures.append("worker pids are not distinct")
    if any(r.get("result_digest") != expected_digest for r in results):
        failures.append("a worker digest does not match the expected digest")
    if any(r.get("rounds") != rounds for r in results):
        failures.append("a worker ran a different round count")

    wall = 0.0
    overlap = 0.0
    cpu = sum(float(r.get("cpu_seconds", 0)) for r in results)
    if results:
        first = min(float(r["start_monotonic"]) for r in results)
        last = max(float(r["end_monotonic"]) for r in results)
        wall = last - first
        overlap = min(float(r["end_monotonic"]) for r in results) - max(
            float(r["start_monotonic"]) for r in results
        )
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
        "workers": results,
        "memory": memory,
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
    rounds = int(value("--rounds", ROUNDS))
    out_dir = value("--out-dir", "/data/ps5-git/results")
    os.makedirs(out_dir, exist_ok=True)

    if "--index" in argv:
        return worker(out_dir, run_id, int(value("--index")), rounds)
    if "--aggregate" in argv:
        return aggregate(
            out_dir,
            run_id,
            int(value("--workers", 2)),
            rounds,
            value("--tested-sha", "unknown"),
        )
    print("usage: cpu_report.py --index N | --aggregate [--workers N] [--rounds N]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
