"""A CPU test for the console, run by the console.

Two roles, both inside the launcher's normal app jobs:

  --index N     one CPU-bound worker: hashes a fixed buffer, records its own
                CPU time, PID and digest, writes its JSON and exits.
  --aggregate   launches the workers through the supervisor's HTTP API, waits
                for them, and writes the run's report.

There is no os.fork anywhere. A second-level fork inside an app job takes this
console's kernel down (ticket #153), so the parallelism comes from the
supervisor, which forks a process per job in C and has done so for every app
since the launcher started.
"""

import hashlib
import json
import os
import sys
import threading
import time
import urllib.request
from urllib.parse import urlencode

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
    start = time.process_time()
    digest = digest_for(rounds)
    cpu = time.process_time() - start
    payload = {
        "run_id": run_id,
        "index": index,
        "pid": os.getpid(),
        "rounds": rounds,
        "cpu_seconds": cpu,
        "result_digest": digest,
    }
    write_json(os.path.join(out_dir, "cpu-%s-w%d.json" % (run_id, index)), payload)
    trace("worker %d written cpu=%.3f" % (index, cpu))
    print("WORKER %d pid=%d cpu=%.3f" % (index, payload["pid"], cpu))
    return 0


def launch(base_url, app, arguments):
    query = urlencode({"app": app, "args": arguments})
    with urllib.request.urlopen(base_url + "/api/launch?" + query, timeout=30) as r:
        return json.loads(r.read().decode())


def status(base_url):
    with urllib.request.urlopen(base_url + "/api/status", timeout=30) as r:
        return json.loads(r.read().decode())


def wait_jobs(base_url, job_ids, deadline):
    finished = {}
    polls = 0
    while time.time() < deadline and len(finished) < len(job_ids):
        polls += 1
        for item in status(base_url).get("jobs", []):
            if item.get("job_id") in job_ids and item.get("finished"):
                finished[item["job_id"]] = item
        if polls % 10 == 0:
            trace("poll %d done=%d/%d" % (polls, len(finished), len(job_ids)))
        if len(finished) < len(job_ids):
            time.sleep(0.2)
    return finished


def aggregate(out_dir, run_id, workers, rounds, base_url, app, tested_sha, timeout):
    trace("aggregate start workers=%d rounds=%d base=%s" % (workers, rounds, base_url))
    expected_digest = digest_for(rounds)
    for index in range(workers):
        path = os.path.join(out_dir, "cpu-%s-w%d.json" % (run_id, index))
        try:
            os.unlink(path)
        except OSError:
            pass

    stop = threading.Event()
    mem = []
    sampler = threading.Thread(target=sample_memory, args=(stop, mem), daemon=True)
    sampler.start()

    wall_start = time.monotonic()
    jobs = []
    for index in range(workers):
        arguments = (
            "--cpu-worker /data/ps5-git/tests/cpu_report.py"
            " --run-id %s --index %d --rounds %d --out-dir %s"
            % (run_id, index, rounds, out_dir)
        )
        trace("launching worker %d" % index)
        response = launch(base_url, app, arguments)
        trace("launched worker %d job=%s" % (index, response.get("job_id")))
        jobs.append(response.get("job_id"))
    finished = wait_jobs(base_url, jobs, time.monotonic() + timeout)
    wall_seconds = time.monotonic() - wall_start
    trace("all jobs done=%d wall=%.3f" % (len(finished), wall_seconds))

    stop.set()
    sampler.join(timeout=2)

    results = []
    failures = []
    for index in range(workers):
        path = os.path.join(out_dir, "cpu-%s-w%d.json" % (run_id, index))
        try:
            with open(path, "r", encoding="utf-8") as f:
                results.append(json.load(f))
        except OSError:
            failures.append("worker %d wrote no result" % index)

    pids = [r.get("pid") for r in results]
    if len(results) != workers:
        failures.append("only %d of %d workers reported" % (len(results), workers))
    if len(set(pids)) != len(pids):
        failures.append("worker pids are not distinct")
    if any(r.get("result_digest") != expected_digest for r in results):
        failures.append("a worker digest does not match the expected digest")
    for job_id, item in finished.items():
        if item.get("exit_code") != 0:
            failures.append("job %s exited %s" % (job_id, item.get("exit_code")))
    if len(finished) != len(jobs):
        failures.append("a worker job did not finish")

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
        "wall_seconds": wall_seconds,
        "expected_digest": expected_digest,
        "workers": results,
        "jobs": finished,
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
            value("--base-url", "http://127.0.0.1:8090"),
            value("--app", "ps5git"),
            value("--tested-sha", "unknown"),
            float(value("--timeout", 900)),
        )
    print("usage: cpu_report.py --index N | --aggregate [--workers N] [--rounds N]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
