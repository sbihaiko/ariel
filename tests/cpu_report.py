"""A CPU test for the console, run by the console.

The point is to measure the PS5's processors, not to assert them: the parent
records one enclosing monotonic interval, and every child reports its own CPU
time, PID, exit status and result digest. The workers are explicit forks with a
pipe; nothing here starts a process through subprocess or exec.
"""

import hashlib
import json
import os
import random
import sys
import threading
import time

BUFFER = b"ps5-cpu-report/" * 6553  # ~1 MiB
ROUNDS = 8192  # ~8 GiB of hashing per worker
SAMPLES = []


def worker(write_fd: int, rounds: int) -> None:
    start = time.process_time()
    digest = hashlib.sha256()
    for i in range(rounds):
        digest.update(BUFFER)
        digest.update(i.to_bytes(4, "little"))
    cpu = time.process_time() - start
    payload = {
        "pid": os.getpid(),
        "cpu_seconds": cpu,
        "result_digest": digest.hexdigest(),
    }
    os.write(write_fd, (json.dumps(payload) + "\n").encode())
    os.close(write_fd)
    os._exit(0)


def sample_memory(stop, out):
    path = "/proc/meminfo"
    while not stop.is_set():
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        out.append(int(line.split()[1]))
                        break
        except OSError:
            out.append(None)
        stop.wait(1.0)


def read_all(fd):
    chunks = []
    while True:
        data = os.read(fd, 4096)
        if not data:
            break
        chunks.append(data)
    os.close(fd)
    return b"".join(chunks)


def main(argv):
    tested_sha = "unknown"
    if "--tested-sha" in argv:
        tested_sha = argv[argv.index("--tested-sha") + 1]
    workers = 2
    if "--workers" in argv:
        workers = int(argv[argv.index("--workers") + 1])

    rounds = ROUNDS
    if "--rounds" in argv:
        rounds = int(argv[argv.index("--rounds") + 1])

    run_id = "%s-%s-%06x" % (
        time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        tested_sha[:8],
        random.randrange(1 << 24),
    )
    if "--run-id" in argv:
        run_id = argv[argv.index("--run-id") + 1]
    out_dir = "/data/ps5-git/results"
    if "--out-dir" in argv:
        out_dir = argv[argv.index("--out-dir") + 1]

    stop = threading.Event()
    mem = []
    sampler = threading.Thread(target=sample_memory, args=(stop, mem), daemon=True)

    expected = hashlib.sha256()
    for i in range(rounds):
        expected.update(BUFFER)
        expected.update(i.to_bytes(4, "little"))
    expected_digest = expected.hexdigest()

    wall_start = time.monotonic()
    children = []
    for index in range(workers):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            worker(write_fd, rounds)
        os.close(write_fd)
        children.append((pid, read_fd))

    sampler.start()
    results = []
    statuses = []
    for pid, read_fd in children:
        data = read_all(read_fd)
        _, status = os.waitpid(pid, 0)
        statuses.append({"pid": pid, "exit_code": os.waitstatus_to_exitcode(status)})
        if data:
            result = json.loads(data.decode().strip())
            result["exit_code"] = os.waitstatus_to_exitcode(status)
            results.append(result)

    wall_seconds = time.monotonic() - wall_start
    stop.set()
    sampler.join(timeout=2)

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
        "wall_seconds": wall_seconds,
        "rounds": rounds,
        "expected_digest": expected_digest,
        "workers": results,
        "statuses": statuses,
        "memory": memory,
    }

    try:
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "cpu-%s.json" % run_id)
    except OSError:
        out_path = "cpu-%s.json" % run_id
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
