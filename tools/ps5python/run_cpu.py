"""Run the CPU test on the console and fetch its result.

The host launches one worker job per core the test may use, waits for all of
them, then launches the aggregator job, which reads the workers' JSONs and
writes the run's report. Nothing on the console launches anything, and nothing
forks: both are ways this console's kernel goes down (issue #153). The report
is read back over ftpsrv.
"""

import argparse
import json
import sys
import time
from urllib.parse import urlencode

import console

TEST = "/data/ps5-git/tests/cpu_report.py"
OUT = "/data/ps5-git/results"


def launch(host, app, args):
    query = urlencode({"app": app, "args": args})
    return console.get_json(host, f"/api/launch?{query}")


def wait_all(host, job_ids, timeout):
    done = {}
    deadline = time.time() + timeout
    while time.time() < deadline and len(done) < len(job_ids):
        status = console.get_json(host, "/api/status")
        for item in status.get("jobs", []):
            if item.get("job_id") in job_ids and item.get("finished"):
                done[item["job_id"]] = item
        if len(done) < len(job_ids):
            time.sleep(0.5)
    return done


def fetch(host, remote):
    conn = console.ftp(host)
    chunks = []
    try:
        conn.retrbinary(f"RETR {remote}", chunks.append)
    finally:
        conn.quit()
    return b"".join(chunks)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=console.DEFAULT_HOST)
    p.add_argument("--app", default="ps5git")
    p.add_argument("--run-id", required=True)
    p.add_argument("--workers", default="2")
    p.add_argument("--rounds", default=None)
    p.add_argument("--timeout", type=float, default=900)
    p.add_argument("--out", default="-")
    args = p.parse_args(argv)

    count = int(args.workers)
    extra = f"--run-id {args.run_id} --workers {count}"
    if args.rounds:
        extra += f" --rounds {args.rounds}"
    job = launch(args.host, args.app, f"--cpu {TEST} {extra}")
    print(f"job {job.get('job_id')}")
    done = wait_all(args.host, [job.get("job_id")], args.timeout)
    if not done:
        print("CPU FAIL the job did not finish")
        return 1
    item = done[job.get("job_id")]
    print(f"CPU exit={item.get('exit_code')} pid={item.get('app_pid')}")
    if item.get("exit_code") != 0:
        return 1

    raw = fetch(args.host, f"{OUT}/cpu-{args.run_id}.json")
    report = json.loads(raw.decode())
    workers = report.get("workers", [])
    ids = {w.get("thread_id") for w in workers}
    cpu = float(report.get("cpu_seconds_total", 0))
    wall = float(report.get("wall_seconds", 0) or 0)
    print(f"cpu_count={report.get('cpu_count')} workers={len(workers)} threads={len(ids)}"
          f" cpu={cpu:.2f}s wall={wall:.2f}s ratio={report.get('cpu_wall_ratio', 0):.2f}")

    failures = list(report.get("failures") or [])
    if len(workers) < 2:
        failures.append("fewer than two workers")
    if len(ids) != len(workers):
        failures.append("worker thread ids are not distinct")
    if any(w.get("result_digest") != report.get("expected_digest") for w in workers):
        failures.append("a digest does not match expected_digest")
    if report.get("status") != "ok":
        failures.append("report status is %r" % report.get("status"))

    if args.out != "-":
        with open(args.out, "wb") as f:
            f.write(raw)
    if failures:
        for line in failures:
            print("CPU FAIL " + line)
        return 1
    print("CPU OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
