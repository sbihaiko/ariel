"""Run the CPU test on the console and fetch its result.

The launcher starts the app job, the job writes its JSON under the console
state directory, and this reads that file back over ftpsrv. The run id is
chosen here so the fetched file is unambiguous.
"""

import argparse
import json
import sys
import time
from urllib.parse import urlencode

import console


def launch(host, app, args):
    query = urlencode({"app": app, "args": args})
    return console.get_json(host, f"/api/launch?{query}")


def wait(host, job_id, timeout):
    pid = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = console.get_json(host, "/api/status")
        for item in status.get("jobs", []):
            if item.get("job_id") != job_id:
                continue
            pid = item.get("app_pid") or pid
            if item.get("finished"):
                item["app_pid"] = item.get("app_pid") or pid
                return item
        time.sleep(0.5)
    return None


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

    extra = f"--run-id {args.run_id} --workers {args.workers}"
    if args.rounds:
        extra += f" --rounds {args.rounds}"
    job = launch(args.host, args.app, f"--cpu /data/ps5-git/tests/cpu_report.py {extra}")
    print(f"job {job.get('job_id')}")
    done = wait(args.host, job.get("job_id"), args.timeout)
    if done is None:
        print("CPU FAIL the job did not finish")
        return 1
    print(f"CPU exit={done.get('exit_code')} pid={done.get('app_pid')}")
    if done.get("exit_code") != 0:
        return 1

    raw = fetch(args.host, f"/data/ps5-git/results/cpu-{args.run_id}.json")
    report = json.loads(raw.decode())
    workers = report.get("workers", [])
    pids = {w.get("pid") for w in workers}
    cpu = sum(float(w.get("cpu_seconds", 0)) for w in workers)
    wall = float(report.get("wall_seconds", 0) or 0)
    print(f"cpu_count={report.get('cpu_count')} workers={len(workers)} pids={len(pids)}"
          f" cpu={cpu:.2f}s wall={wall:.2f}s ratio={(cpu / wall) if wall else 0:.2f}")

    failures = list(report.get("failures") or [])
    if len(workers) < 2:
        failures.append("fewer than two workers")
    if len(pids) != len(workers):
        failures.append("worker pids are not distinct")
    if any(w.get("result_digest") != report.get("expected_digest") for w in workers):
        failures.append("a digest does not match expected_digest")
    if not wall or cpu <= 1.5 * wall:
        failures.append("workers did not overlap")
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
