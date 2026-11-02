"""Drive the end-to-end run: clone, CPU workers, publish.

Every job is launched from here. The console never launches another job,
never forks and never creates a thread (ADR-0020), so the sequence is three
host steps: `--clone` records the tested SHA, one `--cpu-worker` job per
worker writes its result, and `--run` checks the report against the clone and
pushes the commit.
"""

import argparse
import json
import sys
import time
from urllib.parse import urlencode

import console

CLONE_STATE = "/data/ps5-git/state/clone.json"
RESULTS = "/data/ps5-git/results"


def launch(host, app, args):
    return console.get_json(host, f"/api/launch?{urlencode({'app': app, 'args': args})}")


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


def run_job(host, app, label, args, timeout):
    job = launch(host, app, args)
    job_id = job.get("job_id")
    print(f"{label} job {job_id}")
    done = wait_all(host, [job_id], timeout)
    if not done:
        raise SystemExit(f"{label} did not finish")
    item = done[job_id]
    print(f"{label} exit={item.get('exit_code')}")
    if item.get("exit_code") != 0:
        raise SystemExit(f"{label} failed")
    return item


def fetch_json(host, remote):
    conn = console.ftp(host)
    chunks = []
    try:
        conn.retrbinary(f"RETR {remote}", chunks.append)
    finally:
        conn.quit()
    return json.loads(b"".join(chunks).decode())


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=console.DEFAULT_HOST)
    p.add_argument("--app", default="ps5git")
    p.add_argument("--run-id", required=True)
    p.add_argument("--workers", default="2")
    p.add_argument("--rounds", default=None)
    p.add_argument("--timeout", type=float, default=600)
    args = p.parse_args(argv)

    run_job(args.host, args.app, "clone", "--clone", args.timeout)
    clone = fetch_json(args.host, CLONE_STATE)
    tested = clone["tested"]
    repo_dir = clone["dir"]
    print(f"tested {tested[:8]} at {repo_dir}")

    # The workers run the state copy, which is byte-identical to the clone's;
    # `--run` refuses a report whose test_sha256 does not match the clone, so
    # the evidence still belongs to the tested tree.
    test_path = "/data/ps5-git/tests/cpu_report.py"
    common = f"--run-id {args.run_id} --workers {args.workers} --out-dir {RESULTS} --tested-sha {tested}"
    if args.rounds:
        common += f" --rounds {args.rounds}"

    jobs = []
    for index in range(int(args.workers)):
        job = launch(args.host, args.app, f"--cpu-worker {test_path} {common} --index {index}")
        jobs.append(job.get("job_id"))
        print(f"worker {index} job {job.get('job_id')}")
    done = wait_all(args.host, jobs, args.timeout)
    if len(done) != len(jobs) or any(i.get("exit_code") != 0 for i in done.values()):
        raise SystemExit("CPU FAIL a worker job failed")
    print("workers done")

    run_job(args.host, args.app, "publish", f"--run --run-id {args.run_id}", args.timeout)
    print(f"E2E submitted run {args.run_id} tested {tested}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
