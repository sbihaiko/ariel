"""Run the console self-test through the launcher and judge its output.

The launcher starts the app as a job and reports its exit code; the log cursor
carries the lines the self-test prints. Both are required: a line without the
job's own exit code proves nothing, and an exit code without the line proves
nothing either.
"""

import argparse
import sys
import time
from urllib.parse import urlencode

import console

REQUIRED = (
    "PYTHON OK 3.14.7 ps5",
    "AUDIT OK subprocess blocked",
    "FORK OK parent=",
    "HTTPS OK verified github.com",
)
NEGATIVE = (
    ("--selftest-negative-ca", "HTTPS FAIL verified unknown-ca", "selftest-negative-ca.txt"),
    ("--selftest-negative-host", "HTTPS FAIL verified hostname-mismatch", "selftest-negative-host.txt"),
)


def launch_and_wait(host, app, args, timeout=120):
    _, since = console.logs(host, 0)
    query = urlencode({"app": app, "args": args})
    job = console.get_json(host, f"/api/launch?{query}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = console.get_json(host, "/api/status")
        for item in status.get("jobs", []):
            if item.get("job_id") == job.get("job_id") and item.get("finished"):
                data, _ = console.logs(host, since)
                return item, data
        time.sleep(1)
    return None, ""


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=console.DEFAULT_HOST)
    p.add_argument("--app", default="ps5-git")
    args = p.parse_args(argv)

    failures = []
    job, logs = launch_and_wait(args.host, args.app, "--selftest")
    if job is None:
        print("SELFTEST FAIL job did not finish")
        return 1
    print(f"SELFTEST job={job.get('job_id')} pid={job.get('app_pid')} exit={job.get('exit_code')}")
    if job.get("app_pid") in (None, 0):
        failures.append("the job carries no pid")
    if job.get("exit_code") != 0:
        failures.append(f"self-test exit {job.get('exit_code')}")
    for line in REQUIRED:
        if line not in logs:
            failures.append("missing line: " + line)

    for mode, expected, name in NEGATIVE:
        njob, nlogs = launch_and_wait(args.host, args.app, mode)
        if njob is None:
            failures.append(f"{mode}: job did not finish")
            continue
        if expected not in nlogs:
            failures.append(f"{mode}: missing line: {expected}")
        if njob.get("exit_code") == 0:
            failures.append(f"{mode}: exit 0, expected non-zero")
        print(f"SELFTEST {mode} exit={njob.get('exit_code')} log={name}")

    if failures:
        for line in failures:
            print("SELFTEST FAIL " + line)
        return 1
    print("SELFTEST OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
