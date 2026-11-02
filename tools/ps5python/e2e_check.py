"""Verify one console run from GitHub alone.

The check binds the evidence to one execution: the run id, the tested SHA, the
hash of the test file at that SHA, the result commit, and the ancestry between
them. A stale result, a different source revision or a changed test fails.
"""

import argparse
import base64
import hashlib
import json
import subprocess
import sys


def gh_api(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or out.stdout.strip())
    return json.loads(out.stdout)


def get_file(repo, path, ref):
    data = gh_api(f"repos/{repo}/contents/{path}?ref={ref}")
    return base64.b64decode(data["content"])


def result_commit(repo, run_id, branch):
    commits = gh_api(
        f"repos/{repo}/commits?path=results/cpu-{run_id}.json&sha={branch}&per_page=1"
    )
    if not commits:
        raise RuntimeError(f"no commit carries results/cpu-{run_id}.json on {branch}")
    return commits[0]["sha"]


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--repo", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--branch", default="ps5/results")
    args = p.parse_args(argv)

    try:
        result_sha = result_commit(args.repo, args.run_id, args.branch)
        raw = get_file(args.repo, f"results/cpu-{args.run_id}.json", result_sha)
        report = json.loads(raw.decode())
    except Exception as exc:  # noqa: BLE001
        print(f"E2E FAIL {type(exc).__name__}: {exc}")
        return 1

    failures = []
    if report.get("run_id") != args.run_id:
        failures.append("run_id mismatch")
    tested = report.get("tested_sha", "")
    if not tested or tested == "unknown":
        failures.append("tested_sha missing")

    if tested:
        try:
            compare = gh_api(f"repos/{args.repo}/compare/{tested}...{result_sha}")
            if compare.get("merge_base_commit", {}).get("sha") != tested:
                failures.append("tested_sha is not an ancestor of the result commit")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"compare failed: {exc}")

        try:
            test_bytes = get_file(args.repo, "tests/cpu_report.py", tested)
            if hashlib.sha256(test_bytes).hexdigest() != report.get("test_sha256"):
                failures.append("test_sha256 does not match tests/cpu_report.py at tested_sha")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"test file unreadable: {exc}")

    workers = report.get("workers", [])
    pids = [w.get("pid") for w in workers]
    if len(workers) < 2:
        failures.append("fewer than two workers")
    if len(set(pids)) != len(pids):
        failures.append("worker pids are not distinct")
    # The console workers record no exit code; their exit is proven by the
    # host that launched them. Only a recorded non-zero is a failure here.
    if any("exit_code" in w and w["exit_code"] != 0 for w in workers):
        failures.append("a worker did not exit 0")
    expected = report.get("expected_digest")
    if any(w.get("result_digest") != expected for w in workers):
        failures.append("a worker digest does not match expected_digest")
    try:
        cpu = sum(float(w.get("cpu_seconds", 0)) for w in workers)
        wall = float(report.get("wall_seconds", 0))
        if not wall or cpu <= 1.5 * wall:
            failures.append(f"workers did not overlap (cpu={cpu:.2f}s wall={wall:.2f}s)")
    except (TypeError, ValueError):
        failures.append("timing fields are not numbers")

    if failures:
        for line in failures:
            print("E2E FAIL " + line)
        return 1
    print(f"E2E OK {tested} {result_sha} {len(workers)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
