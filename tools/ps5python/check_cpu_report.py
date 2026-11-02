"""The guard for ADR-0020, run on the host.

The CPU test may not fork and may not reach the launcher's API: both have taken
this console down (#153). This reads the test as source first, then runs it on
the host once to prove the report it produces is well formed.

    python3 tools/ps5python/check_cpu_report.py
"""

import ast
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST = os.path.join(ROOT, "tests", "cpu_report.py")
FORBIDDEN_CALLS = {"fork", "forkpty", "posix_spawn", "posix_spawnp", "spawnv", "spawnl"}
FORBIDDEN_MODULES = {"subprocess", "urllib", "http", "socketserver", "threading", "_thread"}


def check_source(source):
    failures = []
    tree = ast.parse(source, TEST)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    failures.append("imports %s" % alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in FORBIDDEN_MODULES:
                failures.append("imports from %s" % node.module)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in FORBIDDEN_CALLS:
                failures.append("calls .%s()" % func.attr)
    return failures


def run_once():
    """Two worker processes, as the console runs them: index 0 aggregates."""
    with tempfile.TemporaryDirectory() as out:
        env = dict(os.environ)
        env["PS5GIT_TRACE"] = os.path.join(out, "trace.txt")
        procs = {}
        for index in (1, 0):
            procs[index] = subprocess.Popen(
                [sys.executable, TEST, "--run-id", "guard", "--workers", "2",
                 "--rounds", "1024", "--index", str(index), "--out-dir", out],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        for index, proc in procs.items():
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                return ["worker %d exited %d: %s" % (index, proc.returncode, stderr.strip()[-300:])]
        with open(os.path.join(out, "cpu-guard.json"), "r", encoding="utf-8") as f:
            report = json.load(f)
    failures = list(report.get("failures") or [])
    if report.get("status") != "ok":
        failures.append("report status is %r" % report.get("status"))
    ids = [w.get("pid") for w in report.get("workers", [])]
    if len(ids) < 2 or len(set(ids)) != len(ids):
        failures.append("worker pids are not distinct")
    return failures


def main():
    with open(TEST, "r", encoding="utf-8") as f:
        failures = check_source(f.read())
    if failures:
        for line in failures:
            print("GUARD FAIL cpu_report " + line)
        return 1
    failures = run_once()
    if failures:
        for line in failures:
            print("GUARD FAIL cpu_report " + line)
        return 1
    print("GUARD OK cpu_report no fork, no thread, no launcher API, report is sound")
    return 0


if __name__ == "__main__":
    sys.exit(main())
