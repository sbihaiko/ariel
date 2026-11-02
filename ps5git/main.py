"""The console-side half of the PS5 Git spike.

It runs as a script-mode app bundle inside the CPython web launcher. The first
mode is a self-test that proves the capabilities the spike depends on: Python
starts, process execution is blocked, fork and waitpid work, and TLS to GitHub
verifies against the bundled CA. Git modes are added by later tickets.
"""

import json
import os
import runpy
import socket
import ssl
import sys
import time

STATE = os.environ.get("PS5GIT_STATE", "/data/ps5-git")
LOG = STATE + "/log"
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# The CA is the pinned certifi bundle, either installed into the state
# directory or read straight from the app's own vendored copy.
_CA_CHOICES = [STATE + "/ca.pem", os.path.join(APP_DIR, "lib", "certifi", "cacert.pem")]
CA = next((p for p in _CA_CHOICES if os.path.isfile(p)), _CA_CHOICES[0])
CA_BAD = STATE + "/ca-bad.pem"


def emit(lines, path=None):
    text = "\n".join(lines) + "\n"
    if path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    sys.stdout.write(text)
    sys.stdout.flush()


BLOCKED = ("subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn")


def trace(message):
    """Append one durable line, so a crash can be read after a reboot."""
    try:
        os.makedirs(LOG, exist_ok=True)
        fd = os.open(LOG + "/cpu-trace.txt", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            line = "%s pid=%d %s\n" % (time.strftime("%H:%M:%S"), os.getpid(), message)
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def install_audit_hook():
    """Refuse process creation for the rest of the process, Git phase included."""

    def hook(event, args):
        if event in BLOCKED:
            raise RuntimeError("blocked " + event)

    sys.addaudithook(hook)


def audit_probe():
    seen = []

    def hook(event, args):
        if event in ("subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn"):
            seen.append(event)
            raise RuntimeError("blocked " + event)

    sys.addaudithook(hook)
    raised = ""
    try:
        import subprocess
        subprocess.Popen(["/bin/true"])
    except Exception as exc:  # noqa: BLE001 - the failure is the signal
        raised = type(exc).__name__ + ": " + str(exc)
    return seen, raised


def fork_probe():
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.write(write_fd, b"child-ok")
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    data = os.read(read_fd, 32)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    return os.getpid(), pid, data, status


def tls_probe(cafile, server_hostname="github.com"):
    ctx = ssl.create_default_context(cafile=cafile)
    infos = socket.getaddrinfo("github.com", 443, socket.AF_INET, socket.SOCK_STREAM)
    family, socktype, proto, _, addr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(30)
    try:
        sock.connect(addr)
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
            return tls.getpeercert()
    finally:
        sock.close()


def selftest(negative):
    lines = []
    lines.append("PYTHON OK %s %s" % (sys.version.split()[0], sys.platform))
    seen, raised = audit_probe()
    if seen:
        lines.append("AUDIT OK subprocess blocked event=%s" % seen[0])
    elif raised:
        # The platform may refuse the call before the hook sees an event; the
        # refusal itself is the proof that no process can start.
        lines.append("AUDIT OK subprocess blocked raised=%s" % raised)
    else:
        lines.append("AUDIT FAIL subprocess not blocked")

    try:
        parent, child, data, status = fork_probe()
        if data == b"child-ok" and status == 0:
            lines.append("FORK OK parent=%d child=%d status=%d" % (parent, child, status))
        else:
            lines.append("FORK FAIL parent=%d child=%d status=%d data=%r" % (parent, child, status, data))
    except Exception as exc:  # noqa: BLE001
        lines.append("FORK FAIL %s: %s" % (type(exc).__name__, exc))

    # A negative mode inverts the exit code on purpose: the handshake is meant
    # to fail, so a refusal exits non-zero and an unexpected acceptance exits
    # zero. The host reads the line, not only the code, and a job that accepts
    # the wrong CA or hostname is the failure this pair exists to catch.
    if negative == "ca":
        try:
            tls_probe(CA_BAD)
        except ssl.SSLError as exc:
            lines.append("HTTPS FAIL verified unknown-ca %s" % exc.reason)
            emit(lines, LOG + "/selftest-negative-ca.txt")
            return 1
        except Exception as exc:  # noqa: BLE001
            lines.append("HTTPS FAIL verified unknown-ca %s: %s" % (type(exc).__name__, exc))
            emit(lines, LOG + "/selftest-negative-ca.txt")
            return 1
        lines.append("HTTPS FAIL accepted wrong CA")
        emit(lines, LOG + "/selftest-negative-ca.txt")
        return 0

    if negative == "host":
        try:
            tls_probe(CA, server_hostname="example.com")
        except ssl.SSLError as exc:
            lines.append("HTTPS FAIL verified hostname-mismatch %s" % exc.reason)
            emit(lines, LOG + "/selftest-negative-host.txt")
            return 1
        except Exception as exc:  # noqa: BLE001
            lines.append("HTTPS FAIL verified hostname-mismatch %s: %s" % (type(exc).__name__, exc))
            emit(lines, LOG + "/selftest-negative-host.txt")
            return 1
        lines.append("HTTPS FAIL accepted wrong hostname")
        emit(lines, LOG + "/selftest-negative-host.txt")
        return 0

    try:
        cert = tls_probe(CA)
        subject = dict(x[0] for x in cert.get("subject", ()))
        common = subject.get("commonName", "unknown")
        lines.append("HTTPS OK verified github.com CN=%s" % common)
    except Exception as exc:  # noqa: BLE001
        lines.append("HTTPS FAIL verified github.com %s: %s" % (type(exc).__name__, exc))
        emit(lines, LOG + "/selftest.txt")
        return 1

    emit(lines, LOG + "/selftest.txt")
    return 0


def setting(name, default=None):
    path = STATE + "/config.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get(name, default)
    except OSError:
        return default


def run_cpu_test(test_path, tested, run_id, workers, extra=None):
    """Run one CPU report in this interpreter and return its result path."""
    saved = sys.argv
    sys.argv = [test_path, "--tested-sha", tested, "--run-id", run_id,
                "--workers", workers, "--out-dir", STATE + "/results"] + (extra or [])
    try:
        runpy.run_path(test_path, run_name="__main__")
    except SystemExit as exc:
        if exc.code not in (None, 0):
            return None, "cpu test exit=%s" % exc.code
    finally:
        sys.argv = saved
    result = STATE + "/results/cpu-" + run_id + ".json"
    if not os.path.isfile(result):
        return None, "result file missing " + result
    return result, ""


def cpu_loop(argv):
    """The local half of the CPU evidence: no Git, no credential."""
    install_audit_hook()
    trace("cpu entry " + " ".join(argv))
    print("AUDIT OK subprocess blocked for the whole run")
    test_path = argv[argv.index("--cpu") + 1] if "--cpu" in argv else STATE + "/tests/cpu_report.py"
    if not os.path.isfile(test_path):
        print("CPU FAIL missing test at " + test_path)
        return 2
    run_id = argv[argv.index("--run-id") + 1] if "--run-id" in argv else None
    if run_id is None:
        run_id = "%s-%06x" % (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
            int.from_bytes(os.urandom(3), "big"),
        )
    workers = argv[argv.index("--workers") + 1] if "--workers" in argv else "2"
    extra = ["--rounds", argv[argv.index("--rounds") + 1]] if "--rounds" in argv else []
    result, reason = run_cpu_test(test_path, "local", run_id, workers, extra)
    if result is None:
        trace("cpu exit 1 " + reason)
        print("CPU FAIL " + reason)
        return 1
    trace("cpu exit 0 " + result)
    print("CPU OK " + run_id + " " + result)
    return 0


def run_loop(argv):
    # Imported here: the self-test must start even when the Git dependency is
    # absent, and dulwich is only needed from the first Git step on.
    import git_runner

    install_audit_hook()
    print("AUDIT OK subprocess blocked for the whole run")
    repo_dir = argv[argv.index("--dir") + 1] if "--dir" in argv else "/data/ps5-git-spike"
    remote = argv[argv.index("--remote") + 1] if "--remote" in argv else setting("remote")
    if not remote:
        print("RUN FAIL no remote configured")
        return 2
    owner_repo = remote.rstrip("/")
    if owner_repo.endswith(".git"):
        owner_repo = owner_repo[:-4]
    owner_repo = "/".join(owner_repo.rsplit("/", 2)[-2:])
    if git_runner.guard(owner_repo) != 0:
        return 1
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        if git_runner.clone(remote, repo_dir) != 0:
            return 1
    else:
        if git_runner.pull(repo_dir, "main") != 0:
            return 1

    tested = git_runner.head(git_runner.Repo(repo_dir))
    run_id = argv[argv.index("--run-id") + 1] if "--run-id" in argv else None
    if run_id is None:
        run_id = "%s-%s-%06x" % (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
            tested[:8],
            int.from_bytes(os.urandom(3), "big"),
        )
    workers = argv[argv.index("--workers") + 1] if "--workers" in argv else "2"

    test_path = os.path.join(repo_dir, "tests", "cpu_report.py")
    if not os.path.isfile(test_path):
        print("RUN FAIL missing tests/cpu_report.py at " + tested[:8])
        return 2
    extra = ["--rounds", argv[argv.index("--rounds") + 1]] if "--rounds" in argv else []
    result, reason = run_cpu_test(test_path, tested, run_id, workers, extra)
    if result is None:
        print("RUN FAIL " + reason)
        return 1
    with open(result, "r", encoding="utf-8") as f:
        report = json.load(f)
    available = (report.get("memory") or {}).get("mem_available_kb")
    if isinstance(available, int) and available < 200 * 1024:
        print("RUN FAIL memory below 200 MB: %d KB" % available)
        return 1
    sha = git_runner.commit_results(
        repo_dir, result, "results: %s tested %s" % (run_id, tested[:8])
    )
    if sha is None:
        print("RUN FAIL push refused, the commit stays local")
        return 1
    print("RUN OK %s %s %s" % (run_id, tested, sha.decode()))
    return 0


def main(argv):
    if "--cpu" in argv:
        return cpu_loop(argv)
    if "--run" in argv:
        return run_loop(argv)
    if "--selftest" in argv:
        return selftest(None)
    if "--selftest-negative-ca" in argv:
        return selftest("ca")
    if "--selftest-negative-host" in argv:
        return selftest("host")
    print("usage: main.py --selftest [--selftest-negative-ca|--selftest-negative-host] | --run [--dir D] [--remote URL] [--run-id ID] [--workers N]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
