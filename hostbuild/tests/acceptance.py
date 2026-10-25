#!/usr/bin/env python3
"""Headless acceptance harness for the Ariel agent port.

Starts the host build of Ariel in a temporary root, reads the access token
from its standard output and drives the server only through the agent port.
Requests for approval reach the virtual controller on the server's standard
input, and its prompt and acknowledgements arrive on standard output.

The suite creates the temporary root it runs under. It also writes to a
staged object from outside, as the ungated telnet shell can in Stage 1, and
it reads the store back to check what a commit promised: the name's current
record and the object the new build replaced. Those facts have no reply of
their own until payload run arrives.
"""

import contextlib
import datetime
import hashlib
import http.server
import io
import json
import os
import platform
import queue
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

HOST = "127.0.0.1"
TOKEN_LINE = re.compile(r"^token ([0-9a-f]{32})$")
STAGED_LINE = re.compile(r"^staged (s-[0-9a-f]+)$")
APPROVAL_LINE = re.compile(r"^approval_required (a-[0-9a-f]+)$")
PROMPT_LINE = re.compile(
    r"^prompt (a-[0-9a-f]+) payload (\S+) \((\d+) bytes, sha256 ([0-9a-f]{64})\)"
    r" will run$"
)
CLOCK_LINE = re.compile(r"^clock (\d+)$")

# The store's expiry runs on the clock in a waiter of its own, so every
# settle counts it beside the connections a scenario holds.
EXPIRY_WAITERS = 1

# The server reads a closing connection for this long (agent_close).
CLOSE_DRAIN_MS = 200

results = []


def check(name, fn):
    try:
        fn()
    except Exception as err:  # noqa: BLE001 - a failed scenario is a report
        results.append((name, False, "%s: %s" % (type(err).__name__, err)))
        print("FAIL %s: %s: %s" % (name, type(err).__name__, err))
    else:
        results.append((name, True, ""))
        print("PASS %s" % name)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


class Server:
    """The host build of Ariel, started against a temporary root."""

    def __init__(self, binary, env=None, setup=None):
        self.binary = binary
        self.env = env
        self.root = tempfile.mkdtemp(prefix="ariel-host-", dir=os.path.realpath("/tmp"))
        self.token = None
        if setup is not None:
            setup(self.root)
        self._start()

    def _spawn(self):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [self.binary, "--port", str(self.port), "--root", self.root],
            env=dict(os.environ, **(self.env or {})),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.lines = queue.Queue()
        self.reader = threading.Thread(
            target=self._pump, args=(self.proc, self.lines), daemon=True)
        self.reader.start()

    def start_until_exit(self, env=None):
        """Start Ariel with env and return its exit status once it has ended.

        Ariel that cannot recover its store ends before it prints a token, so
        this waits for the exit instead of reading one.
        """
        self.env = env
        self._spawn()
        try:
            return self.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.stop()
            raise AssertionError("Ariel started instead of ending on its own")

    def _start(self):
        self._spawn()
        try:
            token = self._read_token()
        except Exception:
            self.stop()
            raise
        if self.token is None:
            self.token = token
        else:
            assert token == self.token, "the token must survive a restart"

    def restart(self):
        """Stop Ariel and start it again against the same root."""
        self.stop()
        self._start()

    def _pump(self, proc, lines):
        for raw in proc.stdout:
            line = raw.decode("ascii", "replace").rstrip("\r\n")
            lines.put(line)
        lines.put(None)

    def next_line(self, timeout=5.0):
        """Return the next line the server printed, or None on timeout."""
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            return None
        assert line is not None, (
            "the server closed its standard output; its standard error: %r"
            % self.stderr_tail())
        return line

    def stderr_tail(self):
        """What Ariel wrote to standard error so far, without blocking: a
        payload it started may still hold the pipe open."""
        try:
            self.proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        fd = self.proc.stderr.fileno()
        os.set_blocking(fd, False)
        try:
            return (os.read(fd, 4096) or b"").decode("ascii", "replace")
        except OSError:
            return ""
        finally:
            os.set_blocking(fd, True)

    def assert_no_line(self, timeout=0.4):
        line = self.next_line(timeout=timeout)
        assert line is None, "expected no output, got %r" % line

    def _read_token(self):
        line = self.next_line(timeout=10.0)
        assert line is not None, "server printed no token line"
        match = TOKEN_LINE.match(line)
        assert match, "unexpected startup line %r" % line
        self.assert_no_line()
        return match.group(1)

    def connect(self, timeout=5.0):
        sock = socket.create_connection((HOST, self.port), timeout=timeout)
        sock.settimeout(timeout)
        return sock

    def advance(self, ms):
        """Advance the host test clock and wait for the server to confirm.

        Time moves only when this is called, so a deadline scenario runs
        without sleeping.
        """
        self.proc.stdin.write(("clock advance %d\n" % ms).encode("ascii"))
        self.proc.stdin.flush()
        line = self.next_line(timeout=5.0)
        match = CLOCK_LINE.match(line or "")
        assert match, "expected a clock confirmation, got %r" % line
        return int(match.group(1))

    def settle(self, connections):
        """Wait until the server has seen the clock and has nothing to do.

        Returns once the store's expiry and exactly this many connections
        are blocked with nothing to read, each past the latest advance. A
        scenario can then look at what that time did, without sleeping.
        """
        waiters = EXPIRY_WAITERS + connections
        self.proc.stdin.write(("clock settle %d\n" % waiters).encode("ascii"))
        self.proc.stdin.flush()
        line = self.next_line(timeout=5.0)
        assert line == "settled %d" % waiters, (
            "expected %d settled waiters, got %r" % (waiters, line))

    def fresh(self):
        """Move past every approval expiry and staging TTL: a clean table."""
        return self.advance(900_000)

    def controller(self, command, expected, timeout=5.0):
        """Drive the virtual controller and return its acknowledgement."""
        self.proc.stdin.write((command + "\n").encode("ascii"))
        self.proc.stdin.flush()
        line = self.next_line(timeout=timeout)
        assert line == expected, "expected %r, got %r" % (expected, line)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def read_reply(sock):
    """Read until the server closes the connection."""
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data.decode("ascii", "replace")
        data += chunk


def recv_busy(sock):
    """Read until the busy reply is complete; the server may keep the socket."""
    data = b""
    while not data.endswith(b"exit 82\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("ascii", "replace")


def assert_open(sock, what):
    """The server has neither answered on sock nor closed it."""
    timeout = sock.gettimeout()
    sock.setblocking(False)
    try:
        data = sock.recv(4096)
    except BlockingIOError:
        return
    finally:
        sock.settimeout(timeout)
    raise AssertionError("%s: the server %s" % (
        what, "answered %r" % data if data else "closed the connection"))


def reply_lines(reply):
    text = reply.replace("\r\n", "\n")
    return [line for line in text.split("\n") if line != ""]


def assert_exit_only(reply, status):
    lines = reply_lines(reply)
    expected = ["exit %d" % status]
    assert lines == expected, "expected %r, got %r" % (expected, lines)


def assert_unknown(reply):
    lines = reply_lines(reply)
    exits = [line for line in lines if line.startswith("exit ")]
    assert len(exits) == 1, "expected exactly one exit line, got %r" % lines
    assert lines[:-1] == ["unknown_command"], (
        "expected 'unknown_command' before the exit line, got %r" % lines
    )
    assert lines[-1] == exits[0], "the exit line must come last: %r" % lines
    status = int(exits[0].split()[1])
    assert status != 0, "unknown_command must exit nonzero, got %d" % status


def assert_gated(reply):
    """A command nothing implements is gated: the owner is asked (75), or busy (76)."""
    lines = reply_lines(reply)
    exits = [line for line in lines if line.startswith("exit ")]
    assert len(exits) == 1, "expected exactly one exit line, got %r" % lines
    assert lines[-1] == exits[0], "the exit line must come last: %r" % lines
    assert exits[0] in ("exit 75", "exit 76"), (
        "an unlisted command must exit 75 or 76, got %r" % lines)
    assert "unknown_command" not in lines, (
        "an unlisted command is gated, never unknown_command: %r" % lines)


def push(server, name, data, declared_size=None, declared_hash=None,
         fragments=None, timeout=5.0, throttle=True):
    """Send one payload push and return the lines the server answered.

    A push is normally spaced 10 s after the last notification on the test
    clock, as a real agent would be; a rate-limit scenario passes
    throttle=False.
    """
    size = len(data) if declared_size is None else declared_size
    if declared_hash is None:
        declared_hash = hashlib.sha256(data).hexdigest()
    if throttle:
        server.advance(10_000)
    sock = server.connect(timeout=timeout)
    if fragments is not None:
        # Each fragment leaves as its own segment, without waiting.
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        header = "auth %s\npayload push %s %d %s\n" % (
            server.token, name, size, declared_hash)
        sock.sendall(header.encode("ascii"))
        try:
            if fragments is None:
                sock.sendall(data)
            else:
                offset = 0
                for step in fragments:
                    sock.sendall(data[offset:offset + step])
                    offset += step
                sock.sendall(data[offset:])
            sock.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError):
            # A refusal such as staging_full can close the connection
            # before the client finishes sending the body. The reply may
            # still be waiting to be read.
            pass
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def assert_mismatch(server, lines):
    assert lines == ["upload_mismatch", "exit 81"], (
        "expected upload_mismatch and exit 81, got %r" % lines
    )
    server.assert_no_line()


def assert_staged(server, lines, name, data, timeout=5.0):
    """Check a matching push's reply and the prompt the owner would see."""
    assert len(lines) == 4, "expected four reply lines, got %r" % lines
    staged = STAGED_LINE.match(lines[0])
    assert staged, "expected 'staged <id>', got %r" % lines[0]
    approval = APPROVAL_LINE.match(lines[1])
    assert approval, "expected 'approval_required <id>', got %r" % lines[1]
    assert CHALLENGE_LINE.match(lines[2]), (
        "expected a challenge line, got %r" % lines[2])
    assert lines[3] == "exit 75", "expected exit 75, got %r" % lines[3]

    prompt = server.next_line(timeout=timeout)
    match = PROMPT_LINE.match(prompt or "")
    assert match, "expected an approval prompt, got %r" % prompt
    assert match.group(1) == approval.group(1), (
        "the prompt names %s but the reply names %s"
        % (match.group(1), approval.group(1))
    )
    assert match.group(2) == name, (
        "the prompt names %r, not %r" % (match.group(2), name)
    )
    assert int(match.group(3)) == len(data), (
        "the prompt says %s bytes, not %d" % (match.group(3), len(data))
    )
    assert match.group(4) == hashlib.sha256(data).hexdigest(), (
        "the prompt shows the wrong hash"
    )
    return staged.group(1), approval.group(1)


def decide_push(server, name, data, decision, fragments=None):
    """Push, check the prompt, then sign it, or deny it on the controller."""
    lines = push(server, name, data, fragments=fragments)
    _, approval = assert_staged(server, lines, name, data)
    if decision == "approve":
        sign_and_grant(server, approval, challenge_of(lines))
    else:
        server.controller("deny %s" % approval, "denied %s" % approval)
    return approval


def commit(server, staging_id):
    """Send one payload commit and return the lines the server answered."""
    sock = server.connect()
    try:
        sock.sendall(
            ("auth %s\npayload commit %s\n" % (server.token, staging_id))
            .encode("ascii")
        )
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def run_payload(server, name, args=()):
    """Send one payload run and return the lines the server answered."""
    command = "payload run --wait %s" % name
    if args:
        command += " " + " ".join(args)
    sock = server.connect()
    try:
        sock.sendall(
            ("auth %s\n%s\n" % (server.token, command)).encode("ascii")
        )
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def compile_payload(source, name="payload"):
    """Build a native payload with the host compiler and return its bytes."""
    workdir = tempfile.mkdtemp(prefix="ariel-payload-")
    path = os.path.join(workdir, name + ".c")
    with open(path, "w") as handle:
        handle.write(source)
    binary = os.path.join(workdir, name)
    subprocess.run(
        [os.environ.get("CC", "cc"), "-Wall", "-Werror", "-o", binary, path],
        check=True,
    )
    with open(binary, "rb") as handle:
        return handle.read()


HELLO_SOURCE = """
#include <stdio.h>

int
main(int argc, char* argv[]) {
  printf("Hello, world from Ariel!\\n");
  for(int i = 1; i < argc; i++) {
    printf("argv[%d] = %s\\n", i, argv[i]);
  }
  return 0;
}
"""


def healthy_build(tag):
    """A build that runs and exits 0, so its one-shot health check passes."""
    return compile_payload(
        HELLO_SOURCE.replace("Hello, world from Ariel!", "Hello from %s!" % tag),
        tag)


def install_payload(server, name, data):
    """Push, approve and commit one build, and return its hash."""
    staging, _ = approve_push(server, name, data)
    hash_hex = hashlib.sha256(data).hexdigest()
    assert commit(server, staging) == [
        "installed %s %s" % (name, hash_hex), "exit 0"], (
        "an approved commit must install the build"
    )
    return hash_hex


def scenario_run_streams_output(server):
    data = compile_payload(HELLO_SOURCE, "hello")
    install_payload(server, "hello", data)
    lines = run_payload(server, "hello", ("one", "two"))
    expected = [
        "Hello, world from Ariel!",
        "argv[1] = one",
        "argv[2] = two",
        "status 0",
        "exit 0",
    ]
    assert lines == expected, (
        "a run must stream the payload's output, then its status and exit 0, "
        "got %r" % lines
    )


EXIT_SOURCE = """
#include <stdio.h>

int
main(void) {
  printf("exiting %d\\n", EXIT_CODE);
  return EXIT_CODE;
}
"""


EXIT_ON_ARG_SOURCE = """
#include <stdio.h>

int
main(int argc, char* argv[]) {
  printf("exiting %d\\n", EXIT_CODE);
  return argc > 1 ? EXIT_CODE : 0;
}
"""


def scenario_run_reports_payload_status(server):
    # A build that exits nonzero with no arguments fails its one-shot check at
    # commit, so this build exits with its status only when given an argument.
    for code in (3, 75):
        data = compile_payload(
            EXIT_ON_ARG_SOURCE.replace("EXIT_CODE", str(code)), "exit%d" % code)
        install_payload(server, "exit%d" % code, data)
        lines = run_payload(server, "exit%d" % code, ("now",))
        expected = ["exiting %d" % code, "status %d" % code, "exit 0"]
        assert lines == expected, (
            "a payload exiting %d must answer 'status %d' and 'exit 0', "
            "got %r" % (code, code, lines)
        )


def scenario_run_unknown_name(server):
    lines = run_payload(server, "nosuchpayload")
    assert lines == ["unknown_payload", "exit 1"], (
        "an unknown name must be an error, got %r" % lines
    )

    lines = run_payload(server, "../x")
    assert lines == ["bad_name", "exit 1"], (
        "a name outside the grammar must be an error, got %r" % lines
    )


def scenario_run_stale_object(server):
    data = compile_payload(HELLO_SOURCE, "stale")
    hash_hex = install_payload(server, "stale", data)
    # The ungated telnet shell can still write to /data in Stage 1.
    path = os.path.join(store_dir(server), "objects", hash_hex)
    with open(path, "wb") as handle:
        handle.write(b"tampered bytes")
    lines = run_payload(server, "stale")
    assert lines == ["approval_stale", "exit 78"], (
        "an object changed behind Ariel's back must answer approval_stale "
        "and exit 78 and must not run, got %r" % lines
    )


def scenario_run_fifo_object(server):
    # A fresh server: a run that hangs must not take the other checks down.
    fresh = Server(server.binary)
    try:
        data = compile_payload(HELLO_SOURCE, "fifo")
        hash_hex = install_payload(fresh, "fifo", data)
        other = install_payload(fresh, "fine", compile_payload(
            HELLO_SOURCE, "fine"))
        path = os.path.join(store_dir(fresh), "objects", hash_hex)
        os.unlink(path)
        os.mkfifo(path, 0o600)

        # A FIFO with no writer must not block the open, and the stale
        # answer must come back while the store is still usable.
        sock = fresh.connect(timeout=3.0)
        try:
            sock.sendall(("auth %s\npayload run --wait fifo\n"
                          % fresh.token).encode("ascii"))
            lines = reply_lines(read_reply(sock))
        finally:
            sock.close()
        assert lines == ["approval_stale", "exit 78"], (
            "a FIFO in place of a committed object must answer "
            "approval_stale and exit 78, got %r" % lines
        )

        lines = run_payload(fresh, "fine")
        assert lines[-2:] == ["status 0", "exit 0"], (
            "another client must still run after the FIFO, got %r" % lines
        )
        assert other
    finally:
        fresh.stop()


def scenario_run_needs_no_new_approval(server):
    data = compile_payload(HELLO_SOURCE, "once")
    install_payload(server, "once", data)

    expected = [
        "Hello, world from Ariel!",
        "argv[1] = one",
        "status 0",
        "exit 0",
    ]
    assert run_payload(server, "once", ("one",)) == expected, (
        "the first run of a committed build must need no approval"
    )
    server.assert_no_line()
    assert run_payload(server, "once", ("one",)) == expected, (
        "a later run of the same build must need no approval either"
    )
    server.assert_no_line()

    # A different build is a different hash, so it asks the owner again.
    other = compile_payload(
        EXIT_SOURCE.replace("EXIT_CODE", "0"), "once-other")
    lines = push(server, "once", other)
    assert_staged(server, lines, "once", other)


LINGER_SOURCE = """
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int
main(int argc, char* argv[]) {
  struct timespec pause = {0, 10 * 1000 * 1000};
  FILE* started;

  // With no arguments this is the one-shot health check, which must exit 0.
  if(argc < 3) {
    return 0;
  }

  // Signal that the payload is running, then wait for the harness to let
  // it finish. Neither side has to guess how long a fork or a run takes.
  started = fopen(argv[1], "w");
  if(!started) {
    return 2;
  }
  if(fputs("started\\n", started) == EOF) {
    (void)fclose(started);
    return 2;
  }
  if(fclose(started) != 0) {
    return 2;
  }

  while(access(argv[2], F_OK) != 0) {
    (void)nanosleep(&pause, NULL);
  }

  printf("awake\\n");
  return 0;
}
"""


def wait_for_file(path, timeout=5.0):
    """Wait for an explicit signal from the payload, never a guessed delay."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.01)
    return False


def scenario_run_does_not_leak_connections(server):
    """A finished connection must reach end of stream while a run is going."""
    data = compile_payload(LINGER_SOURCE, "linger")
    install_payload(server, "linger", data)

    workdir = tempfile.mkdtemp(prefix="ariel-linger-")
    started = os.path.join(workdir, "started")
    release = os.path.join(workdir, "release")

    # This client's connection is accepted and still open when the run
    # forks its payload. The exit path of the quick start's `nc` reads
    # until the server closes its side, so a payload that inherited this
    # socket would keep the client waiting until the payload exits.
    stalled = server.connect(timeout=5.0)
    try:
        stalled.sendall(("auth %s\n" % server.token).encode("ascii"))

        outcome = []
        worker = threading.Thread(
            target=lambda: outcome.append(
                run_payload(server, "linger", (started, release))))
        worker.start()
        try:
            # The payload itself says when it has started, and it stays
            # running until the release file appears, so the end-of-stream
            # check below cannot be satisfied by the payload exiting first.
            assert wait_for_file(started), (
                "the payload never signalled that it started")
            stalled.shutdown(socket.SHUT_WR)
            stalled.settimeout(1.0)
            try:
                # Any reply is beside the point; reaching end of stream
                # while the payload still runs is the behavior under test.
                read_reply(stalled)
            except socket.timeout:
                raise AssertionError(
                    "a payload inherited another client's socket: that "
                    "client waited for end of stream until the payload exited"
                )
        finally:
            # Let the payload finish even when the check above failed.
            with open(release, "w") as handle:
                handle.write("go\n")
            worker.join(timeout=10.0)
        assert not worker.is_alive(), "the run did not finish"
        assert outcome and outcome[0] == ["awake", "status 0", "exit 0"], (
            "the run must finish, got %r" % outcome
        )
    finally:
        stalled.close()


def scenario_run_exec_failure(server):
    # Bytes that cannot be executed fail their one-shot check at commit. With
    # no previous version the failed build stays current, so an ad-hoc run of
    # it still reaches spawn_failed.
    data = b"this is not an executable\n"
    digest = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, "notexec", data)
    assert commit(server, staging) == [
        "health_failed notexec %s" % digest, "exit 1"], (
        "a build that cannot be executed must fail its one-shot check")
    assert ("health.fail", "notexec", "spawn", digest) in health_events(server), (
        "a check that could not be spawned must be audited as health.fail, "
        "got %r" % health_events(server))
    lines = run_payload(server, "notexec")
    assert lines == ["spawn_failed", "exit 1"], (
        "a stored object that cannot be executed must answer spawn_failed "
        "and exit 1, never the payload's own status line, got %r" % lines
    )


HANG_SOURCE = """
#include <unistd.h>

int
main(void) {
  for(;;) {
    (void)pause();
  }
}
"""

SLEEP_SOURCE = """
#include <stdio.h>
#include <time.h>

int
main(void) {
  struct timespec pause = {1, 0};
  (void)nanosleep(&pause, NULL);
  printf("slept\\n");
  return 0;
}
"""

# The one-shot timeout a background run gets: payload config, which would set
# it per payload, is Stage 2 (#2). Until then every background run has this.
RUN_TIMEOUT_MS = 30_000


def background_run(server, name):
    """Send one payload run without --wait and return the lines answered."""
    return send_command(server, "payload run %s" % name)


def payload_logs(server, name):
    """Send one payload logs and return the lines answered."""
    return send_command(server, "payload logs %s" % name)


def audit_events(server):
    """The audit tail as (kind, name, id, sha256) tuples, oldest first."""
    return [
        tuple(line.split()[1:5])
        for line in audit_tail(server)
        if line != "exit 0"
    ]


def running_flag(server, name):
    """The running= field of one payload's list line."""
    line = listed(payload_list(server), name)
    assert line is not None, "payload list must name %s" % name
    return line.rsplit("running=", 1)[1].split()[0]


def scenario_background_run_returns_pid(server):
    data = compile_payload(EXIT_SOURCE.replace("EXIT_CODE", "0"), "bgpid")
    digest = install_payload(server, "bgpid", data)
    lines = background_run(server, "bgpid")
    assert len(lines) == 2 and lines[1] == "exit 0" and re.fullmatch(
        r"pid [1-9][0-9]*", lines[0]), (
        "a background run must answer 'pid <n>' and 'exit 0' at once, "
        "got %r" % lines)
    pid = lines[0].split()[1]
    assert payload_logs(server, "bgpid") == ["exiting 0", "exit 0"], (
        "logs must hold what the payload printed, then its exit line")
    runs = [event for event in audit_events(server)
            if event[1] == "bgpid" and event[0] in ("run", "exit")]
    assert runs == [
        ("run", "bgpid", pid, digest),
        ("exit", "bgpid", "0", digest)], (
        "the run and its exit must be audited in order, got %r" % runs)


def scenario_background_logs_one_shot(server):
    data = compile_payload(HELLO_SOURCE, "bghello")
    install_payload(server, "bghello", data)
    assert background_run(server, "bghello")[-1] == "exit 0"
    lines = payload_logs(server, "bghello")
    assert lines == ["Hello, world from Ariel!", "exit 0"], (
        "logs of a one-shot must show its full output once it has exited, "
        "got %r" % lines)


def scenario_background_hung_payload_is_cut(server):
    data = compile_payload(HANG_SOURCE, "bghang")
    digest = install_hanging(server, "bghang", data)
    lines = background_run(server, "bghang")
    assert lines[-1] == "exit 0" and lines[0].startswith("pid "), (
        "a background run must answer a pid, got %r" % lines)
    pid = lines[0].split()[1]
    assert running_flag(server, "bghang") == "yes", (
        "payload list must show a background payload as running")

    server.advance(RUN_TIMEOUT_MS - 1000)
    assert running_flag(server, "bghang") == "yes", (
        "a payload must not be cut before its timeout")

    server.advance(1000)
    deadline = time.monotonic() + 5.0
    while running_flag(server, "bghang") != "no":
        assert time.monotonic() < deadline, (
            "a hung payload must be cut once its timeout has passed")
        time.sleep(0.02)

    assert payload_logs(server, "bghang") == ["exit 0"], (
        "logs of a cut payload answer once it is gone, with no output")
    cuts = [event for event in audit_events(server) if event[1] == "bghang"]
    assert ("cut", "bghang", pid, digest) in cuts, (
        "the cut must be audited, got %r" % cuts)


def scenario_background_run_refusals(server):
    assert send_command(server, "payload run bgnosuch") == [
        "unknown_payload", "exit 1"]
    assert send_command(server, "payload logs bgnosuch") == [
        "unknown_payload", "exit 1"]
    assert send_command(server, "payload run ../escape") == [
        "bad_name", "exit 1"]
    assert send_command(server, "payload logs ../escape") == [
        "bad_name", "exit 1"]

    data = compile_payload(EXIT_SOURCE.replace("EXIT_CODE", "0"), "bgnever")
    install_payload(server, "bgnever", data)
    # Activation runs the one-shot check, which writes the log, so a committed
    # payload has its check's output there before any background run.
    assert payload_logs(server, "bgnever") == ["exiting 0", "exit 0"], (
        "the log of a committed payload must hold its health check's output")

    data = compile_payload(SLEEP_SOURCE, "bgsleep")
    install_payload(server, "bgsleep", data)
    assert background_run(server, "bgsleep")[-1] == "exit 0"
    assert background_run(server, "bgsleep") == [
        "already_running", "exit 1"], (
        "a second background run of a running payload must be refused")
    events = audit_events(server)
    assert ("refuse", "bgnosuch", "unknown_payload", "-") in events, (
        "a refused run must be audited, got %r" % events)
    assert ("refuse", "bgsleep", "already_running", "-") in events, (
        "a refused run of a running payload must be audited, got %r" % events)
    assert payload_logs(server, "bgsleep") == ["slept", "exit 0"], (
        "logs must wait for the running payload to exit")


def doc_path(name="quick-start.md"):
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "..", "..", "docs", name)


def run_quick_start(server, doc):
    """Run the quick start's 'After Stage 1' section against one server."""
    import quickstart

    workdir = tempfile.mkdtemp(prefix="ariel-quickstart-")
    quickstart.run_quick_start(
        doc_path=doc,
        workdir=workdir,
        host=HOST,
        port=server.port,
        token=server.token,
        next_line=lambda timeout=5.0: server.next_line(timeout=timeout),
        approve=lambda approval_id, challenge: sign_and_grant(
            server, approval_id, challenge),
    )


def fixture_fails(server, text, description):
    """Run the fixture against mutated documentation and demand a failure."""
    import quickstart

    handle = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
    try:
        handle.write(text)
        handle.close()
        fresh = Server(server.binary)
        try:
            try:
                run_quick_start(fresh, handle.name)
            except quickstart.FixtureError:
                return
            raise AssertionError(
                "%s must fail the fixture" % description)
        finally:
            fresh.stop()
    finally:
        os.unlink(handle.name)


def scenario_quick_start(server):
    fresh = Server(server.binary)
    try:
        run_quick_start(fresh, doc_path())
    finally:
        fresh.stop()


def scenario_quick_start_doc_drift(server):
    import quickstart

    with open(doc_path()) as handle:
        text = handle.read()
    section = quickstart.after_stage1(text)
    drifted = section.replace(
        "Hello, world from Ariel!", "Goodbye from Ariel!", 1)
    assert drifted != section, (
        "the 'After Stage 1' section must show the payload's output")
    fixture_fails(server, text.replace(section, drifted, 1),
                  "a quick start changed without Ariel")


def scenario_quick_start_broken_setup(server):
    import quickstart

    with open(doc_path()) as handle:
        text = handle.read()
    section = quickstart.after_stage1(text)
    export = "$ export ARIEL_TOKEN=%s" % quickstart.TOKEN_PLACEHOLDER
    assert export in section, "the section must export the token"

    wrong = ("0" if server.token[0] != "0" else "1") + server.token[1:]
    mutations = (
        ("a wrong token in the documented export",
         "$ export ARIEL_TOKEN=%s" % wrong),
        ("a setup command that does not exist",
         "$ no-such-ariel-command ARIEL_TOKEN=%s"
         % quickstart.TOKEN_PLACEHOLDER),
    )

    for description, replacement in mutations:
        mutated = text.replace(export, replacement, 1)
        assert mutated != text, "the section must hold the export command"
        fixture_fails(server, mutated, description)


def scenario_quick_start_unlabeled_block(server):
    import quickstart

    with open(doc_path()) as handle:
        text = handle.read()
    section = quickstart.after_stage1(text)

    for label in ("sh", "bash", "shell", ""):
        extra = "\n```%s\n$ no-such-ariel-command\n```\n" % label
        mutated = text.replace(section, section.rstrip("\n") + extra + "\n", 1)
        assert mutated != text, "the section must be found"
        fixture_fails(server, mutated,
                      "a failing command in a '%s' block" % label)


def staging_path(server, staging_id):
    return os.path.join(server.root, "data", "ariel", "staging", staging_id)


def assert_staging_full(lines):
    assert lines == ["staging_full", "exit 80"], (
        "expected staging_full and exit 80, got %r" % lines)


def scenario_upload_too_large(server):
    """One upload is at most 64 MiB; past that, staging_full."""
    server.fresh()
    too_big = 64 * 1024 * 1024 + 1
    assert_staging_full(push(server, "toobig", b"", declared_size=too_big,
                             declared_hash="0" * 64))
    server.assert_no_line()


def scenario_staging_total(server):
    """Staging holds at most 64 MiB in total."""
    server.fresh()
    cap = 64 * 1024 * 1024
    data = b"\0" * cap
    lines = push(server, "big", data, timeout=30.0)
    assert_staged(server, lines, "big", data, timeout=30.0)

    # One byte past the total is refused before a new object is made.
    assert_staging_full(push(server, "extra", b"x"))
    server.assert_no_line()


def scenario_staging_ttl(server):
    """An unanswered staging object disappears after 15 min, by itself."""
    server.fresh()

    # Eight objects, three approvals at a time: each group's approvals
    # expire, but its objects stay until their own TTL.
    created = []
    for group, count in ((0, 3), (1, 3), (2, 2)):
        for i in range(count):
            name = "ttl%d%d" % (group, i)
            data = name.encode("ascii")
            now = server.advance(10_000)
            lines = push(server, name, data, throttle=False)
            staging_id, _ = assert_staged(server, lines, name, data)
            created.append((now, staging_path(server, staging_id)))
        server.advance(120_000)

    # The ninth object has no room while the table is full.
    assert_staging_full(push(server, "ttl-full", b""))
    server.assert_no_line()

    # Only the clock moves from here: no store request can clean up.
    first, first_path = created[0]
    now = server.advance(0)
    server.advance(first + 900_000 - 1 - now)
    server.settle(0)
    gone = [path for _, path in created if not os.path.exists(path)]
    assert not gone, "objects left before their TTL: %r" % gone

    server.advance(1)
    server.settle(0)
    assert not os.path.exists(first_path), (
        "the first object outlived its 15 min TTL")
    gone = [path for _, path in created[1:] if not os.path.exists(path)]
    assert not gone, "objects left before their TTL: %r" % gone

    last, _ = created[-1]
    server.advance(last - first)
    server.settle(0)
    stayed = [path for _, path in created if os.path.exists(path)]
    assert not stayed, "objects outlived their TTL: %r" % stayed

    # Their slots are free again.
    lines = push(server, "ttl-after", b"after the TTL")
    assert_staged(server, lines, "ttl-after", b"after the TTL")


def scenario_pending_limit(server):
    """At most three approvals wait for a decision."""
    server.fresh()
    for i in range(3):
        name = "plim%d" % i
        data = b"pending %d" % i
        lines = push(server, name, data)
        assert_staged(server, lines, name, data)

    lines = push(server, "plim3", b"one too many")
    assert lines == ["approval_busy", "exit 76"], (
        "a fourth pending approval must answer approval_busy and exit 76, "
        "got %r" % lines)
    server.assert_no_line()


def scenario_notification_rate(server):
    """At most one notification is shown every 10 s."""
    server.fresh()
    data = b"the first"
    lines = push(server, "rate1", data)
    assert_staged(server, lines, "rate1", data)

    # The second push at the same test-clock instant is refused, no prompt.
    lines = push(server, "rate2", b"the second", throttle=False)
    assert lines == ["approval_busy", "exit 76"], (
        "a second notification within 10 s must answer approval_busy and "
        "exit 76, got %r" % lines)
    server.assert_no_line()

    # Ten seconds later the next prompt is shown.
    server.advance(10_000)
    data = b"the third"
    lines = push(server, "rate3", data, throttle=False)
    assert_staged(server, lines, "rate3", data)


# Console mode, proven without a console. The sentinel is TEST-NET-1, which
# no console answers on: the plan path must reach it nowhere.
RECOVERY_ROTATE_PROMPT = "key rotate-recovery will run"
RECOVERY_SIGNED_TITLE = ("key rotate-recovery needs the current recovery key, "
                         "and the primary's signature answers signature_invalid")
RECOVERY_TARGETS_TITLE = ("key rotate-recovery refuses the active primary and "
                          "the current recovery key before asking the owner")
RECOVERY_RETIRED_TITLE = ("key rotate-recovery refuses a retired recovery key "
                          "as target and as signer")
ROTATE_CRASH_TITLE = ("a crash at each durable step of key rotate leaves "
                      "exactly one keyring active after restart")
RECOVERY_CRASH_TITLE = ("a crash at each durable step of key rotate-recovery "
                        "leaves exactly one keyring active after restart")
ADR_RECOVERY_TITLE = ("ADR-0009 names the recovery rotation and the crash steps "
                      "of a rotation")
KEYRING_MISSING_TITLE = ("a keyring missing above generation 0 refuses every "
                         "approval")
KEYRING_CORRUPT_TITLE = ("a corrupt keyring above generation 0 refuses every "
                         "approval")
KEYRING_OLDER_TITLE = ("a keyring older than the state file refuses every "
                       "approval")
REVIVE_TITLE = ("a rotated recovery key then a corrupt keyring never revives "
                "the original recovery key")
ANCHOR_MISMATCH_TITLE = ("a build with another anchor refuses every approval "
                         "until key adopt-anchor")
ADOPT_SIGNER_TITLE = ("key adopt-anchor needs the new anchor's recovery key and "
                      "refuses every other signature")
ADOPT_AUDIT_TITLE = ("key adopt-anchor keeps the consumed nonces and the audit "
                     "log")
ADOPT_MATCH_TITLE = ("key adopt-anchor is refused, without a challenge, while "
                     "the anchor matches")

# The durable steps of a rotation, each with the generation that is active
# once Ariel restarts: a prepared rotation rolls back, the rest roll forward.
ROTATION_CRASH_STEPS = (
    ("prepared", 0),
    ("committed", 1),
    ("renamed", 1),
    ("audited", 1),
)

CONSOLE_SENTINEL = "192.0.2.1"
CONSOLE_BANNER = "console mode: %s:2324"
PLAN_RUN = "run  "
# Scenarios that create files or links under the host test root. Console mode
# cannot create them, so it runs its own checks of the same commands instead.
HOST_ROOT_REASON = ("needs files or links in the host test root, which console "
                    "mode cannot create")
# Scenarios that compare an answer with the machine the suite runs on. Console
# mode talks to another machine, so the same answer has no oracle there.
HOST_MACHINE_REASON = ("needs the host's own clock, machine and kernel log, "
                       "which console mode cannot compare")
PLAN_SKIP = re.compile(r"^skip (\S.*) \((needs [^()]+)\)$")
CLOCK_REASON = "needs the test clock"
FAULT_REASON = "needs the fault injector"
FAULT_ENV = "ARIEL_HOST_FAULT"
HOST_FILE_REASON = "needs the state file on the host"

# The scenarios that crash Ariel at a named commit step, which only a host
# build with the fault injector can do.
FAULT_SCENARIOS = {
    ROTATE_CRASH_TITLE,
    RECOVERY_CRASH_TITLE,
    "a crash in prepared leaves the old version in payload list after restart",
    "a crash in committed leaves the new version in payload list after restart",
    "a committed change whose new object is gone is refused at start and "
    "audited, and the state file is left as it was",
    "a recovery killed after its renames, then a clean start, leaves the "
    "listing, state file and audit of one crash",
    "a crash in prepared during a rollback leaves the newer build current "
    "after restart",
    "a crash in committed during a rollback leaves the previous build current "
    "after restart",
    "a crash in prepared of an autoload edit leaves the old list after restart",
    "a crash in committed of an autoload edit leaves the new list after restart",
    "a journal written as v1 before autoload existed rolls a committed change "
    "forward after restart",
    "a journal written as v1 before autoload existed rolls a prepared change "
    "back after restart",
    "a committed autoload edit whose list file is gone rolls forward at the "
    "next start",
}

# The scenarios that rewrite or remove the state file on the host's disk,
# which the agent port cannot do on a console.
HOST_FILE_SCENARIOS = {
    "a store written by Stage 1 is migrated on the first start, and a "
    "second start changes nothing",
    "a state file whose payload lines have eight fields starts and lists "
    "previous=-",
    "a state file in format v1 starts, lists its payloads, and the next save "
    "writes v2",
    "a rollback whose record the store cannot read answers rollback_failed "
    "and keeps the grant",
}

# Scenarios that act on a process only the host build starts (a victim the
# suite spawns, or Ariel's own pid). A console has no such process to act on.
HOST_FIXTURE_REASON = ("needs a process only the host build starts, which "
                       "console mode cannot name")

# The release scenarios start a fake release server and write its allowlist into
# the test root. A console can reach neither, so console mode names them as skipped.
RELEASE_FIXTURE_REASON = ("needs the fake release server and an allowlist the "
                          "host test root writes")

# A granted reboot restarts Ariel's own process, and a crash restart ends it.
# On a console the same grant would reboot the console, so these never run there.
HOST_RESTART_REASON = ("needs a restart of Ariel's own process, which a console "
                       "would turn into a reboot")

# The scenarios whose behavior is defined by moving the host test clock.
# This list comes from the SPEC's time-dependent cases, not from the code.
CLOCK_SCENARIOS = {
    RECOVERY_SIGNED_TITLE,
    RECOVERY_RETIRED_TITLE,
    KEYRING_MISSING_TITLE,
    KEYRING_CORRUPT_TITLE,
    KEYRING_OLDER_TITLE,
    REVIVE_TITLE,
    ANCHOR_MISMATCH_TITLE,
    ADOPT_SIGNER_TITLE,
    ADOPT_AUDIT_TITLE,
    "key rotate accepts only the current primary and refuses the recovery "
    "key's signature",
    "key rotate refuses a retired primary's signature",
    "a signature over another generation's message is refused",
    "a challenge issued before a rotation stops verifying after it",
    "a nonce consumed before a rotation stays consumed after a restart",
    "key rotate refuses a retired primary and the current primary, also "
    "after a restart",
    "an unused approval granted under a retired primary answers "
    "approval_stale",
    "a one-shot past its timeout fails, and with no previous version it is "
    "marked failed",
    "a failed one-shot with no previous version is removed from autoload",
    "payload config is gated, applied after a grant and audited, and refuses "
    "unknown payloads, other kinds and a zero timeout",
    "a rollback whose restored build fails its health check is replaced by "
    "the build it rolled back from",
    "rollbacks that end, and requests left to expire, free their approval "
    "rows, so a push still asks for approval",
    "each gated built-in answers 75 and its challenge before anything runs",
    "a granted built-in on the host answers not available once and audits "
    "the grant and the run",
    "a built-in run with another argument answers approval_stale and exit 78",
    "reptyr of a restarted process answers approval_stale and exit 78 and "
    "touches nothing",
    "a file replaced after a built-in grant answers approval_stale and exit 78",
    "missing auth after 5 s of test clock closes with exit 70",
    "a command still running at the 60 s deadline answers timed_out",
    "a quoted path is escaped in the signed action and decoded by the "
    "signer",
    "a stalled upload does not block another connection",
    "a hung background payload is listed as running, then cut at its "
    "timeout and listed as not running",
    "an approval expires after 120 s of test clock and answers exit 88",
    "an expired approval does not count among the pending ones",
    "an unanswered staging object disappears after 15 min",
    "a second notification within 10 s answers approval_busy with no prompt",
    "the test clock is host-only and cannot enter the PS5 build",
    "a valid signature decides the approval and the gated command runs once",
    "a forged signature answers signature_invalid and runs nothing",
    "a signature for a different command, target or hash answers "
    "signature_action_mismatch",
    "a signature for another console answers signature_console_mismatch",
    "the signer refuses an action with bytes it cannot show",
    "a signature after the challenge expired answers approval_expired and "
    "exit 88",
    "a malformed signature answers signature_malformed and exit 83",
    "the same signature twice is refused the second time",
    "a consumed nonce is refused after Ariel restarts",
    "approval status answers pending, granted, denied, expired and consumed, "
    "and an unknown id is an error",
    "a full approval table gives up an approval with no staged object first, "
    "and an expired staged object still answers approval_expired",
    "the challenge names the command, target, hash, size and run of the "
    "approval",
    "mkdir, rmdir, touch and rm run only after the owner signs, once each",
    "a command nothing implements asks the owner and then does nothing",
    "a file command's audit lines reach audit tail",
    "the challenge of a file command names its path, sha256 none and identity",
    "a file run by path prints nothing until the owner signs, then runs once",
    "a run of a file rewritten after approval answers approval_stale and "
    "exit 78",
    "a run of a file replaced by another object with the same bytes answers "
    "approval_stale and exit 78",
    "a bare name found on the PATH is gated as the file it resolves to",
    "a run's request, grant, start and status reach audit tail in order",
    "the challenge of a run names its path, its sha256 and its identity",
    "a run's arguments are part of the signed action, and other arguments "
    "answer approval_stale",
    "kill asks for approval, and a grant runs it once and audits the request, "
    "grant and kill",
    "a restarted process under the same pid answers approval_stale and exit "
    "78 and is not signalled",
    "a kill signal or start changed in the challenge answers "
    "signature_action_mismatch, and the real grant still runs it",
    "chmod, chown and chgrp run only after the owner signs, once each, and "
    "are audited",
    "a chmod approved for one mode answers approval_stale for another, and "
    "the signed mode runs",
    "mount, umount, chroot and mknod ask the owner, and once signed answer "
    "not available on this platform",
    "an object created under a mknod's name after approval answers "
    "approval_stale and exit 78",
    "the challenge of mount and mknod names its command, target and options",
    "a system command's audit lines reach audit tail",
    "env asks for approval, and a grant reveals the one variable it names",
    "export asks for approval, and a grant sets the variable it names",
    "an export whose value changed after approval answers approval_stale and "
    "exit 78",
    "exec asks for approval of the program's bytes and arguments, and a grant "
    "runs it once",
    "exec with other arguments after approval answers approval_stale and "
    "exit 78",
    "exec of a program replaced after approval answers approval_stale and "
    "exit 78",
    "an autoload edit refused as busy answers approval_busy and is audited",
    "an autoload edit whose audit line fails after the rename answers "
    "audit_failed and stays applied",
    "tar -x answers 75 with a challenge naming its facts, extracts after the "
    "grant, and never overwrites",
    "an archive replaced after the owner signs answers approval_stale and "
    "writes nothing",
    "an archive swapped for a link to Ariel's token after the owner signs "
    "runs nothing",
    "tar listings, runs and refusals reach audit tail under their paths",
}

# The scenarios that act on a process only the host build starts, or on
# Ariel's own pid. A console has neither to act on.
HOST_FIXTURE_SCENARIOS = {
    "kill of Ariel's own process answers protected and exit 87",
    "reptyr of a restarted process answers approval_stale and exit 78 and "
    "touches nothing",
    "http2_get refuses a URL off the allowlist without asking",
    "http2_get answers 75 with its URL in the signed bytes",
    "http2_get fetches its body after a grant and is audited",
    "http2_get -o writes the body to the file after a grant",
    "http2_get refuses an approved URL that left the allowlist",
    "http2_get answers approval_stale when the destination changed after a grant",
    "http2_get refuses a redirect without following it",
}

HOST_RESTART_SCENARIOS = {
    "a restart reads only the new server's output, even when the old one's "
    "stream closes late",
    "a granted reboot restarts Ariel, keeps payloads listed and runs the "
    "autoload entries",
    "a crash restart runs no autoload entry and restarts nothing that was "
    "running",
    "a granted reboot is audited as its request, grant and done",
    "a granted autoload safe-boot skips autoload on the next boot only",
    "a second autoload safe-boot while one is pending answers "
    "safe_boot_pending, exit 1, and asks nothing",
}

# The scenarios that need the host test root: they write scratch files or
# links there, and the token, approval state and nonces live there.
HOST_ROOT_SCENARIOS = {
    "the keyring is a protected object",
    "http2_get -o answers protected for the token and its hard link, unasked",
    "each gated built-in answers 75 and its challenge before anything runs",
    "a built-in's challenge names each argument after the target, in order",
    "a built-in that names Ariel's token answers protected and asks nothing",
    "a file replaced after a built-in grant answers approval_stale and exit 78",
    "a health check whose log cannot be opened fails and is audited as "
    "health.fail",
    "each read-only command runs with no approval and exits 0 with its output",
    "sha256sum prints the digest openssl dgst -sha256 prints",
    "read answers the file's size and SHA-256, its raw bytes, then exit 0",
    "read of a file over the cap returns ranges that reassemble and verify "
    "by the whole file's hash",
    "a cut read from an offset marks the range's length in truncated",
    "read past the end answers bad_range and exit 1, and a bad option "
    "answers bad_option",
    "the token, approval state and nonces answer protected and exit 87 when "
    "read directly",
    "the token, approval state and nonces answer protected and exit 87 "
    "through a symbolic link",
    "the token, approval state and nonces answer protected and exit 87 "
    "through a hard link",
    "writes outside /data, /user and /mnt/usb* answer protected and exit 87 "
    "without asking, and so does Ariel's token",
    "a file replaced after approval answers approval_stale and exit 78",
    "a file replaced after a chmod approval answers approval_stale and keeps "
    "its mode",
    "chmod, chown and chgrp answer protected through hard and symbolic links "
    "to a protected object, even when approved",
    "cp, mv and ln ask the owner first, run once after the signature, and "
    "ask again",
    "a source swapped after approval answers approval_stale and exit 78 for "
    "cp, mv and ln",
    "cp, mv and ln refuse an existing destination with exists, without asking",
    "cp, mv and ln refuse the token, approval state, nonces and the state "
    "directory through any alias with protected and exit 87",
    "a source swapped after approval for a link to the token answers "
    "protected and exit 87, even when approved",
    "cp, mv and ln audit each action and refusal, and audit tail shows them",
    "the challenge of cp names both paths, sha256 none and the source's "
    "identity",
    "a system command on Ariel's token or outside the writable roots answers "
    "protected and exit 87 without asking",
    "unzip -l lists the members at once, and a file that is no zip answers "
    "bad_archive",
    "unzip asks the owner first, extracts after the signature, and asks again",
    "a member with ../ or an absolute path refuses the whole archive with "
    "unsafe_member, asked of no one and written nowhere",
    "an archive replaced or rewritten after approval answers approval_stale "
    "and exit 78",
    "unzip refuses the token, approval state, nonces and the state directory "
    "through any alias with protected and exit 87, even when approved",
    "unzip lists, runs and refusals reach audit tail under their paths",
    "a run of a missing path, a directory or a file without execute bits "
    "answers its word and exit 1 without asking",
    "a run of Ariel's token answers protected and exit 87 without asking",
    "a run with an argument outside printable ASCII answers bad_path, and a "
    "run with too many arguments answers unknown_command, without asking",
    "a quoted path with a space runs, and a quote or backslash is escaped",
    "a target outside printable ASCII answers bad_path and asks nothing",
    "a run of a file over 64 MiB answers too_large and exit 1 without asking",
    "a run never follows a symbolic link, by path or on the PATH, and answers "
    "symbolic_link",
    "tar -t lists every member name in archive order at once, and a non-tar "
    "answers not_a_tar",
    "a member or link that escapes the destination is refused at once, and "
    "nothing is written",
    "tar refuses Ariel's own objects, and a member that names one, through "
    "any alias, without asking",
}


def console_plan(env):
    """Run the harness's console-mode listing path and return the result."""
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "acceptance.py")
    return subprocess.run([sys.executable, script, "--plan"], env=env,
                          capture_output=True, text=True, timeout=120)


def scenario_console_mode_plan(server):
    """PS5_HOST selects console mode, which names every clock scenario it skips."""
    del server  # the plan path contacts nothing

    env = os.environ.copy()
    env["PS5_HOST"] = CONSOLE_SENTINEL
    planned = console_plan(env)
    assert planned.returncode == 0, (
        "the console plan must run without a console, it exited %d: %s"
        % (planned.returncode, planned.stderr))
    lines = planned.stdout.splitlines()
    assert lines and lines[0] == CONSOLE_BANNER % CONSOLE_SENTINEL, (
        "console mode must announce the console it targets, got %r" % lines[:1])

    run = [line[len(PLAN_RUN):] for line in lines if line.startswith(PLAN_RUN)]
    skipped = []
    for line in lines:
        if not line.startswith("skip "):
            continue
        match = PLAN_SKIP.match(line)
        assert match, "a skipped scenario must name its reason: %r" % line
        skipped.append(match.group(1))

    expected_skips = (CLOCK_SCENARIOS | HOST_ROOT_SCENARIOS | FAULT_SCENARIOS
                      | HOST_FILE_SCENARIOS | HOST_FIXTURE_SCENARIOS
                      | HOST_RESTART_SCENARIOS | RELEASE_SCENARIOS
                      | HOST_MACHINE_SCENARIOS)
    assert set(skipped) == expected_skips, (
        "console mode must skip exactly the scenarios that need the test "
        "clock, the host test root, the fault injector or the host's files:"
        "\nmissing %r\nunexpected %r"
        % (sorted(expected_skips - set(skipped)),
           sorted(set(skipped) - expected_skips)))
    assert run, "console mode must run its scenarios against the console"
    assert not set(run) & set(skipped), (
        "a scenario cannot be both run and skipped: %r"
        % sorted(set(run) & set(skipped)))
    assert any("quick start" in title for title in run), (
        "console mode must run the quick start, runs %r" % run)
    assert any("key rotate-recovery" in title for title in run), (
        "console mode must refuse the key rotations without asking, runs %r"
        % run)
    assert any("keyring" in title for title in run), (
        "console mode must read the keyring as protected, runs %r" % run)

    # With PS5_HOST unset nothing selects console mode.
    env.pop("PS5_HOST")
    headless = console_plan(env)
    assert headless.returncode != 0, (
        "without PS5_HOST the suite must not enter console mode")
    assert "PS5_HOST" in (headless.stdout + headless.stderr), (
        "the refusal must name PS5_HOST, got %r"
        % (headless.stdout + headless.stderr))


class ScriptedLink:
    """A fake console agent port: scripted replies, recorded exchange order."""

    def __init__(self, replies, events):
        self.replies = list(replies)
        self.events = events

    def exchange(self, command, body=None, token=None):
        self.events.append(("send", command))
        assert self.replies, "the harness sent an unscripted command: %r" % command
        return list(self.replies.pop(0))


def scripted_session(replies, answers=()):
    """One console session over a scripted link and a scripted operator."""
    import console

    events = []
    shown = []
    answers = list(answers)

    def read(prompt=""):
        events.append(("wait", prompt))
        return answers.pop(0) if answers else ""

    def write(line=""):
        shown.append(line)

    link = ScriptedLink(replies, events)
    operator = console.Operator(read=read, write=write, sleep=lambda s: None)
    return console, link, operator, console.Session(link, operator), events, shown


class SilentSocket:
    """A console connection that accepts a command and answers nothing."""

    def sendall(self, data):
        pass

    def shutdown(self, how):
        pass

    def recv(self, size):
        return b""

    def close(self):
        pass


def scenario_console_run_reaches_checks(server):
    """Console mode reaches its checks over an injected transport."""
    del server  # the injected transport stands in for the console

    import console

    answers = ["0123456789abcdef0123456789abcdef"]
    operator = console.Operator(
        read=lambda prompt="": answers.pop(0) if answers else "",
        write=lambda line="": None, sleep=lambda s: None)
    real_clang = console.prospero_clang
    console.prospero_clang = lambda: ["prospero-clang"]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            results = console.run(
                "192.0.2.1", [], operator=operator,
                connect=lambda address, timeout=None: SilentSocket())
    finally:
        console.prospero_clang = real_clang

    assert len(results) == len(console.CHECKS), (
        "every console check must run, got %d of %d"
        % (len(results), len(console.CHECKS)))
    broken = [detail for _title, _ok, detail in results
              if "NameError" in detail or "AttributeError" in detail]
    assert not broken, "the harness itself is broken: %r" % broken


def scenario_console_quick_start_waits_for_the_gap(server):
    """The quick start's push waits out the gap since the last notification."""
    del server  # the fixture is replaced; nothing reaches a console

    import console

    sleeps = []
    seen = []
    operator = console.Operator(read=lambda prompt="": "",
                                write=lambda line="": None,
                                sleep=sleeps.append)
    session = console.Session(None, operator, sleep=sleeps.append)
    context = console.Context(host="192.0.2.1", port=console.PORT,
                              token="0" * 32, workdir="/nonexistent",
                              cc=["prospero-clang"], document="quick-start.md")

    real = console.quickstart.run_quick_start
    console.quickstart.run_quick_start = lambda **kwargs: seen.append(
        list(sleeps))
    try:
        console.check_quick_start(session, context)
    finally:
        console.quickstart.run_quick_start = real

    # The check before it ends with a push the console notified; the fixture
    # pushes at once and does not retry approval_busy, so the wait comes first.
    assert seen == [[console.NOTIFICATION_SPACING]], (
        "the quick start must wait %.0f s before its push, waited %r"
        % (console.NOTIFICATION_SPACING, seen))


class StopCheck(Exception):
    """A fake console stops a check at the first command it has no answer for."""


class ActivatingLink:
    """A fake agent port that stages, grants and installs every push.

    It answers just enough for a check to reach every push it makes before an
    activation, and records each pushed body, so a test can see what a console
    check would have run on the console.
    """

    def __init__(self):
        self.pushes = []
        self.staged = {}

    def exchange(self, command, body=None, token=None):
        words = command.split()
        if words[:2] == ["payload", "push"]:
            index = len(self.pushes) + 1
            self.pushes.append((words[2], body))
            self.staged["s-%d" % index] = (words[2], words[4])
            return ["staged s-%d" % index, "approval_required a-%d" % index,
                    "challenge a-%d 00" % index, "exit 75"]
        if words[:2] == ["approval", "grant"]:
            return ["approval_granted %s" % words[2], "exit 0"]
        if words[:2] == ["payload", "commit"] and words[2] in self.staged:
            name, digest = self.staged[words[2]]
            return ["installed %s %s" % (name, digest), "exit 0"]
        raise StopCheck(command)

    def raw(self, payload):
        raise StopCheck(payload)


def scenario_console_checks_push_runnable_builds(server):
    """Every console check that activates a build pushes one the console can run."""
    del server  # the fake link stands in for the agent port

    import console

    # A check that only proves a refusal may push bytes that never run.
    refusals = {console.check_truncated_upload, console.check_hash_mismatch,
                console.check_bad_name, console.check_install_bad_name_is_audited,
                console.check_unsigned_commit}
    activating = {console.check_approval_then_install, console.check_audit_tail,
                  console.check_approval_status,
                  console.check_rollback_restores_previous,
                  console.check_rollback_refusals,
                  console.check_autoload_edit_asks_before_it_applies,
                  console.check_autoload_edit_applies_after_grant,
                  console.check_autoload_stale_grant_answers_78}

    built = {}

    def build(label):
        # Stands in for prospero-clang: an ELF the console would run.
        built[label] = b"\x7fELF runnable " + label.encode("ascii")
        return built[label]

    pushed = {}
    for _title, check in console.CHECKS:
        if check is console.check_quick_start:
            continue  # it builds and pushes helloworld.elf itself
        link = ActivatingLink()
        operator = console.Operator(read=lambda prompt="": "",
                                    write=lambda line="": None,
                                    sleep=lambda s: None)
        session = console.Session(link, operator, sleep=lambda s: None)
        context = console.Context(host="192.0.2.1", port=console.PORT,
                                  token="0" * 32, workdir="/nonexistent",
                                  cc=["prospero-clang"],
                                  document="quick-start.md")
        context.build = build
        try:
            check(session, context)
        except Exception:  # noqa: BLE001 - the fake stops every check early
            pass
        pushed[check] = link.pushes

    runnable = set(built.values())
    for check in activating:
        assert pushed[check], (
            "%s must push a build before it activates one" % check.__name__)
    for check, pushes in pushed.items():
        if check in refusals:
            continue
        stray = [name for name, data in pushes if data not in runnable]
        assert not stray, (
            "%s pushes bytes the console cannot run for %r; every activation "
            "runs a health check" % (check.__name__, stray))
    rollback = pushed[console.check_rollback_restores_previous]
    assert len(rollback) == 2 and rollback[0][1] != rollback[1][1], (
        "a rollback needs two distinct runnable builds, got %r"
        % [name for name, _data in rollback])


def cat_printed(data):
    """What cat prints for a file: its bytes, and one newline if they lack one."""
    return data if not data or data.endswith(b"\n") else data + b"\n"


class FakeFileTree:
    """A fake agent port over a file tree, with gated mkdir, touch, cp -r and rm -r.

    A gated command answers 75 with a challenge until the owner's grant is
    recorded, then runs once when it is sent again. drop_children makes cp -r
    copy the directory and not what it holds.
    """

    GATED = ("mkdir", "touch", "cp", "rm")

    def __init__(self, drop_children=False):
        self.paths = set()
        self.drop_children = drop_children
        self.pending = {}
        self.granted = set()
        self.asked = 0

    def exchange(self, command, body=None, token=None):
        words = command.split()
        if words[:2] == ["approval", "grant"]:
            self.granted.add(self.pending.pop(words[2]))
            return ["approval_granted %s" % words[2], "exit 0"]
        if command in self.granted:
            self.granted.discard(command)
            return self.run(words)
        if words[0] in self.GATED:
            self.asked += 1
            approval = "a-%d" % self.asked
            self.pending[approval] = command
            return ["approval_required %s" % approval,
                    "challenge %s 00" % approval, "exit 75"]
        return self.run(words)

    def run(self, words):
        if words[0] == "stat":
            if words[1] in self.paths:
                return ["%s: 0 bytes" % words[1], "exit 0"]
            return ["no_such_file", "exit 1"]
        if words[0] == "ls":
            names = sorted(path.rsplit("/", 1)[1] for path in self.paths
                           if path.rsplit("/", 1)[0] == words[1])
            return ["-rw-r--r-- 0 %s" % name for name in names] + ["exit 0"]
        if words[0] in ("mkdir", "touch"):
            self.paths.add(words[1])
            return ["exit 0"]
        if words[:2] == ["cp", "-r"]:
            source, destination = words[2], words[3]
            for path in sorted(self.paths):
                if path == source or path.startswith(source + "/"):
                    if path == source or not self.drop_children:
                        self.paths.add(destination + path[len(source):])
            return ["exit 0"]
        if words[:2] == ["rm", "-r"]:
            target = words[2]
            if target not in self.paths:
                return ["no_such_file", "exit 1"]
            self.paths -= {path for path in self.paths
                           if path == target or path.startswith(target + "/")}
            return ["exit 0"]
        raise StopCheck(" ".join(words))


class FakeReadConsole:
    """A fake agent port over the throwaway file the read check writes.

    write and rm are gated: each answers 75 with a challenge until the owner's
    grant is recorded, then runs once when it is sent again. bad_header answers
    a whole-file hash that is not the file's; bad_range changes the first byte
    of a range read. Each must fail the read check.
    """

    GATED = ("write", "rm")

    def __init__(self, bad_header=False, bad_range=False):
        self.bad_header = bad_header
        self.bad_range = bad_range
        self.files = {}
        self.pending = {}
        self.granted = set()
        self.asked = 0

    def exchange(self, command, body=None, token=None):
        words = command.split()
        if words[:2] == ["approval", "grant"]:
            self.granted.add(self.pending.pop(words[2]))
            return ["approval_granted %s" % words[2], "exit 0"]
        if words[0] == "write" and (body is None
                                    or len(body) != int(words[2])):
            # The console checks the upload before it asks, so a command
            # without its bytes never reaches the gate.
            return ["upload_mismatch", "exit 81"]
        if command in self.granted:
            self.granted.discard(command)
            return self.run(words, body)
        if words[0] in self.GATED:
            self.asked += 1
            approval = "a-%d" % self.asked
            self.pending[approval] = command
            return ["approval_required %s" % approval,
                    "challenge %s 00" % approval, "exit 75"]
        return self.run(words, body)

    def run(self, words, body):
        if words[0] == "stat":
            if words[1] in self.files:
                return ["%s: %d bytes" % (words[1], len(self.files[words[1]])),
                        "exit 0"]
            return ["no_such_file", "exit 1"]
        if words[0] == "write":
            self.files[words[1]] = body
            return ["exit 0"]
        if words[0] == "rm" and words[1] in self.files:
            del self.files[words[1]]
            return ["exit 0"]
        raise StopCheck(" ".join(words))

    def exchange_bytes(self, command, body=None, token=None):
        words = command.split()
        data = self.files[words[1]]
        if words[0] == "cat":
            return cat_printed(data) + b"exit 0\n"
        if words[0] == "read":
            offset, limit = (0, len(data)) if len(words) == 2 else (
                int(words[3]), int(words[5]))
            shown = min(len(data) - offset, limit)
            body = data[offset:offset + shown]
            if self.bad_range and len(words) > 2:
                body = b"x" + body[1:]
            digest = ("0" * 64 if self.bad_header
                      else hashlib.sha256(data).hexdigest())
            return (("bytes %d %s\n" % (shown, digest)).encode("ascii")
                    + body + b"exit 0\n")
        raise StopCheck(command)


def fake_console_session(console, link):
    operator = console.Operator(read=lambda prompt="": "",
                                write=lambda line="": None,
                                sleep=lambda s: None)
    return console.Session(link, operator, sleep=lambda s: None)


def scenario_console_recursive_copy_check_cleans_up(server):
    """cp -r and rm -r on the console list the copy and remove both paths, pass or fail."""
    del server  # the fake tree stands in for the console

    import console

    names = [check.__name__ for _title, check in console.CHECKS]
    assert "check_recursive_copy_and_remove" in names, (
        "console mode must check that cp -r copies and rm -r removes a tree")

    tree = FakeFileTree()
    console.check_recursive_copy_and_remove(
        fake_console_session(console, tree), None)
    assert tree.paths == set(), (
        "a passing check must leave no throwaway path, left %r" % tree.paths)

    tree = FakeFileTree(drop_children=True)
    try:
        console.check_recursive_copy_and_remove(
            fake_console_session(console, tree), None)
    except AssertionError:
        pass
    else:
        raise AssertionError("a copy that drops its entries must fail the check")
    assert tree.paths == set(), (
        "a failed check must still remove both throwaway paths, left %r"
        % tree.paths)


def scenario_console_read_check_matches_cat(server):
    """read's whole and range answers match the file the check writes and cat."""
    del server  # the fake console stands in for the agent port

    import console

    names = [check.__name__ for _title, check in console.CHECKS]
    assert "check_read_matches_cat" in names, (
        "console mode must check that read answers the bytes cat returns")

    fake = FakeReadConsole()
    console.check_read_matches_cat(fake_console_session(console, fake), None)
    assert fake.files == {}, (
        "a passing check must remove its own file, left %r" % sorted(fake.files))

    for faulty in (FakeReadConsole(bad_header=True),
                   FakeReadConsole(bad_range=True)):
        try:
            console.check_read_matches_cat(
                fake_console_session(console, faulty), None)
        except AssertionError:
            pass
        else:
            raise AssertionError(
                "a read that does not match the file must fail the check")
        assert faulty.files == {}, (
            "a failed check must still remove its own file, left %r"
            % sorted(faulty.files))


def scenario_console_gated_asks_wait_out_busy(server):
    """reboot and a sysctl write wait out approval_busy before they assert 75."""
    del server  # the scripted link stands in for the agent port

    busy = ["approval_busy", "exit 76"]
    for command in ("reboot", "sysctl kern.ostype=Other"):
        console, link, _operator, session, events, _shown = scripted_session(
            [busy, ["approval_required a-1", "challenge a-1 00", "exit 75"]])
        console.ask_without_grant(session, command)
        sent = [event for event in events if event[0] == "send"]
        assert sent == [("send", command), ("send", command)], (
            "%s must be sent again after approval_busy, sent %r"
            % (command, sent))

    console, link, _operator, session, _events, _shown = scripted_session(
        [busy, ["approval_required a-1", "challenge a-1 00", "exit 75"]])
    console.check_reboot_asks_the_owner(session, None)

    # The suite leaves approvals pending by design (no console refusal), and
    # Ariel keeps at most PENDING_MAX open until each expires; the busy
    # retries must outlast one expiry.
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    with open(os.path.join(root, "store.h")) as handle:
        expiry = int(re.search(r"#define APPROVAL_EXPIRY_MS (\d+)ULL",
                               handle.read()).group(1)) / 1000.0
    waited = console.BUSY_RETRIES * console.NOTIFICATION_SPACING
    assert waited > expiry, (
        "the busy retries wait %.0f s, less than one approval expiry (%.0f s)"
        % (waited, expiry))


def scenario_console_stale_check_installs_both_names(server):
    """The stale autoload check installs both names before it asks for either edit."""
    del server  # the fake link stands in for the agent port

    import console

    link = ActivatingLink()
    operator = console.Operator(read=lambda prompt="": "",
                                write=lambda line="": None,
                                sleep=lambda s: None)
    session = console.Session(link, operator, sleep=lambda s: None)
    context = console.Context(host="192.0.2.1", port=console.PORT,
                              token="0" * 32, workdir="/nonexistent",
                              cc=["prospero-clang"], document="quick-start.md")
    context.build = lambda label: b"\x7fELF runnable " + label.encode("ascii")
    try:
        console.check_autoload_stale_grant_answers_78(session, context)
    except Exception:  # noqa: BLE001 - the fake stops at the first autoload read
        pass
    names = [name for name, _data in link.pushes]
    assert {"consolestale", "consoleother"} <= set(names), (
        "an autoload edit of a name that is not installed answers "
        "unknown_payload before it asks; installed %r" % names)


def audit_script(later):
    """Replies for the audit check: install, two equal reads, two gated deletes, a read."""
    data = b"\x7fELF runnable audit"
    digest = hashlib.sha256(data).hexdigest()
    old = ["%d push older o-%d %s" % (1000 + i, i, "0" * 64) for i in range(61)]
    ours = ["2001 push consoleaudit s-1 %s" % digest,
            "2002 grant consoleaudit a-1 %s" % digest,
            "2003 commit consoleaudit s-1 %s" % digest]
    tail = old + ours
    gated = ["approval_required a-2", "challenge a-2 00", "exit 75"]
    replies = [
        ["staged s-1", "approval_required a-1", "challenge a-1 00", "exit 75"],
        ["approval_granted a-1", "exit 0"],
        ["installed consoleaudit %s" % digest, "exit 0"],
        tail + ["exit 0"],
        tail + ["exit 0"],
        gated,
        ["approval_busy", "exit 76"],
        later(tail) + ["exit 0"],
    ]
    return data, replies


def run_audit_check(replies, data):
    console, _link, _operator, session, _events, _shown = scripted_session(replies)
    context = console.Context(host="192.0.2.1", port=console.PORT,
                              token="0" * 32, workdir="/nonexistent",
                              cc=["prospero-clang"], document="quick-start.md")
    context.build = lambda label: data
    console.check_audit_tail(session, context)


def scenario_console_audit_check_allows_appended_lines(server):
    """The audit check accepts lines appended by the gated deletes, and nothing removed."""
    del server  # the scripted link stands in for the agent port

    # The two refused deletes are audited: the window moves on by two lines.
    data, replies = audit_script(lambda tail: tail[2:] + [
        "3001 request audit - a-2 -", "3002 refuse rm - - -"])
    run_audit_check(replies, data)

    # A line removed from the middle of the log is a cleared event.
    data, replies = audit_script(lambda tail: tail[:10] + tail[11:])
    try:
        run_audit_check(replies, data)
    except AssertionError:
        pass
    else:
        raise AssertionError("a removed audit line must fail the audit check")


def scenario_console_approval_prompts(server):
    """An approval step shows the notification and the challenge, and submits the signature."""
    del server  # the fake link stands in for the agent port

    data = b"sign me"
    digest = hashlib.sha256(data).hexdigest()
    signature = "ab" * 64
    challenge = "challenge a-4567ef90 ariel-test %s 10000 70000 %s" % (
        "00" * 16, "61".encode().hex())
    console, link, operator, session, events, shown = scripted_session([
        ["staged s-0123abcd", "approval_required a-4567ef90", challenge,
         "exit 75"],
        ["approval_granted a-4567ef90", "exit 0"],
        ["installed consolesigned %s" % digest, "exit 0"],
    ], answers=[signature])

    lines = session.push("consolesigned", data)
    staging, approval, shown_challenge = console.assert_staged(
        lines, "consolesigned", data)
    assert shown_challenge == challenge, "the challenge line must come through"
    session.request(approval, challenge, "consolesigned", len(data), digest)
    assert session.commit(staging) == [
        "installed consolesigned %s" % digest, "exit 0"], (
        "the scripted commit must answer the installation")

    notification = ("prompt %s payload consolesigned (%d bytes, sha256 %s) "
                    "will run" % (approval, len(data), digest))
    assert "The console notification should read:" in shown, (
        "the owner must be told what the console shows, showed %r" % shown)
    assert "  " + notification in shown, (
        "the step must print the notification the console shows, showed %r"
        % shown)
    assert "  " + challenge in shown, (
        "the step must print the challenge to sign, showed %r" % shown)

    sends = [event[1] for event in events if event[0] == "send"]
    waits = [i for i, event in enumerate(events) if event[0] == "wait"]
    assert len(sends) == 3 and waits, "events %r" % events
    assert "payload push consolesigned" in sends[0], (
        "the first exchange must be the push")
    assert sends[1] == "approval grant %s %s" % (approval, signature), (
        "the owner's signature must be submitted as a grant, sent %r"
        % sends[1])
    assert events.index(("send", sends[0])) < waits[0] < events.index(
        ("send", sends[1])), (
        "the grant must follow the owner's signature, events %r" % events)
    assert "payload commit" in sends[2], "the commit must follow the grant"

def scenario_test_clock_host_only(server):
    """The test clock cannot be compiled into the PS5 build."""
    del server  # this guard needs no server
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))

    # No source the PS5 target builds may mention the test clock; only the
    # host build under hostbuild/ may.
    offenders = []
    for base, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "hostbuild")]
        for name in files:
            if not name.endswith((".c", ".h")):
                continue
            path = os.path.join(base, name)
            with open(path, "r", errors="replace") as handle:
                if "testclock" in handle.read():
                    offenders.append(os.path.relpath(path, repo))
    assert not offenders, (
        "the PS5 build must not see the test clock, but these sources "
        "mention it: %r" % offenders)

    # The guard itself: without the host define the file refuses to
    # compile, and the refusal names the test clock.
    source = os.path.join(repo, "hostbuild", "testclock.c")
    compiler = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory() as scratch:
        obj = os.path.join(scratch, "testclock.o")
        denied = subprocess.run([compiler, "-c", "-o", obj, source],
                                capture_output=True, text=True)
        assert denied.returncode != 0, (
            "testclock.c must refuse to compile without ARIEL_HOST_BUILD")
        assert "the test clock is host-only" in denied.stderr, (
            "the refusal must name the guard, got %r" % denied.stderr)
        allowed = subprocess.run(
            [compiler, "-c", "-o", obj, "-DARIEL_HOST_BUILD=1", source],
            capture_output=True, text=True)
        assert allowed.returncode == 0, (
            "testclock.c must compile for the host build, got %r"
            % allowed.stderr)


def scenario_vcontroller_host_only(server):
    """The virtual controller cannot be compiled into the PS5 build."""
    del server  # this guard needs no server
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))

    # No source the PS5 target builds may mention the virtual controller;
    # only the host build under hostbuild/ may. The approval source on a
    # console is the controller the owner holds, never a listener.
    offenders = []
    for base, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "hostbuild")]
        for name in files:
            if not name.endswith((".c", ".h")):
                continue
            path = os.path.join(base, name)
            with open(path, "r", errors="replace") as handle:
                if "vcontroller" in handle.read():
                    offenders.append(os.path.relpath(path, repo))
    assert not offenders, (
        "the PS5 build must not see the virtual controller, but these "
        "sources mention it: %r" % offenders)

    # The guard itself: without the host define the file refuses to
    # compile, and the refusal names the virtual controller.
    source = os.path.join(repo, "hostbuild", "vcontroller.c")
    compiler = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory() as scratch:
        obj = os.path.join(scratch, "vcontroller.o")
        # The shared headers live at the repository root, as in the host
        # build's own include path.
        include = "-I%s" % repo
        denied = subprocess.run(
            [compiler, include, "-c", "-o", obj, source],
            capture_output=True, text=True)
        assert denied.returncode != 0, (
            "vcontroller.c must refuse to compile without ARIEL_HOST_BUILD")
        assert "the virtual controller is host-only" in denied.stderr, (
            "the refusal must name the guard, got %r" % denied.stderr)
        allowed = subprocess.run(
            [compiler, include, "-c", "-o", obj, "-DARIEL_HOST_BUILD=1",
             source],
            capture_output=True, text=True)
        assert allowed.returncode == 0, (
            "vcontroller.c must compile for the host build, got %r"
            % allowed.stderr)


def approve_push(server, name, data):
    """Push, check the prompt, approve it and return the staging ID."""
    lines = push(server, name, data)
    staging, approval = assert_staged(server, lines, name, data)
    sign_and_grant(server, approval, challenge_of(lines))
    return staging, approval


def payload_list(server):
    """Ask the agent port for the record of installed payloads."""
    sock = server.connect()
    try:
        sock.sendall(("auth %s\npayload list\n" % server.token).encode("ascii"))
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def listed(lines, name):
    """The payload list line for one name, or None when the name is absent."""
    matches = [line for line in lines if line.startswith("payload %s " % name)]
    assert len(matches) <= 1, "payload list names %s more than once: %r" % (
        name, lines)
    return matches[0] if matches else None


def expected_listing(name, hash_hex, previous_hex=None, failed=False):
    """The payload list line a push of name committed as hash_hex shows.

    Stage 1 records only a name and a hash. A push has no release, so its
    version identifiers and source say so, and nothing is running: the commit
    approved running the build, it did not start it. previous names the build
    the commit replaced, or "-" for a first build. failed is always shown,
    before previous, which stays the last field.
    """
    return ("payload %s source=push version=- release=- asset=- "
            "sha256=%s path=/data/ariel/store/objects/%s running=no "
            "failed=%s previous=%s" % (name, hash_hex, hash_hex,
                                       "yes" if failed else "no",
                                       previous_hex or "-"))


def state_path(server):
    return os.path.join(server.root, "data", "ariel", "state")


def read_state(server):
    with open(state_path(server), "rb") as fh:
        return fh.read()


def scenario_list_after_commit(server):
    """After a commit, payload list shows the payload with every field."""
    data = healthy_build("listed")
    hash_hex = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, "listed", data)
    assert commit(server, staging) == [
        "installed listed %s" % hash_hex, "exit 0"], (
        "the build must be committed before it can be listed")

    lines = payload_list(server)
    assert listed(lines, "listed") == expected_listing("listed", hash_hex), (
        "payload list must show the name, source, version identifiers, hash, "
        "path and whether it is running, got %r" % lines)


def scenario_state_survives_restart(server):
    """The state file records committed payloads, and a restart reads them back.

    Listing is read-only: the state file is the same bytes after it.
    """
    data = healthy_build("survivor")
    hash_hex = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, "survivor", data)
    assert commit(server, staging) == [
        "installed survivor %s" % hash_hex, "exit 0"], (
        "the build must be committed before it can be listed")

    before = read_state(server)
    assert listed(payload_list(server), "survivor") == expected_listing(
        "survivor", hash_hex), "the commit must be in the state file"
    assert read_state(server) == before, "payload list must not write state"

    server.restart()

    assert read_state(server) == before, (
        "a restart of Ariel must not rewrite the state file")
    assert listed(payload_list(server), "survivor") == expected_listing(
        "survivor", hash_hex), "the payload must survive a restart of Ariel"


FAKE_SERVER = """#!/bin/sh
printf 'token 00112233445566778899aabbccddeeff\\n'
sleep 1 &
exec sleep 100
"""


def scenario_restart_ignores_the_old_server_stream(server):
    """A restart reads only the new server's output, even when the old one's stream closes late.

    The stub's background child keeps the old standard output open for a
    second after the stub is stopped. That end of stream must not reach the
    queue the restarted server reads from.
    """
    del server  # the stub stands in for Ariel and needs a Server of its own
    workdir = tempfile.mkdtemp(prefix="ariel-stub-")
    try:
        stub_path = os.path.join(workdir, "ariel-stub")
        with open(stub_path, "w", encoding="ascii") as handle:
            handle.write(FAKE_SERVER)
        os.chmod(stub_path, 0o755)
        stub = Server(stub_path)
        try:
            stub.restart()
            stub.assert_no_line(timeout=2.0)
        finally:
            stub.stop()
    finally:
        shutil.rmtree(workdir)


def scenario_stage1_store_migrates_once(server):
    """A store Stage 1 wrote is migrated on the first start, and only once.

    Stage 1 kept no state file, only per-name current records. Removing the
    state file and starting again is the Stage 1 store; the first start builds
    the state file from those records, and a second start changes nothing.
    """
    data = healthy_build("stage-one-build")
    hash_hex = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, "stage1", data)
    assert commit(server, staging) == [
        "installed stage1 %s" % hash_hex, "exit 0"], (
        "the build must be committed before the store can be migrated")

    server.stop()
    os.remove(state_path(server))
    server._start()

    assert listed(payload_list(server), "stage1") == expected_listing(
        "stage1", hash_hex), (
        "the first start must build the state file from the current records")
    migrated = read_state(server)

    server.restart()

    assert read_state(server) == migrated, (
        "a second start must not change the state file")
    assert listed(payload_list(server), "stage1") == expected_listing(
        "stage1", hash_hex), "a second start must list the same payload"


def scenario_state_without_previous_starts(server):
    """A state file whose payload lines have no previous field still starts.

    Ariel once wrote payload lines with eight fields, the last being running.
    Such a payload had no previous version, so payload list shows previous=-,
    and the next save writes the ninth field.
    """
    del server  # a start that fails must not take the suite's Ariel with it
    legacy = Server(SERVER_BINARY)
    try:
        data = healthy_build("legacy")
        hash_hex = hashlib.sha256(data).hexdigest()
        install_payload(legacy, "legacy", data)

        legacy.stop()
        with open(state_path(legacy), "r") as fh:
            lines = fh.read().splitlines()
        # Keep the word "payload" and the eight fields through running, under
        # the v1 marker such a file carries.
        eight = ["ariel-state-v1"] + [" ".join(line.split(" ")[:9])
                                      for line in lines[1:]]
        with open(state_path(legacy), "w") as fh:
            fh.write("\n".join(eight) + "\n")
        legacy._start()

        assert listed(payload_list(legacy), "legacy") == expected_listing(
            "legacy", hash_hex), (
            "a state file of eight fields must list its payloads with "
            "previous=-, got %r" % payload_list(legacy))
    finally:
        legacy.stop()


def scenario_state_v1_nine_fields_loads_and_saves_as_v2(server):
    """A state file in format v1 starts and lists its payloads, and the next save writes v2.

    A v1 payload line has nine fields, the last being previous. It carries no
    timeout and no failed flag, so its payloads get the defaults.
    """
    del server  # a start that fails must not take the suite's Ariel with it
    legacy = Server(SERVER_BINARY)
    try:
        first = healthy_build("v1-first-build")
        second = healthy_build("v1-second-build")
        first_hash = hashlib.sha256(first).hexdigest()
        second_hash = hashlib.sha256(second).hexdigest()
        install_payload(legacy, "v1old", first)
        install_payload(legacy, "v1old", second)

        legacy.stop()
        with open(state_path(legacy), "r") as fh:
            lines = fh.read().splitlines()
        nine = ["ariel-state-v1"] + [" ".join(line.split(" ")[:10])
                                     for line in lines[1:]]
        with open(state_path(legacy), "w") as fh:
            fh.write("\n".join(nine) + "\n")
        legacy._start()

        assert listed(payload_list(legacy), "v1old") == expected_listing(
            "v1old", second_hash, first_hash), (
            "a v1 state file must list its payloads, got %r"
            % payload_list(legacy))

        install_payload(legacy, "v1new", healthy_build("v1-new-build"))
        saved = read_state(legacy).decode("ascii").splitlines()
        assert saved[0] == "ariel-state-v2", (
            "the next save must write format v2, wrote %r" % saved[0])
        old_line = [line for line in saved if line.startswith("payload v1old ")]
        assert old_line and old_line[0].split(" ")[-2:] == ["0", "0"], (
            "a v1 payload must be saved with the default timeout and failed "
            "flag, got %r" % old_line)
        assert listed(payload_list(legacy), "v1old") == expected_listing(
            "v1old", second_hash, first_hash), (
            "the v1 payload must list the same after the save")
    finally:
        legacy.stop()


def scenario_commit_installed(server):
    data = healthy_build("committed-build")
    staging, _ = approve_push(server, "committed", data)
    lines = commit(server, staging)
    expected = "installed committed %s" % hashlib.sha256(data).hexdigest()
    assert lines == [expected, "exit 0"], (
        "an approved commit must answer 'installed <name> <hash>' and exit 0, "
        "got %r" % lines
    )
    assert not os.path.exists(staging_path(server, staging)), (
        "a committed staging object must leave staging"
    )


def store_dir(server):
    return os.path.join(server.root, "data", "ariel", "store")


def scenario_commit_replaces(server):
    first = healthy_build("replace-first-build")
    first_hash = hashlib.sha256(first).hexdigest()
    staging, _ = approve_push(server, "replace", first)
    assert commit(server, staging) == [
        "installed replace %s" % first_hash, "exit 0"], (
        "the first build of a name must be installed"
    )

    second = healthy_build("replace-second-build")
    second_hash = hashlib.sha256(second).hexdigest()
    staging, _ = approve_push(server, "replace", second)
    assert commit(server, staging) == [
        "installed replace %s" % second_hash, "exit 0"], (
        "a new build of the same name must be installed too"
    )

    # The store is what the commit promised: the name points at the new
    # object, and the object it replaces is kept as the previous version.
    # Stage 1 deleted the replaced object here; SPEC #2 keeps it.
    with open(os.path.join(store_dir(server), "current", "replace")) as fh:
        current = fh.read().strip()
    assert current == second_hash, (
        "the current record must point at the new build, got %r" % current
    )
    objects = os.listdir(os.path.join(store_dir(server), "objects"))
    assert second_hash in objects, (
        "the new build must be in the store, it holds %r" % objects
    )
    assert first_hash in objects, (
        "the replaced build must be kept as the previous version, store "
        "holds %r" % objects
    )


def scenario_shared_build_survives_a_replacement(server):
    """A build two names share is kept while either of them still names it.

    shared-a and shared-b commit the same ELF. shared-a then moves on twice,
    and the second move would drop the shared build if nothing checked
    shared-b's record. shared-b still lists it and still runs it.
    """
    shared = compile_payload(HELLO_SOURCE, "shared")
    shared_hash = hashlib.sha256(shared).hexdigest()
    install_payload(server, "shared-a", shared)
    install_payload(server, "shared-b", shared)
    install_payload(server, "shared-a", healthy_build("shared-a-second-build"))
    install_payload(server, "shared-a", healthy_build("shared-a-third-build"))

    assert listed(payload_list(server), "shared-b") == expected_listing(
        "shared-b", shared_hash), (
        "shared-b must still list the build it committed")
    lines = run_payload(server, "shared-b")
    assert lines == [
        "Hello, world from Ariel!", "status 0", "exit 0"], (
        "shared-b must still run the build it committed, got %r" % lines)


FIRST_BUILD = healthy_build("journal-first-build")
SECOND_BUILD = healthy_build("journal-second-build")
JOURNAL_NAME = "journal"
JOURNAL_FILE = "journal"

COUNT_SOURCE = """
#include <stdio.h>

int
main(int argc, char* argv[]) {
  FILE* log;

  // With no arguments this is the one-shot health check, which must exit 0.
  if(argc < 2) {
    return 0;
  }

  // Each start appends one line, so the harness can count how often it ran.
  log = fopen(argv[1], "a");
  if(!log) {
    return 2;
  }
  if(fputs("start\\n", log) == EOF || fclose(log) != 0) {
    return 2;
  }
  return 0;
}
"""


def journal_events(server):
    """The (kind, name, sha256) of every audit line, in order."""
    events = []
    for line in read_audit_log(server).decode("ascii").splitlines():
        match = AUDIT_LINE.match(line)
        if match:
            events.append((match.group(2), match.group(3), match.group(5)))
    return events


def command_until_crash(server, command):
    """Send a command that the injected fault ends, and wait for Ariel to die."""
    sock = server.connect()
    try:
        sock.sendall(
            ("auth %s\n%s\n" % (server.token, command)).encode("ascii")
        )
        reply = reply_lines(read_reply(sock))
    except OSError:
        reply = []
    finally:
        sock.close()
    assert server.proc.wait(timeout=5.0) != 0, "the fault must end Ariel"
    return reply


def commit_until_crash(server, staging):
    return command_until_crash(server, "payload commit %s" % staging)


def crash_commit(server, step):
    """Install FIRST_BUILD, then crash the commit of SECOND_BUILD at step.

    Ariel is left stopped, with the journal as the crash left it.
    """
    install_payload(server, JOURNAL_NAME, FIRST_BUILD)
    server.env = {FAULT_ENV: step}
    server.restart()
    staging, _ = approve_push(server, JOURNAL_NAME, SECOND_BUILD)
    assert commit_until_crash(server, staging) == [], (
        "a commit that crashes must answer nothing"
    )


def crash_replacement(server, step):
    """crash_commit at step, then the restart whose recovery is under test."""
    crash_commit(server, step)
    server.env = None
    server.restart()


def scenario_crash_in_prepared_leaves_old_version(server):
    """A crash after the prepared mark rolls the replacement back on restart."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        first_hash = hashlib.sha256(FIRST_BUILD).hexdigest()
        second_hash = hashlib.sha256(SECOND_BUILD).hexdigest()
        crash_replacement(crashed, "prepared")

        assert listed(payload_list(crashed), JOURNAL_NAME) == (
            expected_listing(JOURNAL_NAME, first_hash)), (
            "a crash in prepared must leave the old version listed")
        store = store_dir(crashed)
        objects = os.listdir(os.path.join(store, "objects"))
        assert not [name for name in objects if name.startswith(second_hash)], (
            "a rolled back build must leave the store, it holds %r" % objects)
        for leftover in (os.path.join(store, "current", JOURNAL_NAME + ".tmp"),
                         os.path.join(store, JOURNAL_FILE + ".tmp"),
                         os.path.join(store, JOURNAL_FILE)):
            assert not os.path.exists(leftover), (
                "a rolled back change must leave %s behind" % leftover)
        assert ("rollback", JOURNAL_NAME, second_hash) in journal_events(crashed), (
            "the rollback must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def scenario_crash_in_committed_leaves_new_version(server):
    """A crash after the committed mark rolls the replacement forward on restart."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        first_hash = hashlib.sha256(FIRST_BUILD).hexdigest()
        second_hash = hashlib.sha256(SECOND_BUILD).hexdigest()
        crash_replacement(crashed, "committed")

        assert listed(payload_list(crashed), JOURNAL_NAME) == (
            expected_listing(JOURNAL_NAME, second_hash, first_hash)), (
            "a crash in committed must leave the new version listed")
        objects = os.listdir(os.path.join(store_dir(crashed), "objects"))
        assert second_hash in objects and first_hash in objects, (
            "the new build and its previous version must be stored, it holds %r"
            % objects)
        assert ("rollforward", JOURNAL_NAME, second_hash) in journal_events(
            crashed), (
            "the roll forward must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def scenario_committed_journal_without_its_object_is_refused(server):
    """A committed change whose new object is gone is not rolled forward.

    Recovery must not point a name at an object the store does not hold. Ariel
    refuses to start, leaves the state file as it was and audits the refusal.
    """
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        second_hash = hashlib.sha256(SECOND_BUILD).hexdigest()
        crash_commit(crashed, "committed")
        os.remove(os.path.join(store_dir(crashed), "objects",
                               second_hash + ".tmp"))
        before = read_state(crashed)

        assert crashed.start_until_exit() != 0, (
            "a committed change without its object must stop Ariel")
        assert read_state(crashed) == before, (
            "a refused recovery must not change the state file")
        assert ("rollforward_refused", JOURNAL_NAME, second_hash) in (
            journal_events(crashed)), (
            "the refused roll forward must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def scenario_recovery_crash_matches_one_crash(server):
    """A recovery killed after its renames, then a clean start, gives one crash's state.

    The first recovery is killed at renamed: the objects are renamed, the
    state record is not written and the journal still says committed. A clean
    start rolls the change forward again, so its listing, state file and audit
    log match a store that crashed only once.
    """
    del server  # each crash needs an Ariel started with the fault injector
    once = Server(SERVER_BINARY)
    twice = Server(SERVER_BINARY)
    try:
        first_hash = hashlib.sha256(FIRST_BUILD).hexdigest()
        second_hash = hashlib.sha256(SECOND_BUILD).hexdigest()

        crash_commit(once, "committed")
        once.env = None
        once.restart()

        crash_commit(twice, "committed")
        assert twice.start_until_exit({FAULT_ENV: "renamed"}) != 0, (
            "a recovery killed at renamed must end Ariel")
        twice.env = None
        twice.restart()

        assert listed(payload_list(twice), JOURNAL_NAME) == expected_listing(
            JOURNAL_NAME, second_hash, first_hash), (
            "the recovery must roll the change forward once it is run again")
        assert payload_list(twice) == payload_list(once), (
            "a recovery that crashed once must list what a single crash lists")
        assert read_state(twice) == read_state(once), (
            "a recovery that crashed once must write the state file a single "
            "crash writes")
        assert journal_events(twice) == journal_events(once), (
            "a recovery that crashed once must audit what a single crash "
            "audits, the log holds %r" % journal_events(twice))
    finally:
        once.stop()
        twice.stop()


def scenario_previous_version_is_kept_then_dropped(server):
    """The replaced build is listed as previous; the build before it is dropped."""
    del server  # the object store is read from the root, so this Ariel is its own
    history = Server(SERVER_BINARY)
    try:
        first = install_payload(history, "history", healthy_build("history-build-a"))
        second = install_payload(history, "history", healthy_build("history-build-b"))
        assert listed(payload_list(history), "history") == expected_listing(
            "history", second, first), (
            "the replaced build must be listed as previous")

        third = install_payload(history, "history", healthy_build("history-build-c"))
        assert listed(payload_list(history), "history") == expected_listing(
            "history", third, second), (
            "the newest replacement must name the build it replaced")
        objects = os.listdir(os.path.join(store_dir(history), "objects"))
        assert second in objects, (
            "the previous version must stay in the store, it holds %r" % objects)
        assert first not in objects, (
            "a build two replacements old must be dropped, it holds %r" % objects)
    finally:
        history.stop()


def rollback_request(server, name):
    """Ask for a rollback, spaced from the notification of the last request."""
    server.advance(10_000)
    return send_command(server, "payload rollback %s" % name)


def scenario_rollback_restores_the_previous_version(server):
    """A rollback answers 75 with its challenge; after a grant the previous build is current."""
    previous = install_payload(server, "rollb", healthy_build("rollback-build-a"))
    current = install_payload(server, "rollb", healthy_build("rollback-build-b"))

    lines = rollback_request(server, "rollb")
    assert len(lines) == 3 and APPROVAL_LINE.match(lines[0]) and (
        lines[2] == "exit 75"), (
        "a rollback without a grant must answer approval_required, its "
        "challenge and exit 75, got %r" % lines)
    approval = APPROVAL_LINE.match(lines[0]).group(1)

    action = action_facts(challenge_of(lines))
    for fact in ("command=payload.rollback", "target=rollb",
                 "sha256=%s" % previous, "option.replaces=%s" % current):
        assert fact in action, (
            "the signed action must name %s, got %r" % (fact, action))

    prompt = server.next_line()
    assert prompt and prompt.startswith(
        "prompt %s payload rollb rolls back to %s, replacing %s"
        % (approval, previous, current)), (
        "the owner must be shown the rollback, got %r" % prompt)

    assert send_command(server, "payload rollback rollb") == [
        "approval_required %s" % approval, "exit 75"], (
        "a rollback repeated before the decision must wait for it")

    sign_and_grant(server, approval, challenge_of(lines))
    assert send_command(server, "payload rollback rollb") == [
        "rolled_back rollb %s" % previous, "exit 0"], (
        "a granted rollback must restore the previous build")
    assert listed(payload_list(server), "rollb") == expected_listing(
        "rollb", previous, current), (
        "after the rollback the previous build must be listed as current")

    events = audit_events(server)
    assert ("request", "rollb", approval, previous) in events, (
        "the request must be audited, the log holds %r" % events)
    assert ("rollback_done", "rollb", approval, previous) in events, (
        "the completed rollback must be audited as rollback_done, the log "
        "holds %r" % events)


def scenario_rollback_without_previous_version_answers_error(server):
    """No previous version, or no such payload: an error, with no prompt."""
    install_payload(server, "rollfirst", healthy_build("first-build-only"))

    assert send_command(server, "payload rollback rollfirst") == [
        "no_previous_version", "exit 1"], (
        "a payload with no previous version must answer no_previous_version")
    assert send_command(server, "payload rollback rollnone") == [
        "unknown_payload", "exit 1"], (
        "a rollback of an unknown payload must answer unknown_payload")
    server.assert_no_line()

    events = audit_events(server)
    assert ("refuse", "rollfirst", "no_previous_version", "-") in events, (
        "the refusal must be audited, the log holds %r" % events)
    assert ("refuse", "rollnone", "unknown_payload", "-") in events, (
        "the refusal must be audited, the log holds %r" % events)


def scenario_rollback_refused_when_the_store_moved_on(server):
    """A grant for a rollback the store no longer matches answers approval_stale."""
    install_payload(server, "rollmoved", healthy_build("moved-build-a"))
    current = install_payload(server, "rollmoved", healthy_build("moved-build-b"))

    lines = rollback_request(server, "rollmoved")
    approval = APPROVAL_LINE.match(lines[0]).group(1)
    server.next_line()
    sign_and_grant(server, approval, challenge_of(lines))

    newest = install_payload(server, "rollmoved", healthy_build("moved-build-c"))
    assert send_command(server, "payload rollback rollmoved") == [
        "approval_stale", "exit 78"], (
        "a rollback whose facts changed after the grant must answer "
        "approval_stale")
    assert listed(payload_list(server), "rollmoved") == expected_listing(
        "rollmoved", newest, current), (
        "a stale rollback must leave the store as it was")
    assert ("refuse", "rollmoved", "approval_stale", "-") in audit_events(
        server), "the stale refusal must be audited"


def scenario_rollback_denied_answers_77(server):
    """A denied rollback answers approval_denied and changes nothing."""
    previous = install_payload(server, "rolldeny", healthy_build("denied-build-a"))
    current = install_payload(server, "rolldeny", healthy_build("denied-build-b"))

    lines = rollback_request(server, "rolldeny")
    approval = APPROVAL_LINE.match(lines[0]).group(1)
    server.next_line()
    server.controller("deny %s" % approval, "denied %s" % approval)

    assert send_command(server, "payload rollback rolldeny") == [
        "approval_denied", "exit 77"], (
        "a denied rollback must answer approval_denied")
    assert listed(payload_list(server), "rolldeny") == expected_listing(
        "rolldeny", current, previous), (
        "a denied rollback must leave the store as it was")
    assert ("refuse", "rolldeny", "approval_denied", "-") in audit_events(
        server), "the denial must be audited"


# More than the approval table holds, so a table that never gives rows back
# runs out during the first loop.
ROLLBACK_ROUNDS = 20


def scenario_rollbacks_give_their_approval_rows_back(server):
    """Rollbacks that end, and requests left to expire, free their rows for a push."""
    del server  # a table filled by an earlier scenario must not decide this one
    rolls = Server(SERVER_BINARY)
    try:
        rollbacks_give_rows_back(rolls)
    finally:
        rolls.stop()


def rollbacks_give_rows_back(server):
    previous = install_payload(server, "rollmany", healthy_build("many-build-a"))
    current = install_payload(server, "rollmany", healthy_build("many-build-b"))

    for i in range(ROLLBACK_ROUNDS):
        lines = rollback_request(server, "rollmany")
        assert APPROVAL_LINE.match(lines[0]), (
            "granted rollback request %d must ask for approval, got %r"
            % (i, lines))
        approval = APPROVAL_LINE.match(lines[0]).group(1)
        server.next_line()
        sign_and_grant(server, approval, challenge_of(lines))
        restored = previous if i % 2 == 0 else current
        assert send_command(server, "payload rollback rollmany") == [
            "rolled_back rollmany %s" % restored, "exit 0"], (
            "granted rollback %d must restore %s" % (i, restored))

    for i in range(ROLLBACK_ROUNDS):
        lines = rollback_request(server, "rollmany")
        assert APPROVAL_LINE.match(lines[0]), (
            "rollback request %d must ask for approval, got %r" % (i, lines))
        server.next_line()
        server.advance(120_000)

    data = b"pushed after the rollbacks"
    lines = push(server, "rollpush", data)
    assert_staged(server, lines, "rollpush", data)


def scenario_unreadable_record_answers_rollback_failed(server):
    """A record the store cannot read answers rollback_failed and keeps the grant."""
    del server  # a table filled by an earlier scenario must not decide this one
    broken = Server(SERVER_BINARY)
    try:
        previous = install_payload(broken, "rollbroken", healthy_build("broken-build-a"))
        current = install_payload(broken, "rollbroken", healthy_build("broken-build-b"))

        lines = rollback_request(broken, "rollbroken")
        approval = APPROVAL_LINE.match(lines[0]).group(1)
        broken.next_line()
        sign_and_grant(broken, approval, challenge_of(lines))

        record = os.path.join(store_dir(broken), "current", "rollbroken")
        os.remove(record)
        os.mkdir(record)
        assert send_command(broken, "payload rollback rollbroken") == [
            "rollback_failed", "exit 1"], (
            "a record that cannot be read must answer rollback_failed, not "
            "unknown_payload")

        os.rmdir(record)
        with open(record, "w") as fh:
            fh.write(current + "\n")
        assert send_command(broken, "payload rollback rollbroken") == [
            "rolled_back rollbroken %s" % previous, "exit 0"], (
            "the grant must survive the failed attempt and restore the build")
        assert ("refuse", "rollbroken", "rollback_failed", "-") in audit_events(
            broken), "the failed attempt must be audited"
    finally:
        broken.stop()


ROLLBACK_CRASH_NAME = "rollcrash"


def rollback_crash(server, step):
    """Install two builds, then crash the rollback to the first at step."""
    install_payload(server, ROLLBACK_CRASH_NAME, FIRST_BUILD)
    install_payload(server, ROLLBACK_CRASH_NAME, SECOND_BUILD)
    server.env = {FAULT_ENV: step}
    server.restart()

    lines = rollback_request(server, ROLLBACK_CRASH_NAME)
    approval = APPROVAL_LINE.match(lines[0]).group(1)
    sign_and_grant(server, approval, challenge_of(lines))
    assert command_until_crash(
        server, "payload rollback %s" % ROLLBACK_CRASH_NAME) == [], (
        "a rollback that crashes must answer nothing")


def scenario_crash_in_prepared_rolls_back_the_rollback(server):
    """A crash after the prepared mark leaves the newer build current on restart."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        first_hash = hashlib.sha256(FIRST_BUILD).hexdigest()
        second_hash = hashlib.sha256(SECOND_BUILD).hexdigest()
        rollback_crash(crashed, "prepared")
        crashed.env = None
        crashed.restart()

        assert listed(payload_list(crashed), ROLLBACK_CRASH_NAME) == (
            expected_listing(ROLLBACK_CRASH_NAME, second_hash, first_hash)), (
            "a crash in prepared must leave the newer build current")
        assert ("rollback", ROLLBACK_CRASH_NAME, first_hash) in journal_events(
            crashed), (
            "the recovered rollback must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def scenario_crash_in_committed_rolls_forward_the_rollback(server):
    """A crash after the committed mark leaves the previous build current on restart."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        first_hash = hashlib.sha256(FIRST_BUILD).hexdigest()
        second_hash = hashlib.sha256(SECOND_BUILD).hexdigest()
        rollback_crash(crashed, "committed")
        crashed.env = None
        crashed.restart()

        assert listed(payload_list(crashed), ROLLBACK_CRASH_NAME) == (
            expected_listing(ROLLBACK_CRASH_NAME, first_hash, second_hash)), (
            "a crash in committed must leave the previous build current")
        assert ("rollforward", ROLLBACK_CRASH_NAME, first_hash) in (
            journal_events(crashed)), (
            "the recovered rollback must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def starts(log):
    try:
        with open(log) as fh:
            return len(fh.readlines())
    except FileNotFoundError:
        return 0


def mark_running(server, name):
    """Edit the state file so name reads as running, as a crash could leave it."""
    marked = []
    for line in read_state(server).decode("ascii").splitlines():
        parts = line.split(" ")
        if len(parts) > 8 and parts[0] == "payload" and parts[1] == name:
            parts[8] = "1"
            line = " ".join(parts)
        marked.append(line)
    with open(state_path(server), "w") as fh:
        fh.write("\n".join(marked) + "\n")


def scenario_running_mark_does_not_restart_payload(server):
    """A payload the record marks running is not started again on restart."""
    del server  # the record is edited on disk, so this Ariel is its own
    host = Server(SERVER_BINARY)
    try:
        log = os.path.join(host.root, "starts.log")
        data = compile_payload(COUNT_SOURCE, "count")
        hash_hex = install_payload(host, "count", data)
        reply = run_payload(host, "count", [log])
        assert "exit 0" in reply, "the counting payload must run, got %r" % reply
        assert starts(log) == 1, "the run must start the payload once"

        host.stop()
        mark_running(host, "count")
        host.restart()

        assert starts(log) == 1, (
            "a restart must not start a payload the record marks running")
        assert listed(payload_list(host), "count") == expected_listing(
            "count", hash_hex), (
            "the restart must clear the running mark")
    finally:
        host.stop()


def scenario_commit_after_restart(server):
    data = b"restart me"
    staging, _ = approve_push(server, "restart", data)
    path = staging_path(server, staging)
    server.restart()
    assert commit(server, staging) == ["approval_stale", "exit 78"], (
        "an approval must not survive a restart of Ariel"
    )
    assert not os.path.exists(path), (
        "a staging object must not survive a restart of Ariel"
    )
    # The staging ID counter starts again, so a new push needs the name free.
    fresh = b"after the restart"
    lines = push(server, "restart", fresh)
    assert_staged(server, lines, "restart", fresh)


def scenario_commit_stale(server):
    data = b"original bytes"
    staging, _ = approve_push(server, "changed", data)
    path = staging_path(server, staging)
    # The telnet shell can still write to /data in Stage 1, so the object
    # behind an approval can change between the approval and the commit.
    with open(path, "wb") as handle:
        handle.write(b"tampered bytes")
    assert commit(server, staging) == ["approval_stale", "exit 78"], (
        "a staging object changed after approval must answer exit 78"
    )
    assert not os.path.exists(path), (
        "an object that no longer matches its approval must be deleted"
    )


def scenario_commit_single_use(server):
    data = healthy_build("one-use-build")
    hash_hex = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, "single", data)

    results = []
    barrier = threading.Barrier(2)

    def race():
        barrier.wait()
        results.append(commit(server, staging))

    threads = [threading.Thread(target=race) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10.0)

    installed = [r for r in results
                 if r == ["installed single %s" % hash_hex, "exit 0"]]
    stale = [r for r in results
             if r == ["approval_stale", "exit 78"]]
    assert len(results) == 2, "both commits must answer, got %r" % results
    assert len(installed) == 1, (
        "exactly one of two concurrent commits may use the approval, got %r"
        % results
    )
    assert len(stale) == 1, (
        "the other commit must answer approval_stale, got %r" % results
    )


def scenario_commit_denied(server):
    lines = push(server, "refused", b"do not keep me")
    staging, approval = assert_staged(server, lines, "refused",
                                      b"do not keep me")
    server.controller("deny %s" % approval, "denied %s" % approval)
    assert commit(server, staging) == ["approval_denied", "exit 77"], (
        "a denied commit must be terminal and answer exit 77"
    )
    assert not os.path.exists(staging_path(server, staging)), (
        "the denied staging object must be deleted"
    )
    assert ("payload.commit.denied", "refused") in [
        event[:2] for event in audit_events(server)], (
        "a denied commit must reach audit tail under its payload's name"
    )
    assert commit(server, staging) == ["approval_stale", "exit 78"], (
        "a consumed denial must not be replayed"
    )
    late = signature_of(sign_challenge(server, challenge_of(lines)))
    assert grant(server, approval, late) == ["approval_stale", "exit 78"], (
        "a signature for a denied approval whose object left must be stale"
    )


def scenario_commit_before_decision(server):
    lines = push(server, "undecided", b"wait for me")
    staging, approval = assert_staged(server, lines, "undecided", b"wait for me")
    assert commit(server, staging) == [
        "approval_required %s" % approval, "exit 75"], (
        "a commit before the decision must ask again with the same approval ID"
    )


def scenario_approval_expired(server):
    """An approval expires after 120 s of test clock."""
    server.fresh()
    data = b"too late to approve"
    lines = push(server, "expired", data)
    staging, _ = assert_staged(server, lines, "expired", data)
    server.advance(120_000)
    assert commit(server, staging) == ["approval_expired", "exit 88"], (
        "a commit after its approval expired must answer approval_expired "
        "and exit 88, so 77 stays a refusal")
    assert not os.path.exists(staging_path(server, staging)), (
        "an expired approval's staging object must be deleted")
    assert ("payload.commit.expired", "expired") in [
        event[:2] for event in audit_events(server)], (
        "an expired commit must reach audit tail under its payload's name")
    assert commit(server, staging) == ["approval_stale", "exit 78"], (
        "once its object is gone, an expired approval is only stale")


def approval_status(server, approval):
    """Ask approval status and return the lines the server answered.

    Status is a question, not an action: it carries no signature and grants
    nothing, so a scenario sends it exactly as written.
    """
    sock = server.connect()
    try:
        sock.sendall(("auth %s\napproval status %s\n"
                      % (server.token, approval)).encode("ascii"))
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def scenario_approval_status(server):
    """approval status names pending, granted, denied, expired and consumed.

    The record outlives the action it allowed, so a consumed approval still
    answers consumed, and an id Ariel never issued is an error.
    """
    server.fresh()
    data = healthy_build("statused")
    lines = push(server, "statused", data)
    staging, approval = assert_staged(server, lines, "statused", data)
    assert approval_status(server, approval) == [
        "approval_status %s pending" % approval, "exit 0"], (
        "a fresh approval must answer pending")

    sign_and_grant(server, approval, challenge_of(lines))
    assert approval_status(server, approval) == [
        "approval_status %s granted" % approval, "exit 0"], (
        "a granted approval must answer granted")

    expected = "installed statused %s" % hashlib.sha256(data).hexdigest()
    assert commit(server, staging) == [expected, "exit 0"], (
        "the granted approval must still commit the build")
    assert approval_status(server, approval) == [
        "approval_status %s consumed" % approval, "exit 0"], (
        "a consumed approval must answer consumed, not disappear")

    lines = push(server, "statuslate", b"this one expires")
    _, late = assert_staged(server, lines, "statuslate", b"this one expires")
    server.advance(120_000)
    assert approval_status(server, late) == [
        "approval_status %s expired" % late, "exit 0"], (
        "an approval past its window must answer expired")

    lines = push(server, "statusdenied", b"refused, then asked about")
    staging_refused, refused = assert_staged(
        server, lines, "statusdenied", b"refused, then asked about")
    server.controller("deny %s" % refused, "denied %s" % refused)
    assert approval_status(server, refused) == [
        "approval_status %s denied" % refused, "exit 0"], (
        "a denied approval must answer denied, not unknown_approval")
    assert commit(server, staging_refused) == ["approval_denied", "exit 77"], (
        "a denied commit must still answer approval_denied")
    assert approval_status(server, refused) == [
        "approval_status %s denied" % refused, "exit 0"], (
        "a denial must still answer denied once its staging object is gone")

    unknown = approval_status(server, "a-0")
    assert unknown == ["unknown_approval", "exit 1"], (
        "an id Ariel never issued must be an error, got %r" % unknown)


def scenario_approval_slot_reclaim(server):
    """A full approval table gives up an approval with no staged object first.

    An approval whose staged object still waits keeps its row, so the commit
    of that object answers approval_expired rather than approval_stale.
    """
    server.fresh()
    victim = b"waits in staging after its window closed"
    lines = push(server, "victim", victim)
    victim_staging, victim_approval = assert_staged(
        server, lines, "victim", victim)
    server.advance(120_000)

    # Fifteen approvals, each denied and committed, fill the table beside the
    # expired one. A committed denial leaves no staged object behind.
    for i in range(15):
        data = b"filler %d" % i
        name = "filler%d" % i
        lines = push(server, name, data)
        staging, approval = assert_staged(server, lines, name, data)
        server.controller("deny %s" % approval, "denied %s" % approval)
        assert commit(server, staging) == ["approval_denied", "exit 77"], (
            "a denied filler must answer approval_denied")

    # The table is full, so this request has to give up one row.
    data = b"needs a slot"
    lines = push(server, "needslot", data)
    assert_staged(server, lines, "needslot", data)

    assert commit(server, victim_staging) == ["approval_expired", "exit 88"], (
        "an expired approval whose staged object waits must keep its row, so "
        "its commit answers approval_expired, not approval_stale")
    assert approval_status(server, victim_approval) == [
        "approval_status %s expired" % victim_approval, "exit 0"], (
        "the expired approval must still answer expired")


def scenario_challenge_fields(server):
    """The challenge names each fact of the approval in canonical form."""
    server.fresh()
    data = b"every fact of the action"
    lines = push(server, "fields", data)
    assert_staged(server, lines, "fields", data)
    expected = ("ariel-action-v1\n"
                "command=payload.commit\n"
                "target=fields\n"
                "sha256=%s\n"
                "option.run=1\n"
                "option.size=%d\n"
                % (hashlib.sha256(data).hexdigest(), len(data)))
    assert challenge_action(challenge_of(lines)) == expected, (
        "the challenge must name the command, target, hash, size and run, "
        "got %r" % challenge_action(challenge_of(lines)))


def scenario_expired_not_pending(server):
    """An expired approval does not count among the pending ones."""
    server.fresh()
    for i in range(3):
        data = b"pending %d" % i
        name = "pnd%d" % i
        lines = push(server, name, data)
        assert_staged(server, lines, name, data)

    lines = push(server, "pnd3", b"one too many")
    assert lines == ["approval_busy", "exit 76"], (
        "a fourth pending approval must answer approval_busy and exit 76")
    server.assert_no_line()

    server.advance(120_000)

    data = b"the expired ones no longer count"
    lines = push(server, "pnd4", data)
    assert_staged(server, lines, "pnd4", data)


def scenario_missing_auth(server):
    sock = server.connect()
    try:
        sock.shutdown(socket.SHUT_WR)
        assert_exit_only(read_reply(sock), 70)
    finally:
        sock.close()


def scenario_auth_deadline(server):
    """No auth line: the clock alone closes the connection, at 5 s."""
    sock = server.connect()
    try:
        server.settle(1)
        server.advance(4_999)
        server.settle(1)
        assert_open(sock, "1 ms before the auth deadline")

        server.advance(1)
        server.settle(1)
        sock.settimeout(1.0)
        assert_exit_only(read_reply(sock), 70)
    finally:
        sock.close()


def assert_closed(sock):
    """The server closed without a reply. Bytes still in flight may reset it."""
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except ConnectionResetError:
        pass
    assert data == b"", "expected a close with no reply, got %r" % data


def scenario_line_limit(server):
    """A command line is at most 4 KiB; an auth line has its own short limit."""
    sock = server.connect()
    try:
        sock.sendall(b"auth " + b"0" * 1100 + b"\n")
        assert_closed(sock)
    finally:
        sock.close()

    # Exactly 4 KiB is still a line: an unknown command, not a close.
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n" % server.token).encode("ascii") +
                     b"a" * 4096 + b"\n")
        assert_unknown(read_reply(sock))
    finally:
        sock.close()

    # One byte past the limit answers too_many_arguments and closes.
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n" % server.token).encode("ascii") +
                     b"a" * 4097 + b"\n")
        assert read_reply(sock) == "too_many_arguments\nexit 1\n", (
            "a line over 4 KiB must answer too_many_arguments and exit 1")
    finally:
        sock.close()


def run_command_bytes(server, command):
    """One command of raw bytes on its own connection; the reply as lines."""
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n" % server.token).encode("ascii") +
                     command + b"\n")
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def scenario_quoted_path_runs(server):
    """Quotes group a token and are removed; no byte is globbed or expanded."""
    folder = scratch_dir(server)
    spaced = os.path.join(folder, "a file.txt")
    with open(spaced, "wb") as handle:
        handle.write(b"quoted\n")
    assert run_command(server, 'cat "%s"' % spaced) == ["quoted", "exit 0"], (
        "a double-quoted path with a space must be addressable")
    assert run_command(server, "cat '%s'" % spaced) == ["quoted", "exit 0"], (
        "a single-quoted path with a space must be addressable")

    quoted = os.path.join(folder, 'a"b.txt')
    with open(quoted, "wb") as handle:
        handle.write(b"quote\n")
    escaped = quoted.replace("\\", "\\\\").replace('"', '\\"')
    assert run_command(server, 'cat "%s"' % escaped) == ["quote", "exit 0"], (
        "a double quote inside double quotes must be escaped")

    slashed = os.path.join(folder, "a\\b.txt")
    with open(slashed, "wb") as handle:
        handle.write(b"slash\n")
    escaped = slashed.replace("\\", "\\\\").replace('"', '\\"')
    assert run_command(server, 'cat "%s"' % escaped) == ["slash", "exit 0"], (
        "a backslash inside double quotes must be escaped")

    assert run_command(server, "echo *") == ["*", "exit 0"], (
        "a * is a literal byte, never a glob")
    assert run_command(server, 'echo "a b" \'c d\'') == [
        "a b c d", "exit 0"], "each quoted token must stay one token"


def scenario_dangling_quote_is_refused(server):
    """An unbalanced quote answers bad_quoting before anything runs."""
    for command in ('cat "unterminated', "cat 'unterminated"):
        assert run_command(server, command) == ["bad_quoting", "exit 1"], (
            "%r must answer bad_quoting and exit 1" % command)
    # A backslash is an ordinary byte outside double quotes and in single
    # quotes: only \" and \\ inside double quotes escape.
    assert run_command(server, "echo a\\b") == ["a\\b", "exit 0"], (
        "a backslash outside quotes must be literal")
    assert run_command(server, "echo 'a\\b'") == ["a\\b", "exit 0"], (
        "a backslash in single quotes must be literal")


def scenario_token_count_is_bounded(server):
    """64 tokens are a command; a 65th answers too_many_arguments."""
    args = ["a%d" % i for i in range(63)]
    assert run_command(server, "echo " + " ".join(args)) == [
        " ".join(args), "exit 0"], "64 tokens must still be one command"
    args.append("a63")
    assert run_command(server, "echo " + " ".join(args)) == [
        "too_many_arguments", "exit 1"], (
        "a 65th token must answer too_many_arguments and exit 1")


def scenario_non_printable_gated_target_answers_bad_path(server):
    """A target outside printable ASCII answers bad_path and asks nothing."""
    base = os.path.join(server.root, "data", "badpath").encode("ascii")
    for what, bad in (("Unicode", b"\xc3\xa9"),
                      ("combining mark", b"\xcc\x81"),
                      ("right-to-left override", b"\xe2\x80\xae"),
                      ("DEL", b"\x7f")):
        lines = run_command_bytes(server, b'mkdir "' + base + b"/" + bad + b'"')
        assert lines == ["bad_path", "exit 1"], (
            "a %s in a gated target must answer bad_path, got %r"
            % (what, lines))
        server.assert_no_line()


def scenario_quoted_path_is_escaped_and_signed(server):
    """A quoted path is %XX-escaped in the action and decoded by the signer."""
    server.advance(120000)
    folder = os.path.join(server.root, "data", "quote dir")
    approval, challenge = gate_request(server, 'mkdir "%s"' % folder)
    action = challenge_action(challenge)
    assert "\ntarget=%s\n" % escape_value(folder) in action, (
        "a space in the signed target must be escaped as %%20, got %r" % action)
    assert "target=%s\n" % folder in decoded_action(action), (
        "the owner must read the decoded path")
    # sign_challenge asserts the signer prints the decoded action.
    sign_and_grant(server, approval, challenge)
    assert run_command(server, 'mkdir "%s"' % folder) == ["exit 0"], (
        "a quoted path granted by the owner must run")
    assert os.path.isdir(folder), "the quoted directory must exist"


def scenario_a_slow_command_times_out(server):
    """A command still running at the 60 s deadline answers timed_out."""
    server.advance(120000)
    sock = server.connect(timeout=10.0)
    try:
        sock.sendall(("auth %s\n" % server.token).encode("ascii"))
        server.settle(1)
        # Half of the connection's deadline goes by before the command is
        # sent, so the sleep's own 60 s ceiling ends 30 s after the
        # connection deadline: only the watchdog can fire on the next step,
        # whatever order two waiters due at once would wake in.
        server.advance(30000)
        sock.sendall(b"sleep 60\n")
        server.settle(1)
        server.advance(30000)
        assert reply_lines(read_reply(sock)) == ["timed_out", "exit 1"], (
            "a command past the connection deadline must answer timed_out")
    finally:
        sock.close()


def scenario_legacy_commands_name_their_error(server):
    """Commands that predate Stage 1 answer a named word and its exit."""
    cases = (
        ("cd /", "no_working_directory"),
        ("ls relative", "relative_path"),
        ("ls /ariel-no-such-path", "no_such_file"),
        ("cat relative", "relative_path"),
        ("cat /ariel-no-such-path", "no_such_file"),
        ("stat /ariel-no-such-path", "no_such_file"),
        ("file /ariel-no-such-path", "no_such_file"),
        ("grep . /ariel-no-such-path", "no_such_file"),
        ("find /ariel-no-such-path", "no_such_file"),
        ("cmp /ariel-no-such-path /ariel-other", "no_such_file"),
        ("hexdump /ariel-no-such-path", "no_such_file"),
        ("df /ariel-no-such-path", "no_such_file"),
        ("sha256sum /ariel-no-such-path", "no_such_file"),
        ("sum /ariel-no-such-path", "no_such_file"),
        ("sfoinfo /ariel-no-such-path", "no_such_file"),
        ("sleep soon", "bad_duration"),
        ("procstat not-a-pid", "not_a_pid"),
        ("sysctl", "missing_operand"),
    )
    for command, word in cases:
        lines = run_command(server, command)
        assert lines == [word, "exit 1"], (
            "%r must answer %r and exit 1, got %r" % (command, word, lines))


BIG_LISTING = 3000
CAP_BYTES = 64 * 1024


def run_command_raw(server, command):
    """One command on its own connection; the reply exactly as sent."""
    sock = server.connect(timeout=10.0)
    try:
        sock.sendall(("auth %s\n%s\n" % (server.token, command)).encode("ascii"))
        return read_reply(sock)
    finally:
        sock.close()


def cut_answer(raw):
    """The body, shown count and total of a cut answer that ends with exit 0."""
    match = re.search(r"truncated (\d+) of (\d+)\nexit 0\n\Z", raw)
    assert match, "a cut answer must end with truncated and exit 0, got %r" % raw[-80:]
    assert len(raw.encode("ascii")) <= CAP_BYTES, (
        "an answer holds at most 64 KiB, the marker included")
    body = raw[:match.start()].splitlines()
    return body, int(match.group(1)), int(match.group(2))


def make_listing(server, name, count):
    folder = os.path.join(scratch_dir(server), name)
    os.makedirs(folder, exist_ok=True)
    names = sorted("entry-%05d-%s" % (i, "x" * 40) for i in range(count))
    for entry in names:
        open(os.path.join(folder, entry), "w").close()
    return folder, names


def scenario_a_large_listing_is_cut(server):
    """ls and find cut a listing over 64 KiB, say how much they showed, and exit 0."""
    folder, names = make_listing(server, "listing", BIG_LISTING)

    body, shown, total = cut_answer(run_command_raw(server, "ls " + folder))
    assert total == BIG_LISTING and 0 < shown < BIG_LISTING, (
        "ls must cut a listing over 64 KiB, got shown %d of %d" % (shown, total))
    assert body == names[:shown], "a cut listing shows the first names in order"

    assert run_command(server, "ls --limit 5 " + folder) == (
        names[:5] + ["truncated 5 of %d" % BIG_LISTING, "exit 0"]), (
        "ls --limit 5 must show five names and say how many there are")

    body, shown, total = cut_answer(run_command_raw(server, "find " + folder))
    assert body[0] == folder and total == BIG_LISTING + 1 and len(body) == shown, (
        "find must cut its tree, root line first, got shown %d of %d" % (shown, total))

    lines = run_command(server, "find --limit 3 " + folder)
    assert len(lines) == 5 and lines[0] == folder and lines[3:] == [
        "truncated 3 of %d" % (BIG_LISTING + 1), "exit 0"], (
        "find --limit 3 must show three lines and say how many there are")


def scenario_a_small_listing_keeps_its_shape(server):
    """A directory under the cap answers its entries and exit 0, with no marker."""
    folder, names = make_listing(server, "small", 2)
    assert run_command(server, "ls " + folder) == names + ["exit 0"], (
        "a listing under the cap must keep its shape")


def scenario_a_large_file_is_cut(server):
    """cat cuts a file over 64 KiB; head, tail and wc read the same file in full."""
    data = b"".join(b"line %06d %s\n" % (i, b"y" * 20) for i in range(8000))
    path = write_scratch(server, "large.txt", data)
    text = data.decode("ascii")
    lines = text.splitlines()

    raw = run_command_raw(server, "cat " + path)
    match = re.search(r"truncated (\d+) of (\d+)\nexit 0\n\Z", raw)
    assert match and int(match.group(2)) == len(data), (
        "cat must cut a file over 64 KiB and say its size, got %r" % raw[-60:])
    shown = int(match.group(1))
    assert 0 < shown < len(data), "cat must show part of the file"
    content = raw[:match.start()]
    assert content in (text[:shown], text[:shown] + "\n"), (
        "a cut cat shows the first bytes of the file, then a line end")
    assert len(raw.encode("ascii")) <= CAP_BYTES, "an answer holds at most 64 KiB"

    assert run_command(server, "head 3 " + path) == (
        lines[:3] + ["truncated 3 of 8000", "exit 0"]), (
        "head 3 must show three lines and say how many there are")
    assert run_command(server, "head " + path) == (
        lines[:10] + ["truncated 10 of 8000", "exit 0"]), (
        "head with no count must show ten lines")
    assert run_command(server, "tail 2 " + path) == (
        lines[-2:] + ["truncated 2 of 8000", "exit 0"]), (
        "tail 2 must show the last two lines and say how many there are")
    assert run_command(server, "wc " + path) == [
        "%d %d %d %s" % (data.count(b"\n"), len(data.split()), len(data), path),
        "exit 0"], "wc must count the whole file"

    small = write_scratch(server, "small.txt", b"one\ntwo\nthree\n")
    assert run_command(server, "head 10 " + small) == [
        "one", "two", "three", "exit 0"], "head under the cap keeps its shape"
    assert run_command(server, "tail 3 " + small) == [
        "one", "two", "three", "exit 0"], "tail under the cap keeps its shape"
    assert run_command(server, "tail 2 " + small) == [
        "two", "three", "truncated 2 of 3", "exit 0"], (
        "tail that omits a line must say how many there are")
    assert run_command(server, "wc " + small) == [
        "3 3 14 " + small, "exit 0"], "wc must count the small file"
    assert run_command(server, "head x " + small) == [
        "bad_argument", "exit 1"], "head takes a whole count"
    assert run_command(server, "head %s 2" % small) == [
        "bad_argument", "exit 1"], "head takes the count before the path"
    assert run_command(server, "tail %s 2" % small) == [
        "bad_argument", "exit 1"], "tail takes the count before the path"


def scenario_a_grep_with_many_matches_is_cut(server):
    """grep cuts a run of matches over 64 KiB and --limit cuts it sooner."""
    data = b"".join(b"match %05d\n" % i for i in range(10000)) + b"other\n"
    path = write_scratch(server, "matches.txt", data)

    body, shown, total = cut_answer(run_command_raw(server, "grep match " + path))
    assert total == 10000 and 0 < shown < 10000, (
        "grep must cut many matches, got shown %d of %d" % (shown, total))
    assert body == ["match %05d" % i for i in range(shown)], (
        "a cut grep shows the first matches in order")

    assert run_command(server, "grep --limit 2 match " + path) == [
        "match 00000", "match 00001", "truncated 2 of 10000", "exit 0"], (
        "grep --limit 2 must show two matches and say how many there are")
    assert run_command(server, "grep 0000[0-2] " + path) == [
        "match 00000", "match 00001", "match 00002", "exit 0"], (
        "grep with few matches must keep its shape")


def scenario_a_limit_of_zero_shows_nothing(server):
    """A limit of zero shows no line and still says how many there are."""
    folder, _names = make_listing(server, "zero", 3)
    assert run_command(server, "ls --limit 0 " + folder) == [
        "truncated 0 of 3", "exit 0"], "ls --limit 0 must show no name"
    assert run_command(server, "find --limit 0 " + folder) == [
        "truncated 0 of 4", "exit 0"], "find --limit 0 must show no line"

    data = b"0123456789" * 10
    path = write_scratch(server, "zero.txt", data)
    assert run_command(server, "cat --limit 0 " + path) == [
        "truncated 0 of 100", "exit 0"], "cat --limit 0 must show no byte"
    assert run_command(server, "grep --limit 0 0 " + path) == [
        "truncated 0 of 1", "exit 0"], "grep --limit 0 must show no match"

    empty = os.path.join(scratch_dir(server), "empty")
    os.makedirs(empty, exist_ok=True)
    assert run_command(server, "ls --limit 0 " + empty) == ["exit 0"], (
        "an empty directory has nothing to cut, so no marker")
    assert run_command(server, "ls --limit many " + folder) == [
        "bad_option", "exit 1"], "a limit that is not a whole number is bad_option"


DATE_LINE = re.compile(r"^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d) UTC$")
SYSINFO_KEYS = {"sysname", "release", "machine", "uptime_seconds",
                "memory_total_bytes", "memory_free_bytes"}


def host_uptime_seconds():
    """The host's uptime as it stands now, read without Ariel."""
    if platform.system() == "Darwin":
        out = subprocess.check_output(["sysctl", "-n", "kern.boottime"])
        match = re.search(r"sec = (\d+)", out.decode("ascii"))
        assert match, "kern.boottime must carry a sec field, got %r" % out
        return int(time.time()) - int(match.group(1))
    with open("/proc/uptime") as file:
        return int(float(file.read().split()[0]))


def host_memory_total_bytes():
    """The host's total memory, read without Ariel."""
    if platform.system() == "Darwin":
        out = subprocess.check_output(["sysctl", "-n", "hw.memsize"])
        return int(out.strip())
    with open("/proc/meminfo") as file:
        for line in file:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    raise AssertionError("MemTotal is absent from /proc/meminfo")


def scenario_date_answers_the_wall_clock(server):
    """date answers one UTC line that matches the host's clock, and takes no operand."""
    lines = run_command(server, "date")
    assert len(lines) == 2 and lines[1] == "exit 0", (
        "date must answer one line and exit 0, got %r" % lines)
    match = DATE_LINE.match(lines[0])
    assert match, "date must answer YYYY-MM-DD HH:MM:SS UTC, got %r" % lines[0]
    shown = datetime.datetime(
        *[int(part) for part in match.groups()],
        tzinfo=datetime.timezone.utc).timestamp()
    assert abs(shown - time.time()) < 120, (
        "date must answer the wall clock, got %r" % lines[0])

    assert run_command(server, "date now") == ["bad_argument", "exit 1"], (
        "date takes no operand")
    assert run_command(server, "date --json") == ["bad_option", "exit 1"], (
        "date has no JSON form")


def scenario_du_totals_a_tree(server):
    """du totals each directory's regular files, children before their parent."""
    folder = os.path.join(scratch_dir(server), "du")
    sub = os.path.join(folder, "sub")
    empty = os.path.join(folder, "empty")
    os.makedirs(sub)
    os.makedirs(empty)
    with open(os.path.join(folder, "a.txt"), "wb") as file:
        file.write(b"12345")
    with open(os.path.join(sub, "b.txt"), "wb") as file:
        file.write(b"abc")

    assert run_command(server, "du " + folder) == [
        "0 " + empty, "3 " + sub, "8 " + folder, "exit 0"], (
        "du must total each directory, children first, and the root last")

    path = os.path.join(folder, "a.txt")
    assert run_command(server, "du " + path) == ["5 " + path, "exit 0"], (
        "du of a regular file answers its own size")

    assert run_command(server, "du " + os.path.join(folder, "nope")) == [
        "no_such_file", "exit 1"], "du of a missing path names the word"
    assert run_command(server, "du relative") == ["relative_path", "exit 1"], (
        "du takes an absolute path")
    assert run_command(server, "du " + folder + " " + sub) == [
        "bad_argument", "exit 1"], "du takes one path"
    assert run_command(server, "du -s " + folder) == ["bad_option", "exit 1"], (
        "du takes no option")


def scenario_du_is_cut_past_the_cap(server):
    """du over more directories than 64 KiB holds is cut, and still exits 0."""
    folder = os.path.join(scratch_dir(server), "du-big")
    os.makedirs(folder)
    count = 3000
    names = ["d-%05d-%s" % (i, "z" * 40) for i in range(count)]
    for name in names:
        os.makedirs(os.path.join(folder, name))

    body, shown, total = cut_answer(run_command_raw(server, "du " + folder))
    assert total == count + 1, (
        "du must count every directory and the root, got %d" % total)
    assert 0 < shown < count + 1, (
        "du must cut a walk over 64 KiB, got shown %d of %d" % (shown, total))
    assert body == ["0 " + os.path.join(folder, name) for name in names[:shown]], (
        "a cut du shows the first directories in sorted order")


def scenario_dmesg_names_the_platform_refusal(server):
    """The host cannot read a kernel log, so dmesg names that rather than answer empty."""
    assert run_command(server, "dmesg") == [
        "not available on this platform", "exit 1"], (
        "the host build must refuse dmesg by name")
    assert run_command(server, "dmesg -c") == ["bad_option", "exit 1"], (
        "dmesg takes no option")
    assert run_command(server, "dmesg now") == ["bad_argument", "exit 1"], (
        "dmesg takes no operand")


def scenario_sysinfo_aggregates_the_machine(server):
    """sysinfo answers uname, uptime and memory, plainly and as one JSON object."""
    lines = run_command(server, "sysinfo")
    assert len(lines) == 4 and lines[3] == "exit 0", (
        "sysinfo must answer three lines and exit 0, got %r" % lines)

    uname = lines[0].split(" ")
    assert uname[0] == "uname" and len(uname) == 4 and all(uname[1:]), (
        "sysinfo must name the sysname, release and machine, got %r" % lines[0])
    expected = platform.uname()
    assert uname[1] == expected.system, (
        "sysinfo must report the host's sysname, got %r" % uname[1])
    assert uname[2] == expected.release, (
        "sysinfo must report the host's release, got %r" % uname[2])
    assert uname[3] == expected.machine, (
        "sysinfo must report the host's machine, got %r" % uname[3])

    uptime = lines[1].split(" ")
    assert uptime[0] == "uptime" and len(uptime) == 2 and uptime[1].isdigit(), (
        "sysinfo must answer uptime in seconds, got %r" % lines[1])
    assert abs(int(uptime[1]) - host_uptime_seconds()) < 300, (
        "sysinfo's uptime must match the host's, got %r" % lines[1])

    memory = lines[2].split(" ")
    assert memory[0] == "memory" and len(memory) == 3, (
        "sysinfo must answer total and free memory, got %r" % lines[2])
    assert memory[1].isdigit() and memory[2].isdigit(), (
        "memory figures must be whole bytes, got %r" % lines[2])
    total, free = int(memory[1]), int(memory[2])
    assert total == host_memory_total_bytes(), (
        "sysinfo's total memory must match the host's, got %d" % total)
    assert 0 < free <= total, "free memory must be within the total, got %d" % free

    raw = run_command_raw(server, "sysinfo --json")
    assert raw.endswith("exit 0\n"), (
        "a JSON answer ends with the exit line, got %r" % raw[-40:])
    objects = raw[:-len("exit 0\n")].splitlines()
    assert len(objects) == 1, (
        "sysinfo --json answers exactly one object, got %r" % objects)
    info = json.loads(objects[0])
    assert set(info) == SYSINFO_KEYS, (
        "the JSON keys are stable, got %r" % sorted(info))
    assert [info["sysname"], info["release"], info["machine"]] == uname[1:], (
        "the JSON uname fields must match the plain answer")
    assert abs(info["uptime_seconds"] - int(uptime[1])) <= 5, (
        "the JSON uptime must match the plain answer")
    assert info["memory_total_bytes"] == total, (
        "the JSON total memory must match the plain answer")
    assert abs(info["memory_free_bytes"] - free) <= total // 10, (
        "the JSON free memory must match the plain answer")
    assert len(raw.encode("ascii")) <= CAP_BYTES, "an answer holds at most 64 KiB"

    assert run_command(server, "sysinfo extra") == ["bad_argument", "exit 1"], (
        "sysinfo takes no operand")
    assert run_command(server, "sysinfo --limit 2") == ["bad_option", "exit 1"], (
        "sysinfo takes no option but --json")


def scenario_wrong_token(server):
    wrong = "0" * 32 if server.token != "0" * 32 else "1" * 32
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n" % wrong).encode("ascii"))
        assert_exit_only(read_reply(sock), 70)
    finally:
        sock.close()


def assert_unlisted_gated(server, command):
    """A command outside the allowlist asks the owner (75) or waits out the gap (76)."""
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n%s\n" % (server.token, command)).encode("ascii"))
        lines = reply_lines(read_reply(sock))
    finally:
        sock.close()
    assert lines[-1] in ("exit 75", "exit 76") and lines[0] != (
        "unknown_command"), (
        "%r must be gated, answered %r" % (command, lines))
    if lines[-1] == "exit 75":
        assert APPROVAL_LINE.match(lines[0]), (
            "%r must name its approval, got %r" % (command, lines))
        server.next_line()


def scenario_unknown_command(server):
    """A command outside the allowlist is gated, never answered unknown_command.

    Nothing implements these, so the owner is asked first; the notification
    gap holds the second and third without a clock move, answering 76.
    """
    # payload run <name> is a Stage 2 command from #26 on, so it is not a probe.
    for command in (
        "payload stop helloworld",
        "payload status",
        "nonsense",
    ):
        sock = server.connect()
        try:
            sock.sendall(
                ("auth %s\n%s\n" % (server.token, command)).encode("ascii")
            )
            lines = reply_lines(read_reply(sock))
        finally:
            sock.close()
        assert lines[-1] in ("exit 75", "exit 76") and lines[0] != (
            "unknown_command"), (
            "%r must be gated, answered %r" % (command, lines))
        if lines[-1] == "exit 75":
            assert APPROVAL_LINE.match(lines[0]), (
                "%r must name its approval, got %r" % (command, lines))
            server.next_line()


def run_command(server, command, timeout=5.0):
    """One command on its own connection; the reply as lines."""
    sock = server.connect(timeout=timeout)
    try:
        sock.sendall(
            ("auth %s\n%s\n" % (server.token, command)).encode("ascii")
        )
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def scenario_pwd_and_ls(server):
    """A connection has no working directory, so pwd answers the root."""
    lines = run_command(server, "pwd")
    assert lines == ["/", "exit 0"], "pwd must answer '/', got %r" % lines
    lines = run_command(server, "ls /")
    assert lines[-1] == "exit 0" and len(lines) > 1, (
        "ls / must list entries then exit 0, got %r" % lines
    )
    lines = run_command(server, "ls /ariel-no-such-path")
    assert lines[-1] == "exit 1" and len(lines) > 1, (
        "ls of a missing path must explain and exit 1, got %r" % lines
    )
    lines = run_command(server, "ls relative")
    assert lines == ["relative_path", "exit 1"], (
        "ls of a relative path must be refused, got %r" % lines
    )


def scenario_cd_is_an_error(server):
    for command in ("cd /", "cd"):
        lines = run_command(server, command)
        assert lines == ["no_working_directory", "exit 1"], (
            "%r must answer no_working_directory, got %r" % (command, lines)
        )


# Every command that opens a secret's contents or its metadata. ls, find and df
# only list names or space, so they are not protected reads.
SECRET_NAMES = ("token", "approvals", "nonces")
SECRET_READS = (
    "cat {p}",
    "stat {p}",
    "file {p}",
    "grep . {p}",
    "hexdump {p}",
    "sha256sum {p}",
    "read {p}",
    "cmp {p} {p}",
)


def scratch_dir(server):
    path = os.path.join(server.root, "readonly")
    os.makedirs(path, exist_ok=True)
    return path


def write_scratch(server, name, data):
    path = os.path.join(scratch_dir(server), name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def secret_path(server, name):
    path = os.path.join(server.root, "data", "ariel", name)
    assert os.path.exists(path), (
        "Ariel must keep its %s file at %s" % (name, path))
    return path


def make_link(path, target, hard):
    if os.path.lexists(path):
        os.unlink(path)
    if hard:
        os.link(target, path)
    else:
        os.symlink(target, path)


def run_exit_zero(server, command):
    """The output lines of a command that must exit 0, without the exit line."""
    lines = run_command(server, command)
    assert lines and lines[-1] == "exit 0", (
        "%s must exit 0, got %r" % (command, lines))
    return lines[:-1]


def assert_protected(server, command):
    lines = run_command(server, command)
    assert lines == ["protected", "exit 87"], (
        "%s must answer protected and exit 87, got %r" % (command, lines))


def scenario_read_only_commands(server):
    """Each read-only command runs with no approval and exits 0 with its output."""
    notes = write_scratch(server, "notes.txt", b"hello\nworld\n")
    copy = write_scratch(server, "copy.txt", b"hello\nworld\n")
    differ = write_scratch(server, "differ.txt", b"hello\nWorld\n")
    folder = scratch_dir(server)

    assert "notes.txt" in run_exit_zero(server, "ls " + folder), (
        "ls must list notes.txt")
    assert run_exit_zero(server, "stat " + notes), "stat must describe the file"
    assert run_exit_zero(server, "file " + notes), "file must name the type"
    assert run_exit_zero(server, "cat " + notes) == ["hello", "world"], (
        "cat must print the file's lines")
    assert run_exit_zero(server, "grep world " + notes) == ["world"], (
        "grep must print the matching line")
    lines = run_command(server, "grep absent " + notes)
    assert lines == ["exit 1"], (
        "grep with no match must exit 1 and print nothing, got %r" % lines)
    found = set(run_exit_zero(server, "find " + folder))
    assert {folder, notes, copy} <= found, (
        "find must list the directory and its files, got %r" % sorted(found))
    assert run_exit_zero(server, "cmp %s %s" % (notes, copy)) == [], (
        "cmp of equal files must print nothing")
    lines = run_command(server, "cmp %s %s" % (notes, differ))
    assert lines[-1] == "exit 1", (
        "cmp of different files must exit 1, got %r" % lines)
    assert any("68 65 6c 6c 6f" in line
               for line in run_exit_zero(server, "hexdump " + notes)), (
        "hexdump must show the bytes of hello")
    assert run_exit_zero(server, "df " + folder), "df must describe the space"


def scenario_read_only_relative_paths(server):
    """A connection has no working directory, so every path must be absolute."""
    for command in ("cat notes.txt", "stat notes.txt", "file notes.txt",
                    "grep world notes.txt", "find notes.txt",
                    "cmp a.txt b.txt", "hexdump notes.txt", "df notes.txt",
                    "sha256sum notes.txt", "read notes.txt"):
        lines = run_command(server, command)
        assert lines == ["relative_path", "exit 1"], (
            "%r must refuse a relative path, got %r" % (command, lines))


def scenario_sha256sum_matches_openssl(server):
    """sha256sum prints the digest that openssl dgst -sha256 prints on the host."""
    data = bytes(range(256)) * 300
    path = write_scratch(server, "digest.bin", data)
    lines = run_exit_zero(server, "sha256sum " + path)
    assert lines, "sha256sum must print a digest line"
    digest = lines[0].split()[0]
    done = subprocess.run(["openssl", "dgst", "-sha256", path],
                          capture_output=True, text=True)
    assert done.returncode == 0, "openssl dgst failed: %s" % done.stderr
    expected = done.stdout.strip().rsplit("= ", 1)[-1]
    assert digest == expected, (
        "sha256sum must match openssl dgst -sha256: got %s, want %s"
        % (digest, expected))


READ_CAP = 64 * 1024


def read_raw(server, command):
    """One command on its own connection; the reply as bytes, binary intact."""
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n%s\n" % (server.token, command)).encode("ascii"))
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return data
            data += chunk
    finally:
        sock.close()


def split_read(reply):
    """The size, hash, body and trailing lines of one read answer."""
    head, sep, rest = reply.partition(b"\n")
    assert sep, "read must answer a header line, got %r" % reply[:80]
    fields = head.decode("ascii").split(" ")
    assert len(fields) == 3 and fields[0] == "bytes", (
        "read's header must be 'bytes <size> <sha256>', got %r" % head)
    size, digest = int(fields[1]), fields[2]
    return size, digest, rest[:size], rest[size:]


def openssl_sha256(path):
    done = subprocess.run(["openssl", "dgst", "-sha256", path],
                          capture_output=True, text=True)
    assert done.returncode == 0, "openssl dgst failed: %s" % done.stderr
    return done.stdout.strip().rsplit("= ", 1)[-1]


def scenario_read_small_file(server):
    """read answers the file's size and SHA-256, then its raw bytes, then exit 0."""
    data = bytes(range(256)) + b"\nhello\r\n\x00\xff"
    path = write_scratch(server, "small.bin", data)
    size, digest, body, tail = split_read(read_raw(server, "read " + path))
    assert size == len(data), "read must report the file's size, got %d" % size
    assert digest == openssl_sha256(path), (
        "read must report the file's SHA-256 as openssl dgst does")
    assert body == data, "read must return the file's raw bytes"
    assert tail == b"exit 0\n", "read must end with exit 0, got %r" % tail


def scenario_read_ranges_over_the_cap(server):
    """A file over the cap reads in ranges that reassemble and verify by hash."""
    data = bytes((i * 131 + 7) % 256 for i in range(READ_CAP * 3 + 1000))
    path = write_scratch(server, "large.bin", data)
    digest = openssl_sha256(path)

    size, got, body, tail = split_read(read_raw(server, "read " + path))
    assert (size, got) == (READ_CAP, digest), (
        "a whole read over the cap must name the cap in its header and the "
        "whole file's hash")
    assert body == data[:READ_CAP], "a read over the cap must return the cap"
    assert tail == ("truncated %d of %d\nexit 0\n" % (READ_CAP, len(data))
                    ).encode("ascii"), "a cut read must say so, got %r" % tail

    assembled = b""
    while len(assembled) < len(data):
        offset = len(assembled)
        command = "read %s --offset %d --limit %d" % (path, offset, READ_CAP)
        size, got, body, tail = split_read(read_raw(server, command))
        assert size == len(body), (
            "a range's header must name the bytes that follow, got %d for %d"
            % (size, len(body)))
        assert got == digest, "every range must report the whole file's hash"
        assert 0 < len(body) <= READ_CAP, (
            "a range must return at most the cap, got %d bytes" % len(body))
        assert tail == b"exit 0\n", "a range must end with exit 0, got %r" % tail
        assembled += body
    assert assembled == data, "the ranges must reassemble the file"
    assert hashlib.sha256(assembled).hexdigest() == digest, (
        "the reassembled bytes must verify against the whole file's hash")


def scenario_read_cut_at_an_offset(server):
    """A cut read from an offset marks the length of its range, not the file's size."""
    data = bytes((i * 17 + 3) % 256 for i in range(300 * 1024))
    path = write_scratch(server, "cut.bin", data)
    offset = 100000
    size, got, body, tail = split_read(
        read_raw(server, "read %s --offset %d" % (path, offset)))
    assert size == len(body) == READ_CAP, (
        "a cut read must name the bytes it sends")
    assert body == data[offset:offset + READ_CAP], (
        "a cut read from an offset must return the cap from that offset")
    assert tail == ("truncated %d of %d\nexit 0\n"
                    % (READ_CAP, len(data) - offset)).encode("ascii"), (
        "the truncated marker must name the range's length, got %r" % tail)


def scenario_read_bad_range(server):
    """A range past the end answers bad_range; a bad option answers bad_option."""
    path = write_scratch(server, "short.txt", b"0123456789")
    assert run_command(server, "read %s --offset 11" % path) == [
        "bad_range", "exit 1"], "an offset past the end must answer bad_range"
    size, digest, body, tail = split_read(
        read_raw(server, "read %s --offset 10" % path))
    assert (size, body, tail) == (0, b"", b"exit 0\n"), (
        "an offset at the end must read nothing, got %r" % body)
    assert run_command(server, "read %s --offset ten" % path) == [
        "bad_option", "exit 1"], "a non-numeric offset must answer bad_option"
    assert run_command(server, "read %s --whence 0" % path) == [
        "bad_option", "exit 1"], "an unknown option must answer bad_option"


def scenario_secrets_read_directly(server):
    for name in SECRET_NAMES:
        path = secret_path(server, name)
        for template in SECRET_READS:
            assert_protected(server, template.format(p=path))


def scenario_secrets_read_through_symlink(server):
    for name in SECRET_NAMES:
        target = secret_path(server, name)
        link = os.path.join(scratch_dir(server), "link-" + name)
        make_link(link, target, hard=False)
        for template in SECRET_READS:
            assert_protected(server, template.format(p=link))


def scenario_secrets_read_through_hard_link(server):
    for name in SECRET_NAMES:
        target = secret_path(server, name)
        link = os.path.join(scratch_dir(server), "hard-" + name)
        make_link(link, target, hard=True)
        for template in SECRET_READS:
            assert_protected(server, template.format(p=link))


def scenario_no_system_change_on_agent_port(server):
    """Telnet is out of scope; the agent port opens no way past the gate.

    The telnet shell has the ungated commands (docs/telnet-boundary.md). This
    checks the other half of the boundary: every command that changes the
    system on the telnet shell is refused here, and the only way to put code
    on the console is a push, which waits for an approval.

    Every command outside the allowlist now asks the owner (75), or is held
    by the notification gap (76) because this scenario does not move the
    clock. A write outside the host test root is protected (87), so the
    host's own /data is never asked about or touched; chmod is protected the
    same way, where it used to ask (75) before attribute commands were gated.
    mount was once an unlisted command answering 75 or 76; it is a gated
    system command now, and its target /mnt is outside the writable roots, so
    it answers 87 without asking.
    """
    secret = secret_path(server, "token")
    for command in (
        "rm " + secret,
        "kill 1",
        "mount -t nullfs / /mnt",
        "mkdir /data/x",
        "touch /data/x",
        "mv /data/a /data/b",
        "chmod 777 /data",
        "exec /data/payload",
        "reboot",
        "/data/payload",
    ):
        sock = server.connect()
        try:
            sock.sendall(
                ("auth %s\n%s\n" % (server.token, command)).encode("ascii")
            )
            lines = reply_lines(read_reply(sock))
        finally:
            sock.close()
        # mv, mount and exec are gated commands of their own now. Their paths
        # are outside the host test root, so they answer protected before they
        # ask the owner.
        if command.startswith(("rm ", "mkdir ", "touch ", "chmod ", "mv ",
                               "mount ", "exec ")):
            assert lines == ["protected", "exit 87"], (
                "%s must answer protected, got %r" % (command, lines))
        else:
            assert lines[-1] in ("exit 75", "exit 76"), (
                "%s must be gated, answered %r" % (command, lines))
            assert lines[-1] == "exit 76" or APPROVAL_LINE.match(lines[0]), (
                "%s must answer approval_required, got %r" % (command, lines))
            if lines[-1] == "exit 75":
                server.next_line()
    # A push is the one way in. It names an approval and shows the owner a
    # prompt; the scenario denies it so nothing stays staged.
    decide_push(server, "boundary", b"\x7fELF telnet boundary", "deny")


INSPECTION_COMMANDS = (
    "authid", "echo", "help", "id", "procstat", "ps", "sfoinfo", "sleep",
    "sum", "sync", "sysctl",
)

# The kernel parameter each host reads for its operating system, and its value.
OSTYPE = {"Darwin": ("kern.ostype", "Darwin"),
          "Linux": ("kernel.ostype", "Linux")}


def sfo_bytes(title):
    """A PARAM.SFO with one string entry, laid out as bundles/core/sfo.h says."""
    key = b"TITLE\0"
    value = title.encode("ascii") + b"\0"
    keys_offset = 20 + 16
    data_offset = keys_offset + len(key)
    return (struct.pack("<IIIII", 0x46535000, 0x101, keys_offset, data_offset, 1)
            + struct.pack("<HBBIII", 0, 0, 2, len(value), len(value), 0)
            + key + value)


def rows_of(lines):
    return [line.split() for line in lines[:-1]]


SYNC_TIMEOUT = 120.0


def scenario_inspection_runs_at_once(server):
    """These commands need no approval, so each answers with its own output."""
    assert run_command(server, "echo hello from ariel") == [
        "hello from ariel", "exit 0"]
    # sync flushes the whole machine, and a busy CI disk can take far longer
    # than one reply's usual 5 s.
    assert run_command(server, "sync", timeout=SYNC_TIMEOUT) == ["exit 0"]
    assert run_command(server, "sleep 0") == ["exit 0"]
    started = time.monotonic()
    assert run_command(server, "sleep 1") == ["exit 0"]
    assert time.monotonic() - started >= 0.9, "sleep 1 must pause a second"
    assert run_command(server, "sleep") == ["missing_operand", "exit 1"]
    assert run_command(server, "sleep soon") == ["bad_duration", "exit 1"]
    assert run_command(server, "sleep 61") == ["bad_duration", "exit 1"]
    lines = run_command(server, "id")
    assert lines[-1] == "exit 0" and lines[0].startswith("uid="), (
        "id must print the user and group, got %r" % lines)
    lines = run_command(server, "help")
    assert lines[-1] == "exit 0", "help must exit 0, got %r" % lines
    listed = {line.split(" ")[0] for line in lines[:-1]}
    missing = sorted(set(INSPECTION_COMMANDS) - listed)
    assert not missing, "help must list every command, missing %r" % missing


def scenario_ps_and_procstat(server):
    """ps lists Ariel's own process; procstat reads one pid and refuses a bad one."""
    pid = str(server.proc.pid)
    lines = run_command(server, "ps")
    assert lines[-1] == "exit 0", "ps must exit 0, got %r" % lines
    rows = rows_of(lines)
    assert rows and rows[0][0] == "PID", "ps must print a header, got %r" % lines
    assert any(row[0] == pid for row in rows[1:]), (
        "ps must list Ariel's process %s, got %r" % (pid, lines))
    lines = run_command(server, "procstat %s" % pid)
    assert lines[-1] == "exit 0", "procstat must exit 0, got %r" % lines
    assert any(row[0] == pid for row in rows_of(lines)[1:]), (
        "procstat must describe %s, got %r" % (pid, lines))
    assert run_command(server, "procstat") == ["missing_operand", "exit 1"]
    assert run_command(server, "procstat 99999999") == [
        "no_such_process", "exit 1"]


# The table commands' fixed tree: alpha is 5 bytes at mode 0640, and the escape
# directory holds a name with a quote, a backslash and a tab.
TABLE_ENTRIES = ("", "alpha", "beta", "empty", "escape", "escape/a\"b\\c",
                 "escape/x\ty", "gamma", "gamma/delta")
FAKE_PS = (
    "#!/bin/sh\n"
    "/bin/cat <<'EOF'\n"
    "  1     0     1     1     0 Ss   launchd\n"
    "421     1   421   421   501 S+   Some App\n"
    "EOF\n"
)


def table_fixture(server):
    """Rebuild the fixed tree the table commands read, and return its root."""
    root = os.path.join(scratch_dir(server), "table")
    shutil.rmtree(root, ignore_errors=True)
    for folder in ("gamma", "empty", "escape"):
        os.makedirs(os.path.join(root, folder))
    with open(os.path.join(root, "alpha"), "wb") as handle:
        handle.write(b"hello")
    os.chmod(os.path.join(root, "alpha"), 0o640)
    for path in ("beta", "gamma/delta", "escape/a\"b\\c", "escape/x\ty"):
        open(os.path.join(root, path), "wb").close()
    return root


def table_path(root, entry):
    return os.path.join(root, entry) if entry else root


def scenario_ls_json_is_one_object_per_entry(server):
    """ls --json answers one object per entry, in the plain listing's order."""
    root = table_fixture(server)
    assert run_command(server, "ls --json %s" % root) == [
        '{"name":"alpha"}', '{"name":"beta"}', '{"name":"empty"}',
        '{"name":"escape"}', '{"name":"gamma"}', "exit 0"], (
        "ls --json of the fixed tree")
    assert run_command(server, "ls --json %s/empty" % root) == [
        "exit 0"], "an empty directory has no objects, only exit 0"
    lines = run_command(server, "ls --json %s/escape" % root)
    assert sorted(lines[:-1]) == [
        '{"name":"a\\"b\\\\c"}', '{"name":"x\\u0009y"}'], (
        "a quote, a backslash and a tab must be escaped in the object, "
        "got %r" % lines)


def scenario_stat_json_is_one_object(server):
    """stat --json answers one object: the path, its size, its octal mode and inode."""
    root = table_fixture(server)
    path = os.path.join(root, "alpha")
    inode = os.stat(path).st_ino
    assert run_command(server, "stat --json %s" % path) == [
        '{"path":"%s","bytes":5,"mode":"640","inode":%d}' % (path, inode),
        "exit 0"], "stat --json of the fixed file"
    assert run_command(server, "stat %s" % path) == [
        "%s: 5 bytes, mode 640, inode %d" % (path, inode), "exit 0"], (
        "the plain stat line must keep its wording")


def scenario_df_json_is_one_object(server):
    """df --json answers one object whose numbers are the plain listing's."""
    root = table_fixture(server)
    lines = run_command(server, "df --json %s" % root)
    assert len(lines) == 2 and lines[-1] == "exit 0", (
        "df --json must answer one object then exit 0, got %r" % lines)
    assert re.fullmatch(
        r'\{"path":"[^"]*","total_bytes":\d+,"free_bytes":\d+,'
        r'"available_bytes":\d+\}', lines[0]), (
        "df --json must use its documented keys, got %r" % lines[0])
    obj = json.loads(lines[0])
    assert obj["path"] == root, "df --json must name the path it was given"
    vfs = os.statvfs(root)
    assert obj["total_bytes"] == vfs.f_blocks * vfs.f_frsize, (
        "df --json total must be the filesystem's total")
    plain = run_command(server, "df %s" % root)
    found = re.fullmatch(
        r"%s: (\d+) bytes total, (\d+) bytes free, (\d+) bytes available"
        % re.escape(root), plain[0])
    assert found and int(found.group(1)) == obj["total_bytes"], (
        "the plain df total must equal the JSON total, got %r" % plain)


def scenario_find_json_is_one_object_per_path(server):
    """find --json answers one object per path, the root first, and exit 0."""
    root = table_fixture(server)
    lines = run_command(server, "find --json %s" % root)
    assert lines[-1] == "exit 0", "find --json must exit 0, got %r" % lines
    objects = lines[:-1]
    assert objects[0] == '{"path":"%s"}' % root, (
        "find --json must name the root first, got %r" % objects[0])
    assert sorted(objects[1:]) == sorted(
        ['{"path":"%s"}' % table_path(root, "alpha"),
         '{"path":"%s"}' % table_path(root, "beta"),
         '{"path":"%s"}' % table_path(root, "empty"),
         '{"path":"%s"}' % table_path(root, "escape"),
         '{"path":"%s/escape/a\\"b\\\\c"}' % root,
         '{"path":"%s/escape/x\\u0009y"}' % root,
         '{"path":"%s"}' % table_path(root, "gamma"),
         '{"path":"%s/gamma/delta"}' % root]), (
        "find --json must list every path once, got %r" % objects)


def scenario_json_row_longer_than_a_line_is_shown_whole(server):
    """A JSON row whose escaped text is longer than a line still shows, while the answer fits."""
    root = os.path.join(scratch_dir(server), "wide")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    open(os.path.join(root, "\x01" * 255), "wb").close()
    assert run_command(server, "find --json " + root) == [
        '{"path":"%s"}' % root, '{"path":"%s/%s"}' % (root, "\\u0001" * 255), "exit 0"], (
        "find --json must show a row over 1536 bytes when the answer fits 64 KiB")
    assert run_command(server, "ls --json " + root) == [
        '{"name":"%s"}' % ("\\u0001" * 255), "exit 0"], (
        "ls --json must show a name over 1536 bytes when the answer fits 64 KiB")


def scenario_json_listing_over_the_cap_is_cut(server):
    """ls --json cuts its objects at the cap, keeps them whole and says how many it showed."""
    folder, names = make_listing(server, "json-listing", BIG_LISTING)
    body, shown, total = cut_answer(run_command_raw(server, "ls --json " + folder))
    assert total == BIG_LISTING and 0 < shown < BIG_LISTING, (
        "ls --json must cut a listing over 64 KiB, got shown %d of %d" % (shown, total))
    assert body == ['{"name":"%s"}' % name for name in names[:shown]], (
        "a cut ls --json shows the first objects in order, each whole")


def scenario_json_limit_is_taken_by_ls_and_find_only(server):
    """--json takes --limit N for ls and find, in either order, and refuses it for the rest."""
    root = table_fixture(server)
    ls_cut = ['{"name":"alpha"}', '{"name":"beta"}', "truncated 2 of 5", "exit 0"]
    find_none = ["truncated 0 of 9", "exit 0"]
    assert run_command(server, "ls --json --limit 2 " + root) == ls_cut, (
        "ls --json --limit 2 must show two objects and say how many there are")
    assert run_command(server, "ls --limit 2 --json " + root) == ls_cut, (
        "ls --limit 2 --json must answer the same as the other order")
    assert run_command(server, "find --limit 0 --json " + root) == find_none, (
        "find --limit 0 --json must show no object and say how many there are")
    assert run_command(server, "find --json --limit 0 " + root) == find_none, (
        "find --json --limit 0 must answer the same as the other order")
    for command in ("stat --json --limit 1 " + os.path.join(root, "alpha"),
                    "df --json --limit 1 " + root,
                    "ps --json --limit 1",
                    "ls --json --limit " + root,
                    "ls --json --limit many " + root):
        assert run_command(server, command) == ["bad_option", "exit 1"], (
            "%r must answer bad_option and nothing else" % command)


def scenario_ps_json_from_a_fixed_ps(server):
    """ps --json answers one object per row of ps, and the plain listing keeps its header."""
    folder = os.path.join(scratch_dir(server), "fake-ps")
    os.makedirs(folder, exist_ok=True)
    fake = os.path.join(folder, "ps")
    with open(fake, "w") as handle:
        handle.write(FAKE_PS)
    os.chmod(fake, 0o755)
    saved = server.env
    server.env = dict(saved or {}, PATH=folder)
    server.restart()
    try:
        assert run_command(server, "ps") == [
            "PID PPID PGID SID UID STATE COMMAND",
            "  1     0     1     1     0 Ss   launchd",
            "421     1   421   421   501 S+   Some App",
            "exit 0"], "plain ps must keep its header and rows"
        assert run_command(server, "ps --json") == [
            '{"pid":1,"ppid":0,"pgid":1,"sid":1,"uid":0,"state":"Ss",'
            '"command":"launchd"}',
            '{"pid":421,"ppid":1,"pgid":421,"sid":421,"uid":501,"state":"S+",'
            '"command":"Some App"}',
            "exit 0"], "ps --json must answer one object per row, no header"
    finally:
        server.env = saved
        server.restart()


def scenario_table_plain_output_is_unchanged(server):
    """Without --json the table commands print what they printed before."""
    root = table_fixture(server)
    alpha = os.path.join(root, "alpha")
    assert run_command(server, "ls %s" % root) == [
        "alpha", "beta", "empty", "escape", "gamma", "exit 0"], (
        "ls must list names")
    assert run_command(server, "ls %s/empty" % root) == [
        "exit 0"], "ls of an empty directory prints nothing but exit 0"
    lines = run_command(server, "find %s" % root)
    assert lines[-1] == "exit 0", "find must exit 0, got %r" % lines
    assert sorted(lines[:-1]) == sorted(
        table_path(root, entry) for entry in TABLE_ENTRIES), (
        "find must print every path as a bare line, got %r" % lines)
    assert run_command(server, "stat %s" % alpha)[-1] == "exit 0"
    lines = run_command(server, "df %s" % root)
    assert lines[-1] == "exit 0" and re.fullmatch(
        r"%s: \d+ bytes total, \d+ bytes free, \d+ bytes available"
        % re.escape(root), lines[0]), "df must keep its plain line"


def scenario_table_bad_option_answers_nothing_else(server):
    """An unsupported option or operand answers bad_option and no partial output."""
    root = table_fixture(server)
    cases = (
        "ls --json=yaml %s" % root,
        "ls -l --json %s" % root,
        "stat --json --yaml %s/alpha" % root,
        "find --json --limit=3 %s" % root,
        "df --json -h %s" % root,
        "ps --json extra",
        "ps --json=yaml",
    )
    for command in cases:
        assert run_command(server, command) == ["bad_option", "exit 1"], (
            "%r must answer bad_option and nothing else" % command)


def scenario_table_json_errors_answer_their_word(server):
    """A table command's JSON failure answers its error word and exit 1, as plain does."""
    assert run_command(server, "ls --json relative") == [
        "relative_path", "exit 1"]
    assert run_command(server, "stat --json /ariel-no-such-path") == [
        "no_such_file", "exit 1"]
    assert run_command(server, "df --json relative") == [
        "relative_path", "exit 1"]
    assert run_command(server, "find --json /ariel-no-such-path") == [
        "no_such_file", "exit 1"]


def scenario_table_json_keys_are_documented(server):
    """The JSON keys are documented, and a rename is named a protocol change."""
    del server
    with open(os.path.join(repo_dir(), "docs", "json-output.md")) as handle:
        doc = handle.read()
    keys = {
        "ps": ("pid", "ppid", "pgid", "sid", "uid", "state", "command"),
        "ls": ("name",),
        "stat": ("path", "bytes", "mode", "inode"),
        "df": ("path", "total_bytes", "free_bytes", "available_bytes"),
        "find": ("path",),
    }
    for command, names in keys.items():
        assert "## `%s`" % command in doc, (
            "docs/json-output.md must have a section for %s" % command)
        for name in names:
            assert "| `%s` |" % name in doc, (
                "docs/json-output.md must document the %s key of %s"
                % (name, command))
    assert "protocol change" in doc, (
        "docs/json-output.md must say that a key rename is a protocol change")
    with open(os.path.join(repo_dir(), "docs", "exit-codes.md")) as handle:
        registry = handle.read()
    assert "`bad_option`" in registry, (
        "docs/exit-codes.md must name bad_option before the code uses it")


def scenario_sysctl_reads_and_refuses_writes(server):
    name, value = OSTYPE[platform.system()]
    assert run_command(server, "sysctl %s" % name) == [value, "exit 0"]
    assert run_command(server, "sysctl") == ["missing_operand", "exit 1"]
    assert_unlisted_gated(server, "sysctl %s=Other" % name)
    assert run_command(server, "sysctl %s" % name) == [value, "exit 0"], (
        "a refused sysctl write must change nothing")


def scenario_sum_and_sfoinfo_read_absolute_paths(server):
    data = os.path.join(server.root, "abc.bin")
    with open(data, "wb") as handle:
        handle.write(b"abc")
    # The BSD sum of "abc" is 16556, by the algorithm bundles/core/sum.c runs.
    assert run_command(server, "sum %s" % data) == [
        "16556 %s" % data, "exit 0"]
    assert run_command(server, "sum abc.bin") == ["relative_path", "exit 1"]
    assert run_command(server, "sum") == ["missing_operand", "exit 1"]
    missing = run_command(server, "sum %s/none" % server.root)
    assert missing[-1] == "exit 1" and len(missing) == 2, (
        "sum of a missing file must explain and exit 1, got %r" % missing)
    sfo = os.path.join(server.root, "PARAM.SFO")
    with open(sfo, "wb") as handle:
        handle.write(sfo_bytes("Hello"))
    assert run_command(server, "sfoinfo %s" % sfo) == [
        "TITLE('Hello')", "exit 0"]
    junk = os.path.join(server.root, "junk.sfo")
    with open(junk, "wb") as handle:
        handle.write(b"not an sfo file")
    assert run_command(server, "sfoinfo %s" % junk) == ["not_sfo", "exit 1"]


def scenario_authid_is_not_available_on_the_host(server):
    """authid reads the console's kernel credentials: a PS5-only reader."""
    assert run_command(server, "authid") == [
        "not available on this platform", "exit 1"]
    assert_unlisted_gated(server, "authid 0x4800000000010003")


GATE_PROMPT = re.compile(r"^prompt (a-[0-9a-f]+) ")


def gate_request(server, command):
    """Send a gated command and check the owner is asked: 75, a challenge, a prompt.

    Ten seconds of test clock pass first, so the notification gap is clear.
    Returns the approval ID and the challenge line.
    """
    server.advance(10_000)
    lines = run_command(server, command)
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "%s must answer approval_required and exit 75, got %r"
        % (command, lines))
    approval = APPROVAL_LINE.match(lines[0])
    assert approval, "expected approval_required, got %r" % lines[0]
    challenge = CHALLENGE_LINE.match(lines[1])
    assert challenge and challenge.group(1) == approval.group(1), (
        "the challenge must name the approval, got %r" % lines[1])
    prompt = GATE_PROMPT.match(server.next_line() or "")
    assert prompt and prompt.group(1) == approval.group(1), (
        "the owner must be asked about %s" % command)
    return approval.group(1), lines[1]


def stat_exit(server, path):
    return run_command(server, "stat " + path)[-1]


def scenario_file_commands_need_the_owner(server):
    """Each of mkdir, rmdir, touch and rm asks first and runs once per signature."""
    folder = os.path.join(server.root, "data", "gate-dir")
    target = os.path.join(server.root, "data", "gate-file")

    approval, challenge = gate_request(server, "mkdir " + folder)
    assert stat_exit(server, folder) == "exit 1", "an unsigned mkdir must not run"
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "mkdir " + folder) == ["exit 0"], (
        "a signed mkdir must run")
    assert stat_exit(server, folder) == "exit 0", "mkdir must create the directory"

    approval, challenge = gate_request(server, "rmdir " + folder)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "rmdir " + folder) == ["exit 0"], (
        "a signed rmdir must run")
    assert stat_exit(server, folder) == "exit 1", "rmdir must remove the directory"

    approval, challenge = gate_request(server, "touch " + target)
    assert stat_exit(server, target) == "exit 1", (
        "an unsigned touch must not create the file")
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "touch " + target) == ["exit 0"], (
        "a signed touch must run")
    assert stat_exit(server, target) == "exit 0", "touch must create the file"

    # The signature is spent: the same touch needs a new one.
    spent, _ = gate_request(server, "touch " + target)
    assert spent != approval, "a spent approval must not be asked again"

    approval, challenge = gate_request(server, "rm " + target)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "rm " + target) == ["exit 0"], (
        "a signed rm must run")
    assert stat_exit(server, target) == "exit 1", "rm must remove the file"


def scenario_file_replaced_after_approval_answers_78(server):
    """A file replaced after the owner signs answers approval_stale and survives."""
    target = os.path.join(server.root, "data", "stale-file")
    approval, challenge = gate_request(server, "touch " + target)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "touch " + target) == ["exit 0"]

    approval, challenge = gate_request(server, "rm " + target)
    sign_and_grant(server, approval, challenge)

    # A new file under the same name has a new identity.
    replacement = target + "-new"
    open(replacement, "wb").close()
    os.replace(replacement, target)

    assert run_command(server, "rm " + target) == [
        "approval_stale", "exit 78"], (
        "a file replaced after approval must answer approval_stale")
    assert stat_exit(server, target) == "exit 0", (
        "a stale approval must not remove the file")


def scenario_unlisted_command_is_gated(server):
    """A command nothing implements asks the owner, then does nothing once signed."""
    approval, challenge = gate_request(server, "nonsense")
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "nonsense") == ["unknown_command", "exit 1"], (
        "a signed command that nothing implements must still do nothing")


def scenario_protected_paths_answer_87_without_asking(server):
    """Writes outside the allowed roots, and Ariel's token, answer protected."""
    outside = [
        "touch /etc/ariel-gate",
        "mkdir " + os.path.join(server.root, "elsewhere"),
        "touch " + os.path.join(server.root, "elsewhere", "x"),
        "mkdir " + os.path.join(server.root, "user"),
        "mkdir " + os.path.join(server.root, "data"),
        "touch " + os.path.join(server.root, "database", "x"),
        "rm " + secret_path(server, "token"),
    ]
    for command in outside:
        assert run_command(server, command) == ["protected", "exit 87"], (
            "%s must answer protected and exit 87" % command)
    server.assert_no_line()


def scenario_file_commands_are_audited(server):
    """Requests, runs and protected refusals of file commands reach audit tail."""
    target = os.path.join(server.root, "data", "audited-file")
    approval, challenge = gate_request(server, "touch " + target)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "touch " + target) == ["exit 0"]
    assert run_command(server, "rm " + secret_path(server, "token")) == [
        "protected", "exit 87"]

    kinds = set()
    for line in run_exit_zero(server, "audit tail 64"):
        fields = line.split()
        if len(fields) == 5:
            kinds.add(fields[1])
    for kind in ("touch.request", "touch.done", "rm.protected"):
        assert kind in kinds, "audit tail must show %s, got %r" % (
            kind, sorted(kinds))


def scenario_file_action_names_its_facts(server):
    """The challenge names the command, the path, and the file's identity."""
    target = os.path.join(server.root, "data", "facts-file")
    approval, challenge = gate_request(server, "touch " + target)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "touch " + target) == ["exit 0"]

    _, challenge = gate_request(server, "rm " + target)
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=rm\n"), action
    assert "\ntarget=%s\n" % target in action, action
    assert "\nsha256=none\n" in action, action
    assert "\noption.kind=file\n" in action, action
    assert "\noption.dev=" in action and "\noption.ino=" in action, action


ATTRIBUTE_TEMPLATES = ("chmod 0777 {p}", "chown 0 {p}", "chgrp 0 {p}")


def file_mode(path):
    return os.stat(path).st_mode & 0o7777


def make_file(server, name, mode):
    path = os.path.join(server.root, "data", name)
    with open(path, "wb") as handle:
        handle.write(b"attribute\n")
    os.chmod(path, mode)
    return path


def scenario_attribute_commands_need_the_owner(server):
    """chmod, chown and chgrp ask first, run once per signature and are audited."""
    target = make_file(server, "attr-file", 0o644)
    uid = os.getuid()
    gid = os.getgid()

    approval, challenge = gate_request(server, "chmod 0600 " + target)
    assert file_mode(target) == 0o644, "an unsigned chmod must not run"
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "chmod 0600 " + target) == ["exit 0"], (
        "a signed chmod must run")
    assert file_mode(target) == 0o600, "chmod must set the mode"

    # The signature is spent: the same chmod needs a new one.
    spent, _ = gate_request(server, "chmod 0600 " + target)
    assert spent != approval, "a spent approval must not be asked again"

    approval, challenge = gate_request(server, "chown %d %s" % (uid, target))
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "chown %d %s" % (uid, target)) == ["exit 0"], (
        "a signed chown must run")
    assert os.stat(target).st_uid == uid, "chown must set the owner"

    approval, challenge = gate_request(server, "chgrp %d %s" % (gid, target))
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "chgrp %d %s" % (gid, target)) == ["exit 0"], (
        "a signed chgrp must run")
    assert os.stat(target).st_gid == gid, "chgrp must set the group"

    # A chmod naming two paths is not one this port runs: it is unlisted.
    approval, challenge = gate_request(
        server, "chmod 0755 %s %s" % (target, target))
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "chmod 0755 %s %s" % (target, target)) == [
        "unknown_command", "exit 1"], (
        "a chmod with two paths must be gated as an unlisted command")
    assert file_mode(target) == 0o600, "a refused chmod must change nothing"

    kinds = set()
    for line in run_exit_zero(server, "audit tail 64"):
        fields = line.split()
        if len(fields) == 5:
            kinds.add(fields[1])
    for kind in ("chmod.request", "chmod.done", "chown.done", "chgrp.done",
                 "unlisted.refused"):
        assert kind in kinds, "audit tail must show %s, got %r" % (
            kind, sorted(kinds))


def scenario_attribute_mode_is_bound_to_approval(server):
    """A chmod approved for one mode answers approval_stale for another."""
    target = make_file(server, "mode-bound", 0o644)
    approval, challenge = gate_request(server, "chmod 0600 " + target)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "chmod 0644 " + target) == [
        "approval_stale", "exit 78"], (
        "a chmod to another mode than the one signed must answer 78")
    assert file_mode(target) == 0o644, "a stale chmod must change nothing"

    approval, challenge = gate_request(server, "chmod 0600 " + target)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "chmod 0600 " + target) == ["exit 0"], (
        "the mode that was signed must run")
    assert file_mode(target) == 0o600, "the signed mode must be set"


def scenario_attribute_file_replaced_answers_78(server):
    """A file replaced after a chmod approval answers approval_stale and keeps its mode."""
    target = make_file(server, "replaced-attr", 0o644)
    approval, challenge = gate_request(server, "chmod 0600 " + target)
    sign_and_grant(server, approval, challenge)

    replacement = target + "-new"
    with open(replacement, "wb") as handle:
        handle.write(b"replacement\n")
    os.chmod(replacement, 0o644)
    os.replace(replacement, target)

    assert run_command(server, "chmod 0600 " + target) == [
        "approval_stale", "exit 78"], (
        "a file replaced after approval must answer approval_stale")
    assert file_mode(target) == 0o644, (
        "a stale chmod must not change the replacement's mode")


def scenario_attribute_commands_refuse_protected_aliases(server):
    """chmod, chown and chgrp answer protected on a protected object, by any alias.

    A link to an ordinary file is not followed: it answers symbolic_link and
    the file keeps its mode.
    """
    secret = secret_path(server, "token")
    mode = file_mode(secret)
    hard = os.path.join(server.root, "data", "alias-hard")
    soft = os.path.join(server.root, "data", "alias-soft")
    make_link(hard, secret, hard=True)
    make_link(soft, secret, hard=False)
    for path in (secret, hard, soft):
        for template in ATTRIBUTE_TEMPLATES:
            assert_protected(server, template.format(p=path))
    assert file_mode(secret) == mode, "a protected object must keep its mode"

    ordinary = make_file(server, "alias-target", 0o644)
    link = os.path.join(server.root, "data", "alias-link")
    make_link(link, ordinary, hard=False)
    assert run_command(server, "chmod 0600 " + link) == [
        "symbolic_link", "exit 1"], "a link to an ordinary file is not followed"
    assert file_mode(ordinary) == 0o644, "a refused link must change nothing"


def scenario_attribute_operands_are_checked_first(server):
    """A bad mode, owner or group, or a missing operand, answers its word and asks nothing."""
    path = "/data/attr-operands"
    for command, word in (
            ("chmod 9 " + path, "bad_mode"),
            ("chmod 10000 " + path, "bad_mode"),
            ("chmod rwx " + path, "bad_mode"),
            ("chown -1 " + path, "bad_owner"),
            ("chown 4294967295 " + path, "bad_owner"),
            ("chown root " + path, "bad_owner"),
            ("chgrp 4294967295 " + path, "bad_group"),
            ("chgrp 1x " + path, "bad_group")):
        assert run_command(server, command) == [word, "exit 1"], (
            "%s must answer %s and exit 1" % (command, word))
    for command in ("chmod", "chmod 0755", "chown 0", "chgrp 0"):
        assert run_command(server, command) == ["missing_operand", "exit 1"], (
            "%s must answer missing_operand and exit 1" % command)

    kinds = set()
    for line in run_exit_zero(server, "audit tail 64"):
        fields = line.split()
        if len(fields) == 5:
            kinds.add(fields[1])
    assert "chmod.refused" in kinds, (
        "a refused chmod must reach audit tail, got %r" % sorted(kinds))


TRANSFERS = ("cp", "mv", "ln")
TRANSFER_BYTES = b"transfer bytes\n"


def make_transfer_file(server, name, data=TRANSFER_BYTES):
    """A regular file in the host test root's data directory, made directly."""
    path = os.path.join(server.root, "data", name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def transfer_line(command, source, destination):
    return "%s %s %s" % (command, source, destination)


def transfer_request(server, line):
    """gate_request after the earlier pending approvals expire.

    The store holds at most three pending approvals, so the requests left
    behind by one transfer would answer approval_busy for the next.
    """
    server.advance(120_000)
    return gate_request(server, line)


def scenario_transfer_commands_need_the_owner(server):
    """cp, mv and ln ask first, run once after the owner signs, and ask again."""
    for command in TRANSFERS:
        source = make_transfer_file(server, "xsrc-" + command)
        destination = os.path.join(server.root, "data", "xdst-" + command)
        line = transfer_line(command, source, destination)

        approval, challenge = transfer_request(server, line)
        assert not os.path.lexists(destination), (
            "an unsigned %s must not run" % command)
        sign_and_grant(server, approval, challenge)
        assert run_command(server, line) == ["exit 0"], (
            "a signed %s must run" % command)
        assert read_bytes(destination) == TRANSFER_BYTES, (
            "%s must give the destination the source's bytes" % command)

        if command == "cp":
            assert os.path.exists(source), "cp must leave the source"
            os.unlink(destination)
            spent, _ = transfer_request(server, line)
            assert spent != approval, "a spent cp approval must not be asked again"
        elif command == "mv":
            assert not os.path.lexists(source), "mv must remove the source"
        else:
            assert os.path.samefile(source, destination), (
                "ln must make the destination a link to the source")


def scenario_transfer_source_swapped_answers_78(server):
    """A source replaced after the owner signs answers approval_stale and moves nothing."""
    for command in TRANSFERS:
        source = make_transfer_file(server, "xswap-" + command)
        destination = os.path.join(server.root, "data", "xswap-dst-" + command)
        line = transfer_line(command, source, destination)
        approval, challenge = transfer_request(server, line)
        sign_and_grant(server, approval, challenge)

        replacement = source + "-new"
        with open(replacement, "wb") as handle:
            handle.write(b"swapped in\n")
        os.replace(replacement, source)

        assert run_command(server, line) == ["approval_stale", "exit 78"], (
            "a source swapped after approval must answer approval_stale for %s"
            % command)
        assert not os.path.lexists(destination), (
            "a swapped source must not be transferred by %s" % command)


def scenario_transfer_refuses_existing_destination(server):
    """An existing destination answers exists without asking, and is left alone."""
    source = make_transfer_file(server, "xkeep-src", b"source\n")
    destination = make_transfer_file(server, "xkeep-dst", b"keep me\n")
    for command in TRANSFERS:
        line = transfer_line(command, source, destination)
        assert run_command(server, line) == ["exists", "exit 1"], (
            "%s onto an existing destination must answer exists" % command)
    assert read_bytes(destination) == b"keep me\n", (
        "an existing destination must be left as it was")
    assert read_bytes(source) == b"source\n", "a refused transfer must not move the source"


def scenario_transfer_outside_writable_roots_answers_87(server):
    """cp, mv and ln refuse a path outside /data, /user and /mnt/usb* without asking."""
    for line in (
        "cp /system/xfer-src /data/xfer-dst",
        "mv /data/xfer-src /etc/xfer-dst",
        "ln /system/xfer-src /data/xfer-dst",
        "cp /data/xfer-src /mnt/xfer-dst",
    ):
        assert run_command(server, line) == ["protected", "exit 87"], (
            "%s must answer protected and exit 87" % line)


def scenario_transfer_protected_objects_answer_87(server):
    """cp, mv and ln refuse Ariel's own objects through any alias, without asking."""
    token = secret_path(server, "token")
    before = read_bytes(token)
    state = os.path.dirname(token)
    source = make_transfer_file(server, "xprot-src")
    destination = os.path.join(server.root, "data", "xprot-dst")
    hard = os.path.join(server.root, "data", "xprot-hard")
    soft = os.path.join(server.root, "data", "xprot-soft")
    make_link(hard, token, hard=True)
    make_link(soft, token, hard=False)

    for command in TRANSFERS:
        for source_path in (token, hard, soft):
            line = transfer_line(command, source_path, destination)
            assert run_command(server, line) == ["protected", "exit 87"], (
                "%s must answer protected for %s" % (command, source_path))
        for target in (token, os.path.join(state, "xprot-new")):
            line = transfer_line(command, source, target)
            assert run_command(server, line) == ["protected", "exit 87"], (
                "%s onto %s must answer protected" % (command, target))

    moved = os.path.join(server.root, "data", "xprot-moved")
    assert run_command(server, "mv %s %s" % (state, moved)) == [
        "protected", "exit 87"], "moving the state directory must answer protected"
    assert read_bytes(token) == before, "a protected token must not change"
    assert os.path.isdir(state) and os.path.exists(source), (
        "a refused transfer must leave the state directory and its source")


def scenario_transfer_protected_after_approval_answers_87(server):
    """A source swapped for a link to Ariel's token after the owner signs runs nothing."""
    token = secret_path(server, "token")
    source = make_transfer_file(server, "xalias-src")
    destination = os.path.join(server.root, "data", "xalias-dst")
    line = transfer_line("cp", source, destination)
    approval, challenge = transfer_request(server, line)
    sign_and_grant(server, approval, challenge)

    os.unlink(source)
    os.link(token, source)

    assert run_command(server, line) == ["protected", "exit 87"], (
        "an approved cp of a source that became the token must answer protected")
    assert not os.path.lexists(destination), (
        "a protected source must not be copied even when approved")


def scenario_transfer_actions_are_audited(server):
    """cp, mv and ln requests, runs and refusals reach audit tail under both paths."""
    source = make_transfer_file(server, "xaudit-src")
    destination = os.path.join(server.root, "data", "xaudit-dst")
    line = transfer_line("cp", source, destination)
    approval, challenge = transfer_request(server, line)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, line) == ["exit 0"]
    assert run_command(server, transfer_line("mv", source, destination)) == [
        "exists", "exit 1"]
    token = secret_path(server, "token")
    assert run_command(server, transfer_line("ln", token, destination)) == [
        "protected", "exit 87"]

    events = set()
    for line_text in run_exit_zero(server, "audit tail 64"):
        fields = line_text.split()
        if len(fields) == 5:
            events.add((fields[1], fields[2]))
    subject = "%s>%s" % (source, destination)
    expected = (
        ("cp.request", subject),
        ("cp.done", subject),
        ("mv.refused", subject),
        ("ln.protected", "%s>%s" % (token, destination)),
    )
    for event in expected:
        assert event in events, (
            "audit tail must show %r, got %r" % (event, sorted(events)))


def scenario_transfer_action_names_its_facts(server):
    """The challenge of cp names both paths, the source's identity and sha256 none."""
    source = make_transfer_file(server, "xfacts-src")
    destination = os.path.join(server.root, "data", "xfacts-dst")
    _, challenge = transfer_request(server, transfer_line("cp", source, destination))
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=cp\n"), action
    assert "\ntarget=%s\n" % source in action, action
    assert "\ndestination=%s\n" % destination in action, action
    assert "\nsha256=none\n" in action, action


WRITE_BYTES = b"written through the shell\n"
WRITE_CAP = 64 * 1024 * 1024


def write_path(server, name):
    return os.path.join(server.root, "data", name)


def write_frame(server, path, data, declared_size=None, declared_hash=None,
                timeout=5.0):
    """One write on its own connection: the command line, then the body."""
    size = len(data) if declared_size is None else declared_size
    digest = (hashlib.sha256(data).hexdigest() if declared_hash is None
              else declared_hash)
    sock = server.connect(timeout=timeout)
    try:
        sock.sendall(("auth %s\nwrite %s %d %s\n"
                      % (server.token, path, size, digest)).encode("ascii"))
        try:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError):
            # A refusal before the body is read can close the connection first.
            pass
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def write_request(server, path, data):
    """A write that must ask the owner: 75, a challenge, a prompt. Returns the approval and the challenge."""
    server.advance(120_000)
    lines = write_frame(server, path, data)
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "write must answer approval_required and exit 75, got %r" % lines)
    approval = APPROVAL_LINE.match(lines[0])
    assert approval, "expected approval_required, got %r" % lines[0]
    challenge = CHALLENGE_LINE.match(lines[1])
    assert challenge and challenge.group(1) == approval.group(1), (
        "the challenge must name the approval, got %r" % lines[1])
    prompt = GATE_PROMPT.match(server.next_line() or "")
    assert prompt and prompt.group(1) == approval.group(1), (
        "the owner must be asked about the write")
    return approval.group(1), lines[1]


def write_events(server, path):
    return {kind for kind, name, _, _ in audit_events(server) if name == path
            and kind.startswith("write.")}


def scenario_write_is_gated_and_lands(server):
    """write asks first, binds path, size and hash, runs once, and asks again after."""
    path = write_path(server, "wgate.bin")
    approval, challenge = write_request(server, path, WRITE_BYTES)
    assert not os.path.lexists(path), "an unsigned write must not run"

    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=write\n"), action
    assert "\ntarget=%s\n" % path in action, action
    assert "\nsha256=%s\n" % hashlib.sha256(WRITE_BYTES).hexdigest() in action, action
    assert "\noption.size=%d\n" % len(WRITE_BYTES) in action, action

    sign_and_grant(server, approval, challenge)
    assert write_frame(server, path, WRITE_BYTES) == ["exit 0"], (
        "a signed write must run")
    assert read_bytes(path) == WRITE_BYTES, "write must land the bytes"

    os.unlink(path)
    again, _ = write_request(server, path, WRITE_BYTES)
    assert again != approval, "a spent write approval must not be asked again"
    assert {"write.request", "write.done"} <= write_events(server, path), (
        "audit tail must show the request and the write")


def scenario_write_mismatch_answers_like_push(server):
    """A body short of its size, past it, or with another hash answers upload_mismatch."""
    path = write_path(server, "wmismatch.bin")
    for declared in (
        {"declared_size": len(WRITE_BYTES) + 1},
        {"declared_size": len(WRITE_BYTES) - 1},
        {"declared_hash": "0" * 64},
    ):
        assert write_frame(server, path, WRITE_BYTES, **declared) == [
            "upload_mismatch", "exit 81"], (
            "a write that does not match its frame must answer upload_mismatch")
    assert not os.path.lexists(path), "a mismatched write must not land"
    server.assert_no_line()


def scenario_write_over_cap_is_refused_before_asking(server):
    """A file over 64 MiB answers too_large before the owner is asked."""
    path = write_path(server, "wbig.bin")
    assert write_frame(server, path, b"", declared_size=WRITE_CAP + 1) == [
        "too_large", "exit 1"], "a write over 64 MiB must answer too_large"
    assert not os.path.lexists(path), "an over-cap write must not land"
    server.assert_no_line()


def scenario_write_existing_destination_answers_exists(server):
    """An existing destination answers exists without asking, and is left alone."""
    path = make_transfer_file(server, "wexists.bin", b"keep me\n")
    assert write_frame(server, path, WRITE_BYTES) == ["exists", "exit 1"], (
        "a write onto an existing destination must answer exists")
    server.assert_no_line()
    assert read_bytes(path) == b"keep me\n", "an existing destination must not be replaced"
    assert "write.refused" in write_events(server, path), (
        "audit tail must show the refused write")


def scenario_write_protected_destinations_answer_87(server):
    """The token, a hard or symbolic link to it, the state directory and /system answer protected."""
    token = secret_path(server, "token")
    before = read_bytes(token)
    hard = write_path(server, "wprot-hard")
    soft = write_path(server, "wprot-soft")
    make_link(hard, token, hard=True)
    make_link(soft, token, hard=False)
    state_entry = os.path.join(os.path.dirname(token), "wprot-new")

    for target in (token, hard, soft, state_entry, "/system/wprot.bin"):
        assert write_frame(server, target, WRITE_BYTES) == [
            "protected", "exit 87"], (
            "write to %s must answer protected and exit 87" % target)
    server.assert_no_line()
    assert read_bytes(token) == before, "a protected token must not change"


def scenario_write_protected_after_grant_answers_87(server):
    """A destination that became a link to the token after the grant answers protected and writes nothing."""
    token = secret_path(server, "token")
    before = read_bytes(token)
    path = write_path(server, "wprot-late.bin")
    approval, challenge = write_request(server, path, WRITE_BYTES)
    sign_and_grant(server, approval, challenge)

    os.symlink(token, path)
    assert write_frame(server, path, WRITE_BYTES) == [
        "protected", "exit 87"], "an approved write through a link to the token must answer protected"
    assert read_bytes(token) == before, "a protected token must not change"


def scenario_write_changed_destination_answers_78(server):
    """A destination that appeared after the grant answers approval_stale and is left alone."""
    path = write_path(server, "wstale.bin")
    approval, challenge = write_request(server, path, WRITE_BYTES)
    sign_and_grant(server, approval, challenge)

    with open(path, "wb") as handle:
        handle.write(b"appeared after approval\n")

    assert write_frame(server, path, WRITE_BYTES) == [
        "approval_stale", "exit 78"], "a destination changed after the grant must answer approval_stale"
    assert read_bytes(path) == b"appeared after approval\n", (
        "a stale write must not replace the destination")
    assert "write.stale" in write_events(server, path), (
        "audit tail must show the stale write")


def scenario_write_denied_answers_77(server):
    """A write the owner denies answers approval_denied, writes nothing, and is audited."""
    path = write_path(server, "wdeny.bin")
    approval, _ = write_request(server, path, WRITE_BYTES)
    server.controller("deny %s" % approval, "denied %s" % approval)

    assert write_frame(server, path, WRITE_BYTES) == [
        "approval_denied", "exit 77"], "a denied write must answer approval_denied"
    assert not os.path.lexists(path), "a denied write must not land"
    assert "write.denied" in write_events(server, path), (
        "audit tail must show the denied write")


def sfocreate_path(server, name="PARAM.SFO"):
    return os.path.join(server.root, "data", name)


def sfocreate_line(options, path):
    """One sfocreate command line: every option, then the output path."""
    return " ".join(["sfocreate"] + ([options] if options else []) + [path])


def sfocreate_request(server, line):
    """An sfocreate that must ask the owner: 75, a challenge, a prompt."""
    server.advance(120_000)
    lines = run_command(server, line)
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "sfocreate must answer approval_required and exit 75, got %r" % lines)
    approval = APPROVAL_LINE.match(lines[0])
    challenge = CHALLENGE_LINE.match(lines[1])
    assert approval and challenge and challenge.group(1) == approval.group(1), (
        "expected approval_required and a matching challenge, got %r" % lines)
    prompt = GATE_PROMPT.match(server.next_line() or "")
    assert prompt and prompt.group(1) == approval.group(1), (
        "the owner must be asked about the create")
    return approval.group(1), lines[1]


def sfocreate_events(server, path):
    return {kind for kind, name, _, _ in audit_events(server) if name == path
            and kind.startswith("sfocreate.")}


def scenario_sfocreate_is_gated_and_lands(server):
    """sfocreate asks first, binds each option as text, and writes the SFO once."""
    path = sfocreate_path(server)
    options = "-i APP_VER=1 -s32 TITLE=Hello"
    approval, challenge = sfocreate_request(
        server, sfocreate_line(options, path))
    assert not os.path.lexists(path), "an unsigned sfocreate must not run"

    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=sfocreate\n"), action
    assert "\ntarget=%s\n" % path in action, action
    assert "\noption.kind=absent\n" in action, action
    for index, arg in enumerate(("-i", "APP_VER=1", "-s32", "TITLE=Hello"), 1):
        assert "\noption.arg%d=%s\n" % (index, arg) in action, action

    sign_and_grant(server, approval, challenge)
    assert run_command(server, sfocreate_line(options, path)) == ["exit 0"], (
        "a signed sfocreate must run")
    assert os.path.isfile(path), "sfocreate must create the output"
    assert run_command(server, "sfoinfo %s" % path) == [
        "APP_VER(0x00000001)", "TITLE('Hello')", "exit 0"], (
        "sfoinfo must read back what sfocreate wrote")
    assert {"sfocreate.request", "sfocreate.done"} <= sfocreate_events(
        server, path), "audit tail must show the request and the create"


def scenario_sfocreate_outside_data_answers_87(server):
    """An output path outside the writable roots answers protected without asking."""
    for target in ("/system/PARAM.SFO", "/etc/PARAM.SFO"):
        assert run_command(server, sfocreate_line("-i APP_VER=1", target)) == [
            "protected", "exit 87"], (
            "sfocreate to %s must answer protected and exit 87" % target)
    server.assert_no_line()
    assert kill_audit(server, "sfocreate.protected", "/system/PARAM.SFO"), (
        "the refusal must be in the audit log")


def scenario_sfocreate_bad_arguments_answer_without_asking(server):
    """A missing, relative or existing output and a bad option answer before asking."""
    kept = sfocreate_path(server, "exists.sfo")
    with open(kept, "wb") as handle:
        handle.write(b"keep me\n")
    for line, answer in (
            ("sfocreate", ["missing_operand", "exit 1"]),
            ("sfocreate relative.sfo", ["relative_path", "exit 1"]),
            (sfocreate_line("-q APP_VER=1",
                            sfocreate_path(server, "q.sfo")),
             ["bad_option", "exit 1"]),
            (sfocreate_line("-i APP_VER", sfocreate_path(server, "i.sfo")),
             ["bad_argument", "exit 1"]),
            (sfocreate_line("-i APP_VER=1", kept), ["exists", "exit 1"])):
        lines = run_command(server, line)
        assert lines == answer, (
            "%r must answer %r without asking, got %r" % (line, answer, lines))
    server.assert_no_line()
    with open(kept, "rb") as handle:
        assert handle.read() == b"keep me\n", (
            "an existing output must not be replaced")


def scenario_sfocreate_changed_destination_answers_78(server):
    """An output that appeared after the grant answers approval_stale and is left alone."""
    path = sfocreate_path(server, "stale.sfo")
    approval, challenge = sfocreate_request(
        server, sfocreate_line("-i APP_VER=1", path))
    sign_and_grant(server, approval, challenge)

    with open(path, "wb") as handle:
        handle.write(b"appeared after approval\n")

    assert run_command(server, sfocreate_line("-i APP_VER=1", path)) == [
        "approval_stale", "exit 78"], (
        "an output changed after the grant must answer approval_stale")
    with open(path, "rb") as handle:
        assert handle.read() == b"appeared after approval\n", (
            "a stale sfocreate must not replace the output")
    assert "sfocreate.stale" in sfocreate_events(server, path), (
        "audit tail must show the stale create")


WRITE_SCENARIOS = [
    ("write asks the owner with path, size and hash, lands once after a grant",
     scenario_write_is_gated_and_lands, HOST_ROOT_REASON),
    ("write answers upload_mismatch for a body that does not match its frame",
     scenario_write_mismatch_answers_like_push, HOST_ROOT_REASON),
    ("write over 64 MiB answers too_large before the owner is asked",
     scenario_write_over_cap_is_refused_before_asking, HOST_ROOT_REASON),
    ("write onto an existing destination answers exists and replaces nothing",
     scenario_write_existing_destination_answers_exists, HOST_ROOT_REASON),
    ("write to the token, its links, the state directory or /system answers "
     "protected and exit 87 without asking",
     scenario_write_protected_destinations_answer_87, HOST_ROOT_REASON),
    ("write whose destination became a link to the token after the grant "
     "answers protected and exit 87",
     scenario_write_protected_after_grant_answers_87, HOST_ROOT_REASON),
    ("write whose destination appeared after the grant answers approval_stale",
     scenario_write_changed_destination_answers_78, HOST_ROOT_REASON),
    ("write the owner denies answers approval_denied and is audited",
     scenario_write_denied_answers_77, HOST_ROOT_REASON),
]


SFOCREATE_SCENARIOS = [
    ("sfocreate asks the owner, binds its options as text, and writes the SFO "
     "once after a grant", scenario_sfocreate_is_gated_and_lands,
     HOST_ROOT_REASON),
    ("sfocreate to a path outside /data, /user and /mnt/usb* answers protected "
     "and exit 87 without asking", scenario_sfocreate_outside_data_answers_87,
     HOST_ROOT_REASON),
    ("sfocreate refuses a missing, relative or existing output and a bad "
     "option with its word, exit 1, before asking",
     scenario_sfocreate_bad_arguments_answer_without_asking, HOST_ROOT_REASON),
    ("an sfocreate output that appeared after the grant answers "
     "approval_stale and exit 78",
     scenario_sfocreate_changed_destination_answers_78, HOST_ROOT_REASON),
]


HELLO_OUTPUT = "Hello, world from Ariel!"

CHANGED_SOURCE = """
#include <stdio.h>

int
main(void) {
  printf("changed after approval\\n");
  return 0;
}
"""


def install_elf(server, name, data, directory="data"):
    """Write data as an executable file under the test root; return its path."""
    folder = os.path.join(server.root, directory)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, name)
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o755)
    return path


def scenario_elf_run_needs_the_owner(server):
    """A file run by path prints nothing until the owner signs, then runs once."""
    server.advance(120000)
    path = install_elf(server, "elf-hello", compile_payload(HELLO_SOURCE, "hello"))
    approval, challenge = gate_request(server, path)
    assert run_command(server, path)[-1] == "exit 75", (
        "a run before the signature must still ask")
    server.assert_no_line()
    sign_and_grant(server, approval, challenge)
    assert run_command(server, path) == [HELLO_OUTPUT, "status 0", "exit 0"], (
        "a signed run must print the payload's output, its status and exit 0")
    spent, _ = gate_request(server, path)
    assert spent != approval, "a signature is spent by the run it allowed"


def scenario_elf_changed_after_approval_answers_78(server):
    """A file rewritten after the owner signs answers approval_stale and does not run."""
    server.advance(120000)
    path = install_elf(server, "elf-changed", compile_payload(HELLO_SOURCE, "hello"))
    approval, challenge = gate_request(server, path)
    sign_and_grant(server, approval, challenge)
    with open(path, "wb") as handle:
        handle.write(compile_payload(CHANGED_SOURCE, "changed"))
    assert run_command(server, path) == ["approval_stale", "exit 78"], (
        "a file rewritten after approval must answer approval_stale")


def scenario_elf_replaced_answers_78(server):
    """A new object with the same bytes is another file: approval_stale, not run."""
    server.advance(120000)
    data = compile_payload(HELLO_SOURCE, "hello")
    path = install_elf(server, "elf-moved", data)
    approval, challenge = gate_request(server, path)
    sign_and_grant(server, approval, challenge)
    replacement = install_elf(server, "elf-moved-new", data)
    os.replace(replacement, path)
    assert run_command(server, path) == ["approval_stale", "exit 78"], (
        "a file replaced after approval must answer approval_stale")


def scenario_elf_on_path_needs_the_owner(server):
    """A bare name found on the PATH is gated as the file it resolves to."""
    server.advance(120000)
    binary = install_elf(server, "elf-path-hello",
                         compile_payload(HELLO_SOURCE, "hello"), "bin")
    saved = server.env
    server.env = dict(saved or {}, PATH=os.path.dirname(binary))
    server.restart()
    try:
        approval, challenge = gate_request(server, "elf-path-hello")
        assert "\ntarget=%s\n" % binary in decoded_action(
            challenge_action(challenge)), (
            "the challenge must name the resolved path, not the bare name")
        sign_and_grant(server, approval, challenge)
        assert run_command(server, "elf-path-hello") == [
            HELLO_OUTPUT, "status 0", "exit 0"], (
            "a signed PATH name must run the file it resolves to")
    finally:
        server.env = saved
        server.restart()


def scenario_elf_refusals_need_no_owner(server):
    """A missing path, a directory and a file without execute bits answer their word."""
    missing = os.path.join(server.root, "data", "elf-missing")
    assert run_command(server, missing) == ["no_such_file", "exit 1"]

    folder = os.path.join(server.root, "data", "elf-folder")
    os.makedirs(folder, exist_ok=True)
    assert run_command(server, folder) == ["not_a_file", "exit 1"]

    plain = os.path.join(server.root, "data", "elf-plain")
    with open(plain, "wb") as handle:
        handle.write(b"not a program\n")
    os.chmod(plain, 0o644)
    assert run_command(server, plain) == ["not_executable", "exit 1"], (
        "a file without execute bits must not be run")
    server.assert_no_line()


def scenario_elf_token_refused(server):
    """Ariel's token answers protected and exit 87 as a run, without asking."""
    token = secret_path(server, "token")
    assert run_command(server, token) == ["protected", "exit 87"], (
        "the token must never be run")
    server.assert_no_line()
    assert any(AUDIT_LINE.match(event) and event.split()[1] == "run.protected"
               for event in audit_tail(server)), (
        "the refusal must be in the audit log")


def scenario_elf_run_is_audited(server):
    """A run's request, grant, start and exit status reach audit tail in that order."""
    server.advance(120000)
    path = install_elf(server, "elf-audited", compile_payload(HELLO_SOURCE, "hello"))
    approval, challenge = gate_request(server, path)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, path) == [HELLO_OUTPUT, "status 0", "exit 0"]
    ours = [event.split() for event in audit_tail(server)
            if AUDIT_LINE.match(event) and event.split()[2] == path
            and event.split()[3] == approval]
    kinds = [fields[1] for fields in ours]
    assert kinds == ["run.request", "grant", "run.start", "run.status"], (
        "the audit log must show the request, the grant, the start and the status: %r"
        % kinds)
    assert ours[-1][4] == "status-0", (
        "the status line must carry the payload's status, got %r" % ours[-1])


def scenario_elf_action_names_its_facts(server):
    """The challenge of a run names the command, the path, the file's sha256 and identity."""
    server.advance(120000)
    data = compile_payload(HELLO_SOURCE, "hello")
    path = install_elf(server, "elf-facts", data)
    _, challenge = gate_request(server, path)
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=run\n"), action
    assert "\ntarget=%s\n" % path in action, action
    assert "\nsha256=%s\n" % hashlib.sha256(data).hexdigest() in action, action
    assert "\noption.kind=file\n" in action, action
    assert "\noption.dev=" in action and "\noption.ino=" in action, action


SYSTEM_NOT_AVAILABLE = ["not available on this platform", "exit 1"]


def scenario_system_commands_need_the_owner(server):
    """mount, umount, chroot and mknod ask first, and once signed are not available on the host."""
    mount_point = os.path.join(server.root, "data", "mount-point")
    jail = os.path.join(server.root, "data", "jail")
    node = os.path.join(server.root, "data", "node")
    source = os.path.join(server.root, "data", "src")
    os.makedirs(mount_point, exist_ok=True)
    os.makedirs(jail, exist_ok=True)
    os.makedirs(source, exist_ok=True)

    for command in (
        "mount -t nullfs %s %s" % (source, mount_point),
        "umount " + mount_point,
        "chroot " + jail,
        "mknod %s b 8 0" % node,
    ):
        approval, challenge = gate_request(server, command)
        assert not os.path.exists(node), "an unsigned mknod must not create the node"
        sign_and_grant(server, approval, challenge)
        assert run_command(server, command) == SYSTEM_NOT_AVAILABLE, (
            "%s must answer not available on this platform after a grant"
            % command)
    assert not os.path.exists(node), "the host must not create the node"


def scenario_system_command_bad_argument(server):
    """A system command with a missing or malformed argument is refused before the owner is asked."""
    node = os.path.join(server.root, "data", "bad-node")
    for command in (
        "mknod %s q 8 0" % node,
        "mknod %s b 256 0" % node,
        "mknod %s b 8" % node,
        "mount -t nullfs " + node,
        "chroot",
        "umount",
    ):
        assert run_command(server, command) == ["bad_argument", "exit 1"], (
            "%s must answer bad_argument and exit 1" % command)
    assert not os.path.exists(node), "a refused mknod must not create the node"
    server.assert_no_line()


def scenario_system_commands_protected_without_asking(server):
    """Ariel's token, through a hard or symbolic link, and a mount outside the writable roots answer protected."""
    secret = secret_path(server, "token")
    hard = os.path.join(server.root, "data", "token-hard")
    soft = os.path.join(server.root, "data", "token-soft")
    make_link(hard, secret, hard=True)
    make_link(soft, secret, hard=False)
    mount_point = os.path.join(server.root, "data", "mount-point")
    os.makedirs(mount_point, exist_ok=True)

    for command in (
        "mount -t nullfs / /mnt",
        "umount " + hard,
        "mknod %s c 1 0" % hard,
        "chroot " + soft,
    ):
        assert_protected(server, command)
    server.assert_no_line()


def scenario_system_command_stale_answers_78(server):
    """An object that appears under a mknod's name after the owner signs answers approval_stale."""
    node = os.path.join(server.root, "data", "stale-node")
    approval, challenge = gate_request(server, "mknod %s c 1 0" % node)
    sign_and_grant(server, approval, challenge)

    open(node, "wb").close()
    assert run_command(server, "mknod %s c 1 0" % node) == [
        "approval_stale", "exit 78"], (
        "an object created after approval must answer approval_stale")
    assert stat_exit(server, node) == "exit 0", (
        "a stale approval must not touch the object")


def scenario_system_command_names_its_facts(server):
    """The challenge of mount and mknod names the command, its target and its options."""
    mount_point = os.path.join(server.root, "data", "mount-point")
    source = os.path.join(server.root, "data", "src")
    node = os.path.join(server.root, "data", "node")
    os.makedirs(mount_point, exist_ok=True)
    os.makedirs(source, exist_ok=True)

    approval, challenge = gate_request(
        server, "mount -t nullfs %s %s" % (source, mount_point))
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=mount\n"), action
    assert "\ntarget=%s\n" % mount_point in action, action
    assert "\noption.fstype=nullfs\n" in action, action
    assert "\noption.from=%s\n" % source in action, action
    sign_and_grant(server, approval, challenge)

    approval, challenge = gate_request(server, "mknod %s b 8 0" % node)
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=mknod\n"), action
    assert "\ntarget=%s\n" % node in action, action
    assert "\noption.type=b\n" in action, action
    assert "\noption.major=8\n" in action and "\noption.minor=0\n" in action, action
    sign_and_grant(server, approval, challenge)


def scenario_system_commands_are_audited(server):
    """Requests, unavailable runs and protected refusals of system commands reach audit tail."""
    mount_point = os.path.join(server.root, "data", "mount-point")
    hard = os.path.join(server.root, "data", "token-audit")
    os.makedirs(mount_point, exist_ok=True)
    make_link(hard, secret_path(server, "token"), hard=True)

    approval, challenge = gate_request(server, "umount " + mount_point)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "umount " + mount_point) == SYSTEM_NOT_AVAILABLE
    assert_protected(server, "mknod %s c 1 0" % hard)

    kinds = set()
    for line in run_exit_zero(server, "audit tail 64"):
        fields = line.split()
        if len(fields) == 5:
            kinds.add(fields[1])
    for kind in ("umount.request", "umount.unavailable", "mknod.protected"):
        assert kind in kinds, "audit tail must show %s, got %r" % (
            kind, sorted(kinds))
def make_archive(server, name, members):
    """A stored zip in the host test root's data directory, members in order.

    Each member is (name, bytes); a name ending in '/' is a directory entry.
    """
    path = os.path.join(server.root, "data", name)
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in members:
            info = zipfile.ZipInfo(member)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)
    return path


def unzip_destination(server, name):
    """An empty directory in the host test root's data directory."""
    path = os.path.join(server.root, "data", name)
    os.makedirs(path)
    return path


def tree(path):
    """Every entry under path, relative to it, sorted."""
    found = []
    for base, dirs, files in os.walk(path):
        for entry in dirs + files:
            found.append(os.path.relpath(os.path.join(base, entry), path))
    return sorted(found)


def unzip_line(archive, destination):
    return "unzip %s %s" % (archive, destination)


def scenario_unzip_list_runs_at_once(server):
    """unzip -l lists the members at once, with their sizes, and asks nothing."""
    archive = make_archive(server, "unzip-list", [
        ("bundle/", b""), ("bundle/hello.txt", b"hello\n"), ("top.txt", b"0123456789")])
    assert run_command(server, "unzip -l " + archive) == [
        "0 bundle/", "6 bundle/hello.txt", "10 top.txt", "exit 0"], (
        "unzip -l must list the members at once")

    garbage = os.path.join(server.root, "data", "unzip-garbage")
    with open(garbage, "wb") as handle:
        handle.write(b"not a zip archive\n")
    assert run_command(server, "unzip -l " + garbage) == [
        "bad_archive", "exit 1"], "a file that is no zip must answer bad_archive"


def scenario_unzip_extract_needs_the_owner(server):
    """unzip asks first, extracts after the owner signs, and asks again once cleared."""
    archive = make_archive(server, "unzip-bundle", [
        ("nested/", b""), ("nested/hello.txt", b"hello\n"), ("top.txt", b"top\n")])
    destination = unzip_destination(server, "unzip-out")
    line = unzip_line(archive, destination)

    approval, challenge = transfer_request(server, line)
    assert tree(destination) == [], "an unsigned unzip must not extract"
    sign_and_grant(server, approval, challenge)
    assert run_command(server, line) == ["exit 0"], "a signed unzip must run"
    assert read_bytes(os.path.join(destination, "nested", "hello.txt")) == b"hello\n"
    assert read_bytes(os.path.join(destination, "top.txt")) == b"top\n"

    assert run_command(server, line) == ["exists", "exit 1"], (
        "an unzip into a filled destination must refuse before any approval")

    shutil.rmtree(destination)
    os.makedirs(destination)
    spent, _ = transfer_request(server, line)
    assert spent != approval, "a spent unzip approval must not be asked again"


def scenario_unzip_refuses_escaping_members(server):
    """A member with ../ or an absolute path refuses the whole archive, unasked and unwritten."""
    destination = unzip_destination(server, "unzip-escape")
    cases = (
        ("parent", [("ok.txt", b"ok\n"), ("../unzip-parent.txt", b"x\n")]),
        ("absolute", [("/data/unzip-absolute.txt", b"x\n")]),
        ("nested", [("a/../../unzip-nested.txt", b"x\n")]),
    )
    for label, members in cases:
        archive = make_archive(server, "unzip-esc-" + label, members)
        assert run_command(server, unzip_line(archive, destination)) == [
            "unsafe_member", "exit 1"], (
            "a %s member must refuse the archive with unsafe_member" % label)
    assert tree(destination) == [], "a refused archive must write nothing"
    assert not os.path.lexists(os.path.join(server.root, "data", "unzip-parent.txt"))
    assert not os.path.lexists(os.path.join(server.root, "data", "unzip-absolute.txt"))
    assert not os.path.lexists(os.path.join(server.root, "data", "unzip-nested.txt"))


def scenario_unzip_archive_changed_answers_78(server):
    """An archive replaced or rewritten after the owner signs answers approval_stale."""
    for mode in ("replaced", "rewritten"):
        archive = make_archive(server, "unzip-swap-" + mode, [("swap.txt", b"signed\n")])
        destination = unzip_destination(server, "unzip-swap-out-" + mode)
        line = unzip_line(archive, destination)
        approval, challenge = transfer_request(server, line)
        sign_and_grant(server, approval, challenge)

        other = make_archive(server, "unzip-swap-other", [("swap.txt", b"swapped\n")])
        if mode == "replaced":
            replacement = archive + "-new"
            os.replace(other, replacement)
            os.replace(replacement, archive)
        else:
            with open(other, "rb") as handle:
                data = handle.read()
            with open(archive, "wb") as handle:
                handle.write(data)

        assert run_command(server, line) == ["approval_stale", "exit 78"], (
            "an archive %s after approval must answer approval_stale" % mode)
        assert tree(destination) == [], (
            "a changed archive (%s) must not extract" % mode)


def scenario_unzip_protected_objects_answer_87(server):
    """unzip refuses Ariel's own objects as archive or destination through any alias."""
    token = secret_path(server, "token")
    before = read_bytes(token)
    state = os.path.dirname(token)
    destination = unzip_destination(server, "unzip-prot-out")
    hard = os.path.join(server.root, "data", "unzip-prot-hard")
    soft = os.path.join(server.root, "data", "unzip-prot-soft")
    make_link(hard, token, hard=True)
    make_link(soft, token, hard=False)

    for archive in (token, hard, soft):
        assert run_command(server, "unzip -l " + archive) == [
            "protected", "exit 87"], "listing %s must answer protected" % archive
        assert run_command(server, unzip_line(archive, destination)) == [
            "protected", "exit 87"], "extracting %s must answer protected" % archive

    good = make_archive(server, "unzip-prot-src", [("p.txt", b"p\n")])
    assert run_command(server, unzip_line(good, state)) == [
        "protected", "exit 87"], "unzip into the state directory must answer protected"

    line = unzip_line(good, destination)
    approval, challenge = transfer_request(server, line)
    sign_and_grant(server, approval, challenge)
    os.unlink(good)
    os.link(token, good)
    assert run_command(server, line) == ["protected", "exit 87"], (
        "an approved unzip of an archive that became the token must answer protected")
    assert tree(destination) == [], "a protected archive must extract nothing"
    assert read_bytes(token) == before, "a protected token must not change"


def scenario_unzip_outside_writable_roots_answers_87(server):
    """unzip refuses a destination outside /data, /user and /mnt/usb* without asking."""
    for line in (
        "unzip /data/unzip-src /system/unzip-out",
        "unzip /system/unzip-src /system/unzip-out",
    ):
        assert run_command(server, line) == ["protected", "exit 87"], (
            "%s must answer protected and exit 87" % line)


def scenario_unzip_actions_are_audited(server):
    """unzip lists, runs and refusals reach audit tail under their paths."""
    archive = make_archive(server, "unzip-audit", [("a.txt", b"a\n")])
    destination = unzip_destination(server, "unzip-audit-out")
    bad = make_archive(server, "unzip-audit-bad", [("../unzip-audit-escape.txt", b"x\n")])
    line = unzip_line(archive, destination)

    approval, challenge = transfer_request(server, line)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, line) == ["exit 0"]
    assert run_exit_zero(server, "unzip -l " + archive) == ["2 a.txt"]
    assert run_command(server, unzip_line(bad, destination)) == [
        "unsafe_member", "exit 1"]

    events = set()
    for line_text in run_exit_zero(server, "audit tail 64"):
        fields = line_text.split()
        if len(fields) == 5:
            events.add((fields[1], fields[2]))
    subject = "%s>%s" % (archive, destination)
    expected = (
        ("unzip.request", subject),
        ("unzip.done", subject),
        ("unzip.list", archive),
        ("unzip.refused", "%s>%s" % (bad, destination)),
    )
    for event in expected:
        assert event in events, (
            "audit tail must show %r, got %r" % (event, sorted(events)))


def scenario_elf_arguments_are_signed(server):
    """A run's arguments are part of what the owner signs: other ones answer approval_stale."""
    server.advance(120000)
    path = install_elf(server, "elf-args", compile_payload(HELLO_SOURCE, "hello"))
    approval, challenge = gate_request(server, path)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, path + " extra") == ["approval_stale", "exit 78"], (
        "a run with arguments the owner did not sign must answer approval_stale")
    server.assert_no_line()

    approval, challenge = gate_request(server, path + " extra")
    action = decoded_action(challenge_action(challenge))
    assert "\noption.argc=1\n" in action and "\noption.arg0=extra\n" in action, (
        "the challenge must carry the arguments, got %r" % action)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, path + " extra") == [
        HELLO_OUTPUT, "argv[1] = extra", "status 0", "exit 0"], (
        "a run with the signed arguments must run once")


def scenario_elf_arguments_the_signer_cannot_show_are_refused(server):
    """A printable argument is signed as an escaped option; a byte outside printable ASCII answers bad_path; over eight answers unknown."""
    server.advance(120000)
    path = install_elf(server, "elf-args-refused", compile_payload(HELLO_SOURCE, "hello"))
    approval, challenge = gate_request(server, path + " /user")
    action = challenge_action(challenge)
    assert "\noption.arg0=%2Fuser\n" in action, (
        "a slash in an argument must be escaped in the signed action, got %r"
        % action)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, path + " /user") == [
        HELLO_OUTPUT, "argv[1] = /user", "status 0", "exit 0"], (
        "a printable argument the owner signed must run")
    for what, bad in (("Unicode", b"\xc3\xa9"),
                      ("combining mark", b"\xcc\x81"),
                      ("right-to-left override", b"\xe2\x80\xae"),
                      ("DEL", b"\x7f")):
        assert run_command_bytes(server, path.encode("ascii") + b" " +
                                 bad) == ["bad_path", "exit 1"], (
            "a %s in an argument must answer bad_path" % what)
        server.assert_no_line()
    assert run_command(server, path + " " + " ".join(["a"] * 9)) == [
        "unknown_command", "exit 1"], (
        "more arguments than the signer carries must be refused")
    server.assert_no_line()


def scenario_elf_too_large_answers_too_large(server):
    """A file over the run limit answers too_large and exit 1 without asking."""
    path = install_elf(server, "elf-large", b"")
    os.truncate(path, 64 * 1024 * 1024 + 1)
    assert run_command(server, path) == ["too_large", "exit 1"], (
        "a file over 64 MiB must answer too_large and exit 1")
    server.assert_no_line()


def scenario_elf_symbolic_link_is_refused(server):
    """A run never follows a symbolic link, by path or on the PATH: symbolic_link, exit 1."""
    target = install_elf(server, "elf-link-target", compile_payload(HELLO_SOURCE, "hello"))
    link = os.path.join(server.root, "data", "elf-link")
    os.symlink(target, link)
    assert run_command(server, link) == ["symbolic_link", "exit 1"], (
        "a symbolic link must not be run")
    server.assert_no_line()

    folder = os.path.join(server.root, "bin")
    os.makedirs(folder, exist_ok=True)
    os.symlink(target, os.path.join(folder, "elf-path-link"))
    saved = server.env
    server.env = dict(saved or {}, PATH=folder)
    server.restart()
    try:
        assert run_command(server, "elf-path-link") == ["symbolic_link", "exit 1"], (
            "a PATH entry that is a symbolic link must not be run")
        server.assert_no_line()
    finally:
        server.env = saved
        server.restart()


def scenario_two_connections(server):
    first = server.connect(timeout=3.0)
    try:
        first.sendall(("auth %s\n" % server.token).encode("ascii"))
        # The first connection is served and waits for its command.
        server.settle(1)
        second = server.connect(timeout=3.0)
        try:
            second.sendall(
                ("auth %s\nanything\n" % server.token).encode("ascii")
            )
            second.settimeout(2.0)
            assert_gated(read_reply(second))
        finally:
            second.close()
        first.sendall(b"anything\n")
        first.settimeout(2.0)
        assert_gated(read_reply(first))
    finally:
        first.close()


def scenario_connection_limit(server):
    """At most four connections are served; a fifth answers busy, exit 82."""
    held = []
    try:
        for _ in range(4):
            sock = server.connect()
            sock.sendall(("auth %s\n" % server.token).encode("ascii"))
            held.append(sock)

        fifth = server.connect()
        try:
            assert reply_lines(read_reply(fifth)) == ["busy", "exit 82"], (
                "a fifth concurrent connection must answer busy and exit 82")
        finally:
            fifth.close()
    finally:
        for sock in held:
            sock.close()

    # Every slot is free again before the next scenario connects.
    server.settle(0)


def scenario_refusal_slots_exhausted(server):
    """With four served and four refused, the ninth still gets busy, exit 82."""
    served = []
    refused = []
    try:
        for _ in range(4):
            sock = server.connect()
            sock.sendall(("auth %s\n" % server.token).encode("ascii"))
            served.append(sock)

        # A refused client that keeps its write side open holds its slot
        # until the close drain ends, so these four take every refusal slot.
        for _ in range(4):
            sock = server.connect()
            sock.settimeout(1.0)
            assert reply_lines(recv_busy(sock)) == ["busy", "exit 82"], (
                "a refused connection must answer busy and exit 82")
            refused.append(sock)
        server.settle(8)

        # The ninth client sends its auth line only after busy arrives, the
        # worst case for a reset: the refusal must still drain it and end in
        # an orderly EOF once the close drain's deadline passes.
        ninth = server.connect()
        try:
            ninth.settimeout(1.0)
            assert reply_lines(recv_busy(ninth)) == ["busy", "exit 82"], (
                "with every refusal slot taken the ninth connection must "
                "still answer busy and exit 82")
            ninth.sendall(("auth %s\n" % server.token).encode("ascii"))
            # The eight held connections and the one drain wait for time.
            server.settle(9)
            server.advance(CLOSE_DRAIN_MS)
            try:
                rest = ninth.recv(4096)
            except ConnectionResetError:
                raise AssertionError(
                    "a refusal past every slot must close with EOF, "
                    "not a reset")
            assert rest == b"", "a refusal sends nothing after busy"
        finally:
            ninth.close()
    finally:
        for sock in refused + served:
            sock.close()

    # Every slot is free again before the next scenario connects.
    server.settle(0)


def scenario_stalled_upload_does_not_block(server):
    """One client stalls an upload; another connection still answers fast."""
    stalled = server.connect()
    try:
        stalled.sendall(("auth %s\npayload push stalled 100 %s\n"
                         % (server.token, "0" * 64)).encode("ascii"))
        stalled.sendall(b"partial")

        started = time.monotonic()
        sock = server.connect()
        try:
            sock.sendall(("auth %s\nnonsense\n" % server.token)
                         .encode("ascii"))
            assert_gated(read_reply(sock))
        finally:
            sock.close()
        elapsed = time.monotonic() - started
        assert elapsed < 1.0, (
            "a stalled upload blocked another connection for %.2f s" % elapsed)

        # The stalled upload ends at its own 59 s stall, which stays below
        # the 60 s connection deadline: a stall is upload_mismatch, not
        # timed_out.
        server.settle(1)
        server.advance(58_999)
        server.settle(1)
        assert_open(stalled, "1 ms before the upload stall deadline")

        server.advance(1)
        server.settle(1)
        stalled.settimeout(1.0)
        reply = read_reply(stalled)
        assert reply_lines(reply) == ["upload_mismatch", "exit 81"], (
            "a stalled upload must end in upload_mismatch, got %r" % reply)
    finally:
        stalled.close()


def scenario_truncated_upload(server):
    assert_mismatch(server, push(server, "helloworld", b"hello",
                                 declared_size=6))


def scenario_extra_bytes(server):
    assert_mismatch(server, push(server, "helloworld", b"hello!",
                                 declared_size=5))


def scenario_hash_mismatch(server):
    assert_mismatch(server, push(server, "helloworld", b"hello",
                                 declared_hash="0" * 64))


def scenario_bad_name(server):
    for name in ("../x", "-payload", "Upper", "a" * 33):
        lines = push(server, name, b"")
        assert lines == ["bad_name", "exit 1"], (
            "expected bad_name and a nonzero exit, got %r for %r"
            % (lines, name)
        )
        server.assert_no_line()


def scenario_matching_push(server):
    decide_push(server, "helloworld", b"hello world\n", "approve")


def scenario_fragmented_upload(server):
    # Every byte value, 0xff included, sent in many small pieces.
    data = bytes(range(256)) * 64
    decide_push(server, "fragmented", data, "approve",
                fragments=[1, 2, 3, 5, 7, 11, 4096, 1])


def scenario_elf_with_ff(server):
    elf = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\xff" * 128 +
           b"\x00\xff" * 256)
    decide_push(server, "elf", elf, "approve")


def scenario_denied_push(server):
    decide_push(server, "denied", b"deny me", "deny")


# Every scenario the headless suite runs, in report order. The third field
# says whether the scenario's behavior is defined by moving the host test
# clock; console mode reads this table to skip and name exactly those.

# ---------------------------------------------------------------------------
# The owner's signature is the approval source (ADR-0006).
# ---------------------------------------------------------------------------

CHALLENGE_LINE = re.compile(
    r"^challenge (a-[0-9a-f]+) (\S+) ([0-9a-f]{32}) (\d+) (\d+) ([0-9a-f]+) (\d+)$")


def tests_dir():
    return os.path.dirname(os.path.abspath(__file__))


def repo_dir():
    return os.path.dirname(os.path.dirname(tests_dir()))


def signer_path(server):
    return os.path.join(os.path.dirname(os.path.abspath(server.binary)),
                        "ariel-sign")


def test_key():
    return os.path.join(tests_dir(), "testkey")


def push_for_challenge(server, name, data):
    """Push, check the prompt and return (staging, approval, challenge).

    The console shows one notification every 10 s and holds three pending
    approvals, so the test clock moves past an approval's whole life first;
    what an earlier scenario left pending has then expired.
    """
    server.advance(120000)
    lines = push(server, name, data)
    assert len(lines) == 4, "expected four reply lines, got %r" % lines
    staged = STAGED_LINE.match(lines[0])
    approval = APPROVAL_LINE.match(lines[1])
    challenge = CHALLENGE_LINE.match(lines[2])
    assert staged and approval and challenge, (
        "expected staged, approval_required and challenge lines, got %r"
        % lines)
    assert lines[3] == "exit 75", "expected exit 75, got %r" % lines[3]
    assert challenge.group(1) == approval.group(1), (
        "the challenge names %s but the reply names %s"
        % (challenge.group(1), approval.group(1)))
    prompt = server.next_line()
    match = PROMPT_LINE.match(prompt or "")
    assert match and match.group(1) == approval.group(1), (
        "expected the approval prompt, got %r" % prompt)
    return staged.group(1), approval.group(1), lines[2]


def challenge_action(challenge):
    return bytes.fromhex(CHALLENGE_LINE.match(challenge).group(6)).decode(
        "ascii")


def decoded_action(action):
    """The action as the owner reads it: the encoder's %XX escapes undone."""
    return re.sub(r"%([0-9A-F]{2})",
                  lambda match: chr(int(match.group(1), 16)), action)


SAFE_ACTION_BYTES = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")


def escape_value(value):
    """The encoder's rule: bytes outside letters, digits, '.', '_' and '-'."""
    return "".join(char if char in SAFE_ACTION_BYTES
                   else "%%%02X" % ord(char) for char in value)


def escape_option_line(line):
    """One canonical 'key=value' line with its value escaped."""
    newline = "\n" if line.endswith("\n") else ""
    key, sep, value = line[:-len(newline) if newline else None].partition("=")
    return line if not sep else key + "=" + escape_value(value) + newline


def action_facts(challenge):
    """The action's lines as the owner reads them."""
    return decoded_action(challenge_action(challenge)).split("\n")


def run_signer(server, challenge, key=None):
    """Sign a challenge line with the offline signer."""
    return subprocess.run(
        [signer_path(server), "sign", key or test_key(), "--yes"],
        input=challenge + "\n", capture_output=True, text=True)


def sign_challenge(server, challenge, key=None):
    """Sign a challenge line with the offline signer; return the hex."""
    done = run_signer(server, challenge, key)
    assert done.returncode == 0, "the signer failed: %r" % done.stderr
    # The signer decodes the action it signs before showing it, never a
    # summary and never the raw escapes the owner would have to read.
    assert decoded_action(challenge_action(challenge)) in done.stderr, (
        "the signer must print the decoded action as signed, got %r"
        % done.stderr)
    envelope = done.stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{128} \S+ [0-9a-f]{64}", envelope), (
        "expected a signature, the console and the action hash, got %r"
        % envelope)
    parts = challenge.split(" ")
    action = bytes.fromhex(parts[6])
    assert envelope.split(" ")[1:] == [
        parts[2], hashlib.sha256(action).hexdigest()], (
        "the envelope must name the console and the action it signed")
    return envelope


def signature_of(envelope):
    """The bare signature of a signer's output line."""
    return envelope.split(" ")[0]


def retarget(challenge, old, new):
    """The challenge with old replaced by new in its canonical action."""
    parts = challenge.split(" ")
    action = bytes.fromhex(parts[6]).decode("ascii")
    assert old in action, "%r is not in the action" % old
    parts[6] = action.replace(old, new).encode("ascii").hex()
    return " ".join(parts)


def challenge_of(lines):
    """The challenge line of a push's reply."""
    found = [line for line in lines if CHALLENGE_LINE.match(line)]
    assert len(found) == 1, "expected one challenge line, got %r" % lines
    return found[0]


def sign_and_grant(server, approval, challenge):
    """The owner's step: sign the challenge, submit it, expect the grant."""
    signature = sign_challenge(server, challenge)
    assert grant(server, approval, signature) == [
        "approval_granted %s" % approval, "exit 0"], (
        "the owner's signature must grant the approval")


def grant(server, approval, signature):
    sock = server.connect()
    try:
        sock.sendall(("auth %s\napproval grant %s %s\n"
                      % (server.token, approval, signature)).encode("ascii"))
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def assert_not_run(server, name, staging, approval):
    """Nothing ran and nothing installed: the commit still waits."""
    assert commit(server, staging) == ["approval_required %s" % approval,
                                       "exit 75"], (
        "a refused grant must leave the approval pending")
    assert run_payload(server, name) == ["unknown_payload", "exit 1"], (
        "a refused grant must install nothing")


def scenario_signature_loop(server):
    """Request, sign with the test key, grant, commit and run once."""
    data = compile_payload('#include <stdio.h>\nint main(void) {'
                           ' puts("signed and run"); return 0; }\n',
                           "signedloop")
    staging, approval, challenge = push_for_challenge(
        server, "signedloop", data)
    action = challenge_action(challenge)
    assert action.startswith("ariel-action-v1\n"), action
    assert "target=signedloop\n" in action, action
    assert "sha256=%s\n" % hashlib.sha256(data).hexdigest() in action, action
    parts = CHALLENGE_LINE.match(challenge).groups()
    assert int(parts[4]) - int(parts[3]) == 120000, (
        "the challenge expires after the approval expiry: %r" % (parts,))
    assert commit(server, staging) == ["approval_required %s" % approval,
                                       "exit 75"], (
        "a commit before the grant must wait")
    signature = sign_challenge(server, challenge)
    assert grant(server, approval, signature) == [
        "approval_granted %s" % approval, "exit 0"]
    digest = hashlib.sha256(data).hexdigest()
    assert commit(server, staging) == ["installed signedloop %s" % digest,
                                       "exit 0"]
    assert run_payload(server, "signedloop") == [
        "signed and run", "status 0", "exit 0"]


def scenario_signature_forged(server):
    data = b"forged approval"
    staging, approval, challenge = push_for_challenge(
        server, "forged", data)
    with tempfile.TemporaryDirectory() as scratch:
        key = os.path.join(scratch, "other.key")
        made = subprocess.run([signer_path(server), "keygen", key],
                              capture_output=True, text=True)
        assert made.returncode == 0, made.stderr
        forged = sign_challenge(server, challenge, key=key)
    assert grant(server, approval, forged) == ["signature_invalid",
                                               "exit 79"]
    assert grant(server, approval, signature_of(forged)) == [
        "signature_invalid", "exit 79"], (
        "a bare forged signature is refused the same way")
    assert_not_run(server, "forged", staging, approval)


def scenario_signature_wrong_action(server):
    data = b"a swapped action"
    staging, approval, challenge = push_for_challenge(
        server, "swapped", data)
    digest = hashlib.sha256(data).hexdigest()
    swaps = [
        ("command", "command=payload.commit", "command=payload.delete"),
        ("target", "target=swapped", "target=other"),
        ("hash", "sha256=%s" % digest, "sha256=%s" % ("0" * 64)),
    ]
    for what, old, new in swaps:
        signature = sign_challenge(server, retarget(challenge, old, new))
        assert grant(server, approval, signature) == [
            "signature_action_mismatch", "exit 85"], (
            "a signature for a different %s must be refused" % what)
    assert_not_run(server, "swapped", staging, approval)


def scenario_signature_wrong_console(server):
    data = b"another console"
    staging, approval, challenge = push_for_challenge(
        server, "elsewhere", data)
    console = CHALLENGE_LINE.match(challenge).group(2)
    parts = challenge.split(" ")
    parts[2] = console + "-two"
    signature = sign_challenge(server, " ".join(parts))
    assert grant(server, approval, signature) == [
        "signature_console_mismatch", "exit 86"]
    assert_not_run(server, "elsewhere", staging, approval)


def scenario_signer_refuses_hidden_bytes(server):
    """The signer signs only what it can show: no NULs, no controls."""
    data = b"hidden bytes"
    _staging, _approval, challenge = push_for_challenge(
        server, "hidden", data)
    parts = challenge.split(" ")
    action = bytes.fromhex(parts[6])
    hidden = [("NUL", action + b"\0command=other\n"),
              ("escape", action + b"\x1b[2J"),
              ("carriage return", action.replace(b"\n", b"\r\n", 1)),
              ("high byte", action + b"\xc3\xa9"),
              ("escaped control", action + b"%1B"),
              ("escaped newline", action + b"%0A"),
              ("broken escape", action + b"%2"),
              ("lowercase escape", action + b"%2f")]
    for what, bad in hidden:
        parts[6] = bad.hex()
        done = subprocess.run(
            [signer_path(server), "sign", test_key(), "--yes"],
            input=" ".join(parts) + "\n", capture_output=True, text=True)
        assert done.returncode != 0 and done.stdout == "", (
            "the signer must refuse an action with a %s, got %r"
            % (what, done.stdout))


def scenario_signature_expired(server):
    data = b"too late to sign"
    staging, approval, challenge = push_for_challenge(
        server, "latesign", data)
    signature = sign_challenge(server, challenge)
    server.advance(120000)
    assert grant(server, approval, signature) == ["approval_expired",
                                                  "exit 88"]
    assert commit(server, staging) == ["approval_expired", "exit 88"]
    assert grant(server, approval, signature) == ["approval_stale", "exit 78"], (
        "once the expired object has left, its signature must be stale")
    assert run_payload(server, "latesign") == ["unknown_payload", "exit 1"]


def scenario_signature_malformed(server):
    data = b"a bad signature"
    staging, approval, challenge = push_for_challenge(
        server, "malformed", data)
    good = signature_of(sign_challenge(server, challenge))
    for what, signature in [("not hex", "zz" * 64),
                            ("too short", good[:-2]),
                            ("too long", good + "00"),
                            ("odd length", good[:-1]),
                            ("uppercase", good.upper()),
                            ("empty", "-")]:
        assert grant(server, approval, signature) == [
            "signature_malformed", "exit 83"], (
            "a signature that is %s must be malformed" % what)
    assert_not_run(server, "malformed", staging, approval)


def scenario_signature_twice(server):
    data = healthy_build("one-signature-build")
    staging, approval, challenge = push_for_challenge(
        server, "twice", data)
    signature = sign_challenge(server, challenge)
    assert grant(server, approval, signature) == [
        "approval_granted %s" % approval, "exit 0"]
    assert grant(server, approval, signature) == ["approval_replayed",
                                                  "exit 84"]
    digest = hashlib.sha256(data).hexdigest()
    assert commit(server, staging) == ["installed twice %s" % digest,
                                       "exit 0"]
    # The approval is spent: the same signature gets nothing now.
    assert grant(server, approval, signature) == ["approval_stale",
                                                  "exit 78"]


def scenario_signature_replay_after_restart(server):
    """A nonce consumed before a restart is not good again after it."""
    del server  # this scenario needs a nonce stream it can repeat
    replay = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "replay"})
    try:
        data = b"replayed after a restart"
        staging, approval, challenge = push_for_challenge(
            replay, "replayed", data)
        signature = sign_challenge(replay, challenge)
        assert grant(replay, approval, signature) == [
            "approval_granted %s" % approval, "exit 0"]
        replay.restart()
        staging, again, repeated = push_for_challenge(
            replay, "replayed", data)
        # Without the persisted nonces the seeded stream would offer the
        # same challenge again; a different one shows the file was loaded.
        assert repeated != challenge, (
            "a nonce consumed before the restart must not be offered again")
        assert CHALLENGE_LINE.match(repeated).group(3) != (
            CHALLENGE_LINE.match(challenge).group(3)), (
            "the new challenge must carry a fresh nonce")
        assert grant(replay, again, signature) == ["signature_invalid",
                                                   "exit 79"], (
            "a signature given before the restart must not decide a new "
            "approval")
        assert_not_run(replay, "replayed", staging, again)
    finally:
        replay.stop()


# ---------------------------------------------------------------------------
# Key hierarchy (ADR-0009): a primary key signs everyday approvals, a recovery
# key is never on the agent's side, and `key rotate` moves the primary to a
# new key under a new generation. Each scenario gets its own Ariel, because a
# rotation changes what every later approval must be signed with.
# ---------------------------------------------------------------------------

SECOND_PRIMARY_KEY = os.path.join(tests_dir(), "host-second-primary-testkey")
RECOVERY_KEY = os.path.join(tests_dir(), "host-recovery-testkey")
ROTATE_PROMPT = "key rotate will run"


def public_key(server, key):
    done = subprocess.run([signer_path(server), "pubkey", key],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def make_key(scratch, name):
    path = os.path.join(scratch, name)
    signer = os.path.join(os.path.dirname(os.path.abspath(SERVER_BINARY)),
                          "ariel-sign")
    done = subprocess.run([signer, "keygen", path],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return path


def rotation_action(new_pub):
    return ["command=key.rotate", "target=keyring", "sha256=none",
            "option.primary=" + new_pub]


def generation_of(challenge):
    fields = challenge.split(" ")
    assert len(fields) == 8, (
        "a challenge must carry the keyring generation as its last field, "
        "got %r" % challenge)
    return fields[7]


def with_generation(challenge, generation):
    fields = challenge.split(" ")
    fields[7] = generation
    return " ".join(fields)


def rotate_primary(server, new_pub, generation, signer, wait_ms=120000):
    """Request, sign with signer, grant and perform one rotation."""
    approval, challenge = gated_request(
        server, "key rotate " + new_pub, rotation_action(new_pub), ROTATE_PROMPT,
        wait_ms=wait_ms)
    assert generation_of(challenge) == str(generation - 1), (
        "the rotation must be signed under generation %d" % (generation - 1))
    signature = sign_challenge(server, challenge, key=signer)
    assert grant(server, approval, signature) == [
        "approval_granted %s" % approval, "exit 0"]
    assert run_command(server, "key rotate " + new_pub) == [
        "key_rotated %d" % generation, "exit 0"]
    return approval


def scenario_key_rotate_needs_current_primary(server):
    del server  # each rotation needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "rotate"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        recovery = public_key(keys, RECOVERY_KEY)
        approval, challenge = gated_request(
            keys, "key rotate " + second, rotation_action(second), ROTATE_PROMPT)
        assert generation_of(challenge) == "0", (
            "the first approval must be made under generation 0")
        for what, key in [("the recovery key", RECOVERY_KEY),
                          ("the key being added", SECOND_PRIMARY_KEY)]:
            signature = sign_challenge(keys, challenge, key=key)
            assert grant(keys, approval, signature) == [
                "signature_invalid", "exit 79"], (
                "a rotation signed by %s must be refused" % what)
        assert recovery != second, "the test keys must be distinct"
        sign_and_grant(keys, approval, challenge)
        assert run_command(keys, "key rotate " + second) == [
            "key_rotated 1", "exit 0"], (
            "the current primary's approval must perform the rotation")
        assert "key_rotate" in [kind for kind, _name, spent, _sha
                                in audit_events(keys) if spent == approval], (
            "the rotation must be recorded in the audit log")
    finally:
        keys.stop()


def scenario_key_rotate_refuses_bad_targets(server):
    """A bad or recovery target is refused before the owner is asked."""
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "targets"})
    try:
        recovery = public_key(keys, RECOVERY_KEY)
        for what, target in [("the recovery key", recovery),
                             ("a key that is not hex", "zz" * 32),
                             ("a short key", recovery[:-2])]:
            assert run_command(keys, "key rotate " + target) == [
                "key_refused", "exit 1"], (
                "a rotation to %s must be refused before the owner is asked"
                % what)
    finally:
        keys.stop()


def scenario_key_rotate_refuses_retired_primary(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "retired"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key())
        with tempfile.TemporaryDirectory() as scratch:
            third = public_key(keys, make_key(scratch, "third.key"))
        approval, challenge = gated_request(
            keys, "key rotate " + third, rotation_action(third), ROTATE_PROMPT)
        assert generation_of(challenge) == "1", (
            "the rotation must be signed under generation 1")
        retired = sign_challenge(keys, challenge, key=test_key())
        assert grant(keys, approval, retired) == [
            "signature_invalid", "exit 79"], (
            "the retired primary must not verify a new rotation")
        signature = sign_challenge(keys, challenge, key=SECOND_PRIMARY_KEY)
        assert grant(keys, approval, signature) == [
            "approval_granted %s" % approval, "exit 0"]
        assert run_command(keys, "key rotate " + third) == [
            "key_rotated 2", "exit 0"]
    finally:
        keys.stop()


def scenario_signature_from_another_generation_is_refused(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "generation"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key())
        with tempfile.TemporaryDirectory() as scratch:
            third = public_key(keys, make_key(scratch, "third.key"))
        approval, challenge = gated_request(
            keys, "key rotate " + third, rotation_action(third), ROTATE_PROMPT)
        cross = sign_challenge(keys, with_generation(challenge, "0"),
                               key=SECOND_PRIMARY_KEY)
        assert grant(keys, approval, cross) == ["signature_invalid",
                                                "exit 79"], (
            "a signature over a generation 0 message must not verify in "
            "generation 1")
        honest = sign_challenge(keys, challenge, key=SECOND_PRIMARY_KEY)
        assert grant(keys, approval, honest) == [
            "approval_granted %s" % approval, "exit 0"]
    finally:
        keys.stop()


def scenario_pending_approval_stops_after_rotation(server):
    """A challenge issued before a rotation is refused after it, whichever
    key signs it. The rotation waits 11 s: past the notification gap, and
    well inside the early challenge's 120 s, so only the generation can
    refuse it. The early challenge is for env, since a new rotation request
    replaces a pending rotation question."""
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "pending"})
    try:
        name = "PATH"
        approval_a, challenge_a = gated_request(
            keys, "env " + name,
            ["command=env", "target=%s" % name, "sha256=none"],
            "env %s will run" % name)
        with tempfile.TemporaryDirectory() as scratch:
            third_key = make_key(scratch, "third.key")
            third = public_key(keys, third_key)
            rotate_primary(keys, third, 1, test_key(), wait_ms=11000)
            for what, key in [("the retired primary", test_key()),
                              ("the new primary", third_key)]:
                early = sign_challenge(keys, challenge_a, key=key)
                assert grant(keys, approval_a, early) == [
                    "signature_invalid", "exit 79"], (
                    "a challenge issued before the rotation must not verify "
                    "after it, signed by %s" % what)
    finally:
        keys.stop()


def scenario_consumed_nonce_survives_rotation_restart(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "spent"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        approval, challenge = gated_request(
            keys, "key rotate " + second, rotation_action(second), ROTATE_PROMPT)
        spent = CHALLENGE_LINE.match(challenge).group(3)
        sign_and_grant(keys, approval, challenge)
        assert run_command(keys, "key rotate " + second) == [
            "key_rotated 1", "exit 0"]
        keys.restart()
        with tempfile.TemporaryDirectory() as scratch:
            third = public_key(keys, make_key(scratch, "third.key"))
        _approval, fresh = gated_request(
            keys, "key rotate " + third, rotation_action(third), ROTATE_PROMPT)
        assert CHALLENGE_LINE.match(fresh).group(3) != spent, (
            "a nonce consumed before the rotation and the restart must not be "
            "offered again")
    finally:
        keys.stop()


def scenario_key_rotate_refuses_revoked_keys(server):
    """A retired primary stays revoked: rotating back to it, or to the
    current primary, is refused before the owner is asked, also after a
    restart and after a second rotation."""
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "revoked"})
    try:
        test_pub = public_key(keys, test_key())
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key())
        assert run_command(keys, "key rotate " + second) == [
            "key_refused", "exit 1"], (
            "rotating to the current primary must be refused")
        assert run_command(keys, "key rotate " + test_pub) == [
            "key_refused", "exit 1"], (
            "rotating back to the retired primary must be refused")
        keys.restart()
        assert run_command(keys, "key rotate " + test_pub) == [
            "key_refused", "exit 1"], (
            "a retired key must stay refused after a restart")
        with tempfile.TemporaryDirectory() as scratch:
            third = public_key(keys, make_key(scratch, "third.key"))
        rotate_primary(keys, third, 2, SECOND_PRIMARY_KEY)
        for what, target in [("the first retired primary", test_pub),
                             ("the second retired primary", second)]:
            assert run_command(keys, "key rotate " + target) == [
                "key_refused", "exit 1"], (
                "rotating back to %s must be refused" % what)
    finally:
        keys.stop()


def scenario_unused_approval_stops_after_rotation(server):
    """An approval granted under a retired primary and not yet used answers
    approval_stale, and the command asks the owner again."""
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "unused"})
    try:
        name = "PATH"
        approval, challenge = gated_request(
            keys, "env " + name,
            ["command=env", "target=%s" % name, "sha256=none"],
            "env %s will run" % name)
        sign_and_grant(keys, approval, challenge)
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key(), wait_ms=11000)
        assert run_command(keys, "env " + name) == [
            "approval_stale", "exit 78"], (
            "a grant made under a retired primary must not run its command")
        assert_asks_again(keys, "env " + name)
    finally:
        keys.stop()


def recovery_rotation_action(new_pub):
    return ["command=key.rotate-recovery", "target=keyring", "sha256=none",
            "option.recovery=" + new_pub]


def rotate_recovery(server, new_pub, generation, signer, wait_ms=120000):
    """Request, sign with signer, grant and perform one recovery rotation."""
    approval, challenge = gated_request(
        server, "key rotate-recovery " + new_pub,
        recovery_rotation_action(new_pub), RECOVERY_ROTATE_PROMPT,
        wait_ms=wait_ms)
    assert generation_of(challenge) == str(generation - 1), (
        "the recovery rotation must be signed under generation %d"
        % (generation - 1))
    signature = sign_challenge(server, challenge, key=signer)
    assert grant(server, approval, signature) == [
        "approval_granted %s" % approval, "exit 0"]
    assert run_command(server, "key rotate-recovery " + new_pub) == [
        "key_rotated %d" % generation, "exit 0"]
    return approval


def scenario_key_rotate_recovery_needs_current_recovery(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "recovery"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            third = public_key(keys, make_key(scratch, "third.key"))
            approval, challenge = gated_request(
                keys, "key rotate-recovery " + third,
                recovery_rotation_action(third), RECOVERY_ROTATE_PROMPT)
            assert generation_of(challenge) == "0", (
                "the first recovery approval must be made under generation 0")
            primary = sign_challenge(keys, challenge, key=test_key())
            assert grant(keys, approval, primary) == [
                "signature_invalid", "exit 79"], (
                "the primary must not sign a recovery rotation")
            signature = sign_challenge(keys, challenge, key=RECOVERY_KEY)
            assert grant(keys, approval, signature) == [
                "approval_granted %s" % approval, "exit 0"], (
                "the current recovery key's signature must grant the rotation")
            assert run_command(keys, "key rotate-recovery " + third) == [
                "key_rotated 1", "exit 0"], (
                "the granted recovery rotation must be performed")
            assert "key_rotate_recovery" in [
                kind for kind, _name, spent, _sha in audit_events(keys)
                if spent == approval], (
                "the recovery rotation must be recorded in the audit log")
    finally:
        keys.stop()


def scenario_key_rotate_recovery_refuses_bad_targets(server):
    """The active primary and the current recovery key are refused as targets
    before the owner is asked."""
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "recovery-targets"})
    try:
        primary = public_key(keys, test_key())
        recovery = public_key(keys, RECOVERY_KEY)
        for what, target in [("the active primary", primary),
                             ("the current recovery key", recovery)]:
            assert run_command(keys, "key rotate-recovery " + target) == [
                "key_refused", "exit 1"], (
                "a recovery rotation to %s must be refused before the owner "
                "is asked" % what)
    finally:
        keys.stop()


def scenario_key_rotate_recovery_refuses_retired_recovery(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "recovery-retired"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            third_key = make_key(scratch, "third.key")
            third = public_key(keys, third_key)
            retired = public_key(keys, RECOVERY_KEY)
            fourth = public_key(keys, make_key(scratch, "fourth.key"))
            rotate_recovery(keys, third, 1, RECOVERY_KEY)
            assert run_command(keys, "key rotate-recovery " + retired) == [
                "key_refused", "exit 1"], (
                "the retired recovery key must be refused as a target")
            approval, challenge = gated_request(
                keys, "key rotate-recovery " + fourth,
                recovery_rotation_action(fourth), RECOVERY_ROTATE_PROMPT)
            assert generation_of(challenge) == "1", (
                "the next recovery approval must be made under generation 1")
            signature = sign_challenge(keys, challenge, key=RECOVERY_KEY)
            assert grant(keys, approval, signature) == [
                "signature_invalid", "exit 79"], (
                "the retired recovery key must not sign a recovery rotation")
            signature = sign_challenge(keys, challenge, key=third_key)
            assert grant(keys, approval, signature) == [
                "approval_granted %s" % approval, "exit 0"], (
                "the current recovery key must still sign")
    finally:
        keys.stop()


def assert_one_keyring_active(server, scratch, name, expected, verb, action,
                              prompt, old_key, new_key):
    """Only the keyring Ariel restarted with verifies a fresh challenge."""
    probe = public_key(server, make_key(scratch, name))
    approval, challenge = gated_request(
        server, "%s %s" % (verb, probe), action(probe), prompt)
    generation = generation_of(challenge)
    assert generation == str(expected), (
        "after the restart the keyring must be generation %d, got %s"
        % (expected, generation))
    active, other = (old_key, new_key) if expected == 0 else (new_key, old_key)
    assert grant(server, approval, sign_challenge(server, challenge,
                                                  key=other)) == [
        "signature_invalid", "exit 79"], (
        "only one keyring may be active: the other key must not verify")
    assert grant(server, approval, sign_challenge(server, challenge,
                                                  key=active)) == [
        "approval_granted %s" % approval, "exit 0"], (
        "the active keyring's key must verify")


def scenario_key_rotate_crash_leaves_one_keyring(server):
    del server
    with tempfile.TemporaryDirectory() as scratch:
        for step, expected in ROTATION_CRASH_STEPS:
            keys = Server(SERVER_BINARY, env={
                "ARIEL_HOST_NONCE_SEED": "crash-" + step,
                FAULT_ENV: step})
            try:
                second = public_key(keys, SECOND_PRIMARY_KEY)
                approval, challenge = gated_request(
                    keys, "key rotate " + second, rotation_action(second),
                    ROTATE_PROMPT)
                sign_and_grant(keys, approval, challenge)
                assert command_until_crash(keys, "key rotate " + second) == [], (
                    "a key rotate that crashes at %s must answer nothing" % step)
                keys.env = None
                keys.restart()
                assert_one_keyring_active(
                    keys, scratch, "probe-%s.key" % step, expected, "key rotate",
                    rotation_action, ROTATE_PROMPT, test_key(),
                    SECOND_PRIMARY_KEY)
            finally:
                keys.stop()


def scenario_key_rotate_recovery_crash_leaves_one_keyring(server):
    del server
    with tempfile.TemporaryDirectory() as scratch:
        for step, expected in ROTATION_CRASH_STEPS:
            target_key = make_key(scratch, "target-%s.key" % step)
            keys = Server(SERVER_BINARY, env={
                "ARIEL_HOST_NONCE_SEED": "crash-recovery-" + step,
                FAULT_ENV: step})
            try:
                target = public_key(keys, target_key)
                approval, challenge = gated_request(
                    keys, "key rotate-recovery " + target,
                    recovery_rotation_action(target), RECOVERY_ROTATE_PROMPT)
                signature = sign_challenge(keys, challenge, key=RECOVERY_KEY)
                assert grant(keys, approval, signature) == [
                    "approval_granted %s" % approval, "exit 0"]
                assert command_until_crash(
                    keys, "key rotate-recovery " + target) == [], (
                    "a key rotate-recovery that crashes at %s must answer "
                    "nothing" % step)
                keys.env = None
                keys.restart()
                assert_one_keyring_active(
                    keys, scratch, "probe-recovery-%s.key" % step, expected,
                    "key rotate-recovery", recovery_rotation_action,
                    RECOVERY_ROTATE_PROMPT, RECOVERY_KEY, target_key)
            finally:
                keys.stop()


ANCHOR_PRIMARY_ENV = "ARIEL_HOST_ANCHOR_PRIMARY"
ANCHOR_RECOVERY_ENV = "ARIEL_HOST_ANCHOR_RECOVERY"
ADOPT_COMMAND = "key adopt-anchor"
ADOPT_PROMPT = "key adopt-anchor will run"


def adopt_action(primary_pub, recovery_pub):
    return ["command=key.adopt-anchor", "target=keyring", "sha256=none",
            "option.primary=" + primary_pub, "option.recovery=" + recovery_pub]


def anchored(seed, primary_pub, recovery_pub):
    """The environment of a build whose anchor is the given pair."""
    return {"ARIEL_HOST_NONCE_SEED": seed,
            ANCHOR_PRIMARY_ENV: primary_pub,
            ANCHOR_RECOVERY_ENV: recovery_pub}


def new_anchor(server, scratch):
    """A new anchor's keys: primary and recovery as hex, then their key files."""
    primary_key = make_key(scratch, "anchor-primary.key")
    recovery_key = make_key(scratch, "anchor-recovery.key")
    return (public_key(server, primary_key), public_key(server, recovery_key),
            primary_key, recovery_key)


def assert_refused_without_asking(server, command):
    """The command is refused before the owner is asked: no challenge, exit 1."""
    lines = run_command(server, command)
    assert lines == ["key_refused", "exit 1"], (
        "%s must be refused without a challenge, got %r" % (command, lines))


def assert_refused_everything(server):
    """With the key state untrusted, nothing asks the owner and nothing runs."""
    second = public_key(server, SECOND_PRIMARY_KEY)
    for command in ["env PATH", ADOPT_COMMAND, "key rotate " + second,
                    "key rotate-recovery " + second]:
        assert_refused_without_asking(server, command)


def scenario_keyring_missing_refuses_approvals(server):
    """A recorded generation 1 with the keyring gone refuses every approval,
    and the build's own keys do not come back in the keyring's place."""
    del server  # each rotation needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "missing"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key())
        os.remove(secret_path(keys, "keyring"))
        keys.restart()
        assert_refused_everything(keys)
    finally:
        keys.stop()


def scenario_keyring_corrupt_refuses_approvals(server):
    """A recorded generation 1 with a corrupt keyring refuses every approval."""
    del server  # each rotation needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "corrupt"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key())
        with open(secret_path(keys, "keyring"), "w", encoding="ascii") as fh:
            fh.write("generation 1\nprimary not-a-key\n")
        keys.restart()
        assert_refused_everything(keys)
    finally:
        keys.stop()


def scenario_keyring_older_than_state_refuses_approvals(server):
    """A keyring restored to generation 0 under a state file at generation 1
    refuses every approval, so the retired keys do not verify again."""
    del server  # each rotation needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "older"})
    try:
        with open(secret_path(keys, "keyring"), "rb") as fh:
            generation_zero = fh.read()
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key())
        with open(secret_path(keys, "keyring"), "wb") as fh:
            fh.write(generation_zero)
        keys.restart()
        assert_refused_everything(keys)
    finally:
        keys.stop()


def scenario_recovery_then_corrupt_keyring_never_revives_recovery(server):
    """After a recovery rotation, a corrupt keyring does not fall back to the
    build's original recovery key: approvals are refused and nothing asks."""
    del server  # each rotation needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "revive"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            third = public_key(keys, make_key(scratch, "third-recovery.key"))
            rotate_recovery(keys, third, 1, RECOVERY_KEY)
        with open(secret_path(keys, "keyring"), "w", encoding="ascii") as fh:
            fh.write("generation 1\nrecovery 00\n")
        keys.restart()
        assert_refused_everything(keys)
    finally:
        keys.stop()


def scenario_anchor_mismatch_refuses_until_adopted(server):
    """A build whose anchor differs from the keyring's refuses every approval
    except key adopt-anchor, which it asks for and refuses without a rotation."""
    del server  # the anchor change needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "mismatch"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            primary, recovery, _pkey, _rkey = new_anchor(keys, scratch)
            keys.env = anchored("mismatch", primary, recovery)
            keys.restart()
        second = public_key(keys, SECOND_PRIMARY_KEY)
        for command in ["env PATH", "key rotate " + second]:
            assert_refused_without_asking(keys, command)
        approval, challenge = gated_request(
            keys, ADOPT_COMMAND, adopt_action(primary, recovery), ADOPT_PROMPT)
        assert approval and challenge
    finally:
        keys.stop()


def scenario_adopt_anchor_needs_the_new_recovery_key(server):
    """key adopt-anchor is granted only by the new anchor's recovery key; the
    new primary, the retired recovery key and the retired primary are refused."""
    del server  # the anchor change needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "signer"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            primary, recovery, primary_key, recovery_key = new_anchor(keys, scratch)
            keys.env = anchored("signer", primary, recovery)
            keys.restart()
            approval, challenge = gated_request(
                keys, ADOPT_COMMAND, adopt_action(primary, recovery), ADOPT_PROMPT)
            for what, key in [("the new primary", primary_key),
                              ("the retired recovery key", RECOVERY_KEY),
                              ("the retired primary", test_key())]:
                assert grant(keys, approval,
                             sign_challenge(keys, challenge, key=key)) == [
                    "signature_invalid", "exit 79"], (
                    "key adopt-anchor must refuse a signature by %s" % what)
            signature = sign_challenge(keys, challenge, key=recovery_key)
            assert grant(keys, approval, signature) == [
                "approval_granted %s" % approval, "exit 0"], (
                "the new recovery key's signature must grant key adopt-anchor")
            assert run_command(keys, ADOPT_COMMAND) == [
                "key_adopted 1", "exit 0"], (
                "a granted key adopt-anchor must adopt the anchor")
    finally:
        keys.stop()


def scenario_adopt_anchor_keeps_nonces_and_audit(server):
    """key adopt-anchor keeps consumed nonces consumed and the audit log's
    earlier lines, and appends its own."""
    del server  # the anchor change needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "adopt-audit"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        rotate_primary(keys, second, 1, test_key())
        approval, challenge = gated_request(
            keys, "env PATH",
            ["command=env", "target=PATH", "sha256=none"], "env PATH will run")
        spent = CHALLENGE_LINE.match(challenge).group(3)
        assert grant(keys, approval, sign_challenge(
            keys, challenge, key=SECOND_PRIMARY_KEY)) == [
            "approval_granted %s" % approval, "exit 0"]
        assert run_command(keys, "env PATH")[-1] == "exit 0"
        with tempfile.TemporaryDirectory() as scratch:
            primary, recovery, _pkey, recovery_key = new_anchor(keys, scratch)
            keys.env = anchored("adopt-audit", primary, recovery)
            keys.restart()
            approval, challenge = gated_request(
                keys, ADOPT_COMMAND, adopt_action(primary, recovery), ADOPT_PROMPT)
            assert grant(keys, approval, sign_challenge(
                keys, challenge, key=recovery_key)) == [
                "approval_granted %s" % approval, "exit 0"]
            assert run_command(keys, ADOPT_COMMAND) == [
                "key_adopted 2", "exit 0"]
            keys.restart()
            _approval, fresh = gated_request(
                keys, "env PATH",
                ["command=env", "target=PATH", "sha256=none"], "env PATH will run")
        assert CHALLENGE_LINE.match(fresh).group(3) != spent, (
            "a nonce consumed before key adopt-anchor must not be offered again")
        kinds = [event[0] for event in audit_events(keys)]
        assert kinds.count("key_rotate") == 1 and kinds.count(
            "key_adopt_anchor") == 1 and kinds.index("key_rotate") < kinds.index(
            "key_adopt_anchor"), (
            "the audit log must keep the rotation and record the adoption, got %r"
            % kinds)
    finally:
        keys.stop()


def scenario_adopt_anchor_refused_when_anchor_matches(server):
    """key adopt-anchor is refused, without a challenge, while the build's
    anchor is the keyring's: adoption is only for a mismatch."""
    assert_refused_without_asking(server, ADOPT_COMMAND)


def scenario_adr_names_recovery_rotation_and_crash_steps(server):
    del server
    adr = os.path.join(repo_dir(), "docs", "adr",
                       "0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md")
    with open(adr, encoding="utf-8") as handle:
        text = handle.read()
    for term in ["key rotate-recovery", "prepared", "committed", "renamed",
                 "audited"]:
        assert term in text, "ADR-0009 must name %r" % term


def scenario_ps5_pubkey_needs_recovery(server):
    """A PS5 build that pins the owner's key without its recovery key is
    refused by make, not left to refuse every grant at run time."""
    pub = public_key(server, SECOND_PRIMARY_KEY)
    alone = subprocess.run(
        ["make", "-n", "-f", os.path.join(repo_dir(), "Makefile"),
         "PS5_PAYLOAD_SDK=/nonexistent", "ARIEL_PUBKEY=" + pub],
        capture_output=True, text=True)
    assert alone.returncode != 0 and "ARIEL_RECOVERY_PUBKEY" in alone.stderr, (
        "the PS5 makefile must name ARIEL_RECOVERY_PUBKEY when only the owner's "
        "key is set, got %r" % alone.stderr)
    paired = subprocess.run(
        ["make", "-n", "-f", os.path.join(repo_dir(), "Makefile"),
         "PS5_PAYLOAD_SDK=/nonexistent", "ARIEL_PUBKEY=" + pub,
         "ARIEL_RECOVERY_PUBKEY=" + public_key(server, RECOVERY_KEY)],
        capture_output=True, text=True)
    assert "ARIEL_RECOVERY_PUBKEY" not in paired.stderr, (
        "a build that pins both keys must not be refused for the pair, got %r"
        % paired.stderr)


def scenario_recovery_pubkey_is_documented(server):
    """The PS5 build instructions and the quick start name both pinned keys."""
    del server
    for doc in ["README.md", os.path.join("docs", "quick-start.md")]:
        with open(os.path.join(repo_dir(), doc), encoding="utf-8") as handle:
            text = handle.read()
        assert "ARIEL_PUBKEY" in text and "ARIEL_RECOVERY_PUBKEY" in text, (
            "%s must document ARIEL_PUBKEY and ARIEL_RECOVERY_PUBKEY" % doc)


def scenario_ps5_refuses_test_key_as_primary(server):
    """The admission rule store_key_check applies to a new primary refuses the
    host test key in the PS5 configuration, and nothing else of the owner's."""
    test_pub = public_key(server, test_key())
    owner = public_key(server, SECOND_PRIMARY_KEY)
    recovery = public_key(server, RECOVERY_KEY)
    with tempfile.TemporaryDirectory() as scratch:
        anchor = public_key(server, make_key(scratch, "anchor.key"))
        ps5 = compile_probe(scratch, "admit-ps5", [],
                            source="admissible_probe.c")
        host = compile_probe(scratch, "admit-host", ["-DARIEL_HOST_BUILD=1"],
                             source="admissible_probe.c")

        def admitted(probe, key, primary, recovery_key):
            done = subprocess.run([probe, key, primary, recovery_key],
                                  capture_output=True, text=True)
            assert done.returncode in (0, 1), done.stderr
            return done.returncode == 0

        assert not admitted(ps5, test_pub, anchor, recovery), (
            "the PS5 configuration must refuse the host test key as primary")
        assert admitted(ps5, owner, anchor, recovery), (
            "the PS5 configuration must admit the owner's key")
        assert not admitted(ps5, recovery, anchor, recovery), (
            "the recovery key must not be admitted as primary")
        assert not admitted(ps5, anchor, anchor, recovery), (
            "the current primary must not be admitted as its own successor")
        assert admitted(host, test_pub, anchor, recovery), (
            "the host configuration admits the host test key")
    with open(os.path.join(repo_dir(), "store.c"), encoding="utf-8") as handle:
        assert "approval_key_admissible(" in handle.read(), (
            "store_key_check must apply the admission rule")


def scenario_keyring_is_protected(server):
    path = secret_path(server, "keyring")
    for template in SECRET_READS:
        assert_protected(server, template.format(p=path))


def scenario_adr_names_the_key_hierarchy(server):
    del server
    adr = os.path.join(repo_dir(), "docs", "adr",
                       "0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md")
    assert os.path.exists(adr), "ADR-0009 must exist at %s" % adr
    with open(adr, encoding="utf-8") as handle:
        text = handle.read()
    for term in ["primary", "recovery", "anchor", "keyring", "generation",
                 "ADR-0006", "## Trust boundary"]:
        assert term in text, "ADR-0009 must define or cite %r" % term
    with open(os.path.join(repo_dir(), "docs", "adr", "README.md"),
              encoding="utf-8") as handle:
        assert "0009-the-key-hierarchy" in handle.read(), (
            "the ADR index must list ADR-0009")


def compile_probe(scratch, name, defines, source="pin_probe.c"):
    root = repo_dir()
    probe = os.path.join(scratch, name)
    done = subprocess.run(
        [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Werror", "-w",
         "-I" + root, "-o", probe,
         os.path.join(tests_dir(), source),
         os.path.join(root, "approval.c"), os.path.join(root, "tweetnacl.c")]
        + defines, capture_output=True, text=True)
    assert done.returncode == 0, "the probe must build: %r" % done.stderr
    return probe


def scenario_ps5_rejects_test_key(server):
    """The PS5 configuration of the verifier refuses the host test key."""
    pub = subprocess.run([signer_path(server), "pubkey", test_key()],
                         capture_output=True, text=True)
    assert pub.returncode == 0, pub.stderr
    test_pub = pub.stdout.strip()

    with tempfile.TemporaryDirectory() as scratch:
        other = os.path.join(scratch, "other.key")
        made = subprocess.run([signer_path(server), "keygen", other],
                              capture_output=True, text=True)
        assert made.returncode == 0, made.stderr
        other_pub = made.stdout.strip()

        # The PS5 build never defines ARIEL_HOST_BUILD.
        ps5 = compile_probe(scratch, "probe-ps5", [])
        host = compile_probe(scratch, "probe-host",
                            ["-DARIEL_HOST_BUILD=1"])
        refused = subprocess.run([ps5, test_pub], capture_output=True,
                                 text=True)
        assert refused.returncode == 1, (
            "the PS5 configuration must refuse the test key: %r"
            % refused.stdout)
        accepted = subprocess.run([ps5, other_pub], capture_output=True,
                                  text=True)
        assert accepted.returncode == 0, (
            "the PS5 configuration must accept an owner's key: %r"
            % accepted.stdout)
        allowed = subprocess.run([host, test_pub], capture_output=True,
                                 text=True)
        assert allowed.returncode == 0, (
            "the host configuration pins the test key: %r" % allowed.stdout)

    # The PS5 makefile refuses to build with the test key pinned.
    build = subprocess.run(
        ["make", "-n", "-f", os.path.join(repo_dir(), "Makefile"),
         "PS5_PAYLOAD_SDK=/nonexistent", "ARIEL_PUBKEY=" + test_pub],
        capture_output=True, text=True)
    assert build.returncode != 0 and "test key" in build.stderr, (
        "the PS5 makefile must refuse the test key, got %r" % build.stderr)

    # And the PS5 platform goes through that one check.
    with open(os.path.join(repo_dir(), "platform_ps5.c")) as handle:
        assert "approval_pin(" in handle.read(), (
            "platform_ps5.c must pin its key through approval_pin")


def scenario_ps5_has_no_pad(server):
    """Nothing in the PS5 approval path touches the controller."""
    del server
    with open(os.path.join(repo_dir(), "platform_ps5.c")) as handle:
        source = handle.read()
    for name in ("scePadInit", "scePadOpen", "scePadReadState",
                 "pad_reader", "pthread_create"):
        assert name not in source, "platform_ps5.c still uses %s" % name


# ---------------------------------------------------------------------------
# The audit log (issue #21). Ariel appends every action; audit tail reads it.
# ---------------------------------------------------------------------------

# A file action has no payload hash, so its line records none in the sha256 field.
AUDIT_LINE = re.compile(
    r"^(\d+) (\S+) (\S+) (\S+) ([0-9a-f]{64}|none|-|status-\d+)$")


def audit_log_path(server):
    return os.path.join(server.root, "data", "ariel", "audit.log")


def read_audit_log(server):
    try:
        with open(audit_log_path(server), "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return b""


def send_command(server, command):
    """Send one command and return the lines the server answered."""
    sock = server.connect()
    try:
        sock.sendall(
            ("auth %s\n%s\n" % (server.token, command)).encode("ascii"))
        return reply_lines(read_reply(sock))
    finally:
        sock.close()


def audit_tail(server, n=None):
    """Send one audit tail and return the lines the server answered."""
    command = "audit tail" if n is None else "audit tail %d" % n
    return send_command(server, command)


def scenario_autoload_show_lists_entries(server):
    """autoload show lists the boot entries, Ariel first, and writes nothing."""
    before = read_audit_log(server)
    lines = send_command(server, "autoload show")
    assert lines == ["autoload ariel", "exit 0"], (
        "a fresh store must autoload only Ariel, got %r" % lines)
    assert read_audit_log(server) == before, (
        "autoload show is read-only and must not audit anything")


AUTOLOAD_SELF = "ariel"


def autoload_listing(server):
    return send_command(server, "autoload show")


def autoload_list_sha(listing):
    """The SHA-256 of the list text a listing shows: one name per line."""
    names = [line[len("autoload "):] for line in listing
             if line.startswith("autoload ")]
    return hashlib.sha256("".join(name + "\n" for name in names)
                          .encode("ascii")).hexdigest()


def autoload_ask(server, op, name):
    """Ask for an autoload edit and return its approval ID and challenge."""
    server.advance(10_000)
    listing = autoload_listing(server)
    lines = send_command(server, "autoload edit %s %s" % (op, name))
    assert lines and lines[-1] == "exit 75", (
        "an autoload edit without a grant must answer 75, got %r" % lines)
    approvals = [APPROVAL_LINE.match(line) for line in lines]
    approvals = [match.group(1) for match in approvals if match]
    assert len(approvals) == 1, "expected one approval, got %r" % lines
    prompt = server.next_line()
    expected = ("prompt %s autoload.%s %s (list sha256 %s) will change autoload"
                % (approvals[0], op, name, autoload_list_sha(listing)))
    assert prompt == expected, (
        "the owner must be prompted with the edit and its list, expected %r, "
        "got %r" % (expected, prompt))
    return approvals[0], challenge_of(lines)


def autoload_apply(server, op, name, approval):
    return send_command(server, "autoload edit %s %s %s" % (op, name, approval))


def autoload_approve(server, op, name):
    """The owner's step for an autoload edit: ask, sign, grant; return the ID."""
    approval, challenge = autoload_ask(server, op, name)
    sign_and_grant(server, approval, challenge)
    return approval


def scenario_autoload_edit_asks_before_it_applies(server):
    """An autoload edit without a grant answers 75 and leaves the list as it was."""
    install_payload(server, "asks", healthy_build("asks-build"))
    autoload_ask(server, "add", "asks")
    assert "autoload asks" not in autoload_listing(server), (
        "an edit that was asked for must not be applied before its grant")


def scenario_autoload_edit_applies_after_grant(server):
    """A granted autoload add is applied, shown by autoload show and audited."""
    install_payload(server, "boot", healthy_build("boot-build"))
    approval = autoload_approve(server, "add", "boot")
    assert autoload_apply(server, "add", "boot", approval) == [
        "autoload add boot", "exit 0"], "a granted autoload add must apply"

    listing = autoload_listing(server)
    assert listing[0] == "autoload ariel" and "autoload boot" in listing, (
        "autoload show must list the added entry, got %r" % listing)

    ours = [line.split() for line in audit_tail(server)
            if line.split()[3:4] == [approval]]
    assert [event[1] for event in ours] == ["grant", "autoload_add"], (
        "the grant and the applied edit must both be audited, got %r" % ours)


def scenario_autoload_pins_ariel(server):
    """Ariel cannot be removed from the list: the edit is refused and audited."""
    assert send_command(server, "autoload edit remove ariel") == [
        "ariel_pinned", "exit 1"], "removing ariel must be refused"
    assert "autoload ariel" in autoload_listing(server), (
        "a refused removal must leave ariel in the list")
    refused = [line.split() for line in audit_tail(server)
               if line.split()[1:4] == ["refuse", "ariel", "ariel_pinned"]]
    assert refused, "the refused removal must be audited"


def scenario_autoload_refusals_answer_their_words(server):
    """Unknown, present and absent names are refused with their own words."""
    install_payload(server, "refused", healthy_build("refused-build"))
    assert send_command(server, "autoload edit add ghost") == [
        "unknown_payload", "exit 1"], "adding a payload that is not installed"
    approval = autoload_approve(server, "add", "refused")
    assert autoload_apply(server, "add", "refused", approval) == [
        "autoload add refused", "exit 0"], "the granted add must apply"
    assert send_command(server, "autoload edit add refused") == [
        "already_in_autoload", "exit 1"], "adding a name twice"
    assert send_command(server, "autoload edit remove missing") == [
        "not_in_autoload", "exit 1"], "removing a name that is not listed"


def scenario_autoload_stale_grant_answers_78(server):
    """A grant for a list that has since changed answers approval_stale."""
    install_payload(server, "stale_one", healthy_build("stale-one-build"))
    install_payload(server, "stale_two", healthy_build("stale-two-build"))
    stale, challenge = autoload_ask(server, "add", "stale_one")

    other = autoload_approve(server, "add", "stale_two")
    assert autoload_apply(server, "add", "stale_two", other) == [
        "autoload add stale_two", "exit 0"], "the other edit must apply"

    sign_and_grant(server, stale, challenge)
    assert autoload_apply(server, "add", "stale_one", stale) == [
        "approval_stale", "exit 78"], "a grant for an older list is stale"
    assert "autoload stale_one" not in autoload_listing(server), (
        "a stale grant must not change the list")


def autoload_apply_until_crash(server, op, name, approval):
    """Send an autoload apply that the injected fault ends, and wait for Ariel to die."""
    sock = server.connect()
    try:
        sock.sendall(("auth %s\nautoload edit %s %s %s\n"
                      % (server.token, op, name, approval)).encode("ascii"))
        reply = reply_lines(read_reply(sock))
    except OSError:
        reply = []
    finally:
        sock.close()
    assert server.proc.wait(timeout=5.0) != 0, "the fault must end Ariel"
    return reply


def crash_autoload(server, step):
    """Grant an autoload add of crash_tool, then crash its apply at step."""
    install_payload(server, "crash_tool", healthy_build("crash-tool-build"))
    server.env = {FAULT_ENV: step}
    server.restart()
    approval, challenge = autoload_ask(server, "add", "crash_tool")
    sign_and_grant(server, approval, challenge)
    assert autoload_apply_until_crash(server, "add", "crash_tool",
                                      approval) == [], (
        "an apply that crashes must answer nothing")


def scenario_crash_in_autoload_prepared_keeps_old_list(server):
    """A crash after the prepared mark leaves the old list after restart."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        crash_autoload(crashed, "prepared")
        crashed.env = None
        crashed.restart()

        assert "autoload crash_tool" not in autoload_listing(crashed), (
            "a crash in prepared must leave the old list")
        new_hash = hashlib.sha256(
            (AUTOLOAD_SELF + "\ncrash_tool\n").encode("ascii")).hexdigest()
        assert ("rollback", "autoload", new_hash) in journal_events(crashed), (
            "the rollback must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def scenario_crash_in_autoload_committed_keeps_new_list(server):
    """A crash after the commit mark leaves the new list after restart."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        crash_autoload(crashed, "committed")
        crashed.env = None
        crashed.restart()

        assert "autoload crash_tool" in autoload_listing(crashed), (
            "a crash in committed must leave the new list")
        new_hash = hashlib.sha256(
            (AUTOLOAD_SELF + "\ncrash_tool\n").encode("ascii")).hexdigest()
        assert ("rollforward", "autoload", new_hash) in journal_events(crashed), (
            "the roll forward must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def autoload_path(server):
    return os.path.join(server.root, "data", "ariel", "autoload")


def journal_as_v1(text):
    """The journal a build before autoload wrote: marker v1, no kind field."""
    marker, record = text.split("\n", 1)
    assert marker == "ariel-journal-v2", "expected a v2 journal, got %r" % marker
    fields = record.split()
    assert fields[0] == "payload", "the replacement must be a payload change"
    return "ariel-journal-v1\n%s\n" % " ".join(fields[1:])


def crash_replacement_as_v1(server, step):
    """crash_commit at step, the journal rewritten as v1, then the restart."""
    crash_commit(server, step)
    path = os.path.join(store_dir(server), JOURNAL_FILE)
    with open(path, "r", encoding="ascii") as handle:
        text = handle.read()
    with open(path, "w", encoding="ascii") as handle:
        handle.write(journal_as_v1(text))
    server.env = None
    server.restart()


def scenario_v1_journal_rolls_forward(server):
    """A journal written before autoload existed still rolls a commit forward."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        first_hash = hashlib.sha256(FIRST_BUILD).hexdigest()
        second_hash = hashlib.sha256(SECOND_BUILD).hexdigest()
        crash_replacement_as_v1(crashed, "committed")

        assert listed(payload_list(crashed), JOURNAL_NAME) == (
            expected_listing(JOURNAL_NAME, second_hash, first_hash)), (
            "a v1 journal committed must roll the new version forward")
        assert ("rollforward", JOURNAL_NAME, second_hash) in journal_events(
            crashed), (
            "the roll forward must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def scenario_v1_journal_rolls_back(server):
    """A v1 journal left in prepared rolls the replacement back."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        first_hash = hashlib.sha256(FIRST_BUILD).hexdigest()
        crash_replacement_as_v1(crashed, "prepared")

        assert listed(payload_list(crashed), JOURNAL_NAME) == (
            expected_listing(JOURNAL_NAME, first_hash)), (
            "a v1 journal prepared must roll the replacement back")
    finally:
        crashed.stop()


def scenario_committed_autoload_without_its_file_rolls_forward(server):
    """A committed autoload edit rolls forward even when its list file is gone."""
    del server  # each crash needs an Ariel started with the fault injector
    crashed = Server(SERVER_BINARY)
    try:
        crash_autoload(crashed, "committed")
        os.remove(autoload_path(crashed))
        crashed.env = None
        crashed.restart()

        assert "autoload crash_tool" in autoload_listing(crashed), (
            "a committed edit must be listed after its file was lost")
        new_hash = hashlib.sha256(
            (AUTOLOAD_SELF + "\ncrash_tool\n").encode("ascii")).hexdigest()
        assert ("rollforward", "autoload", new_hash) in journal_events(crashed), (
            "the roll forward must be audited, the log holds %r"
            % journal_events(crashed))
    finally:
        crashed.stop()


def scenario_autoload_busy_is_audited(server):
    """An autoload edit refused as busy answers approval_busy and is audited."""
    install_payload(server, "busy_one", healthy_build("busy-one-build"))
    install_payload(server, "busy_two", healthy_build("busy-two-build"))
    autoload_ask(server, "add", "busy_one")
    lines = send_command(server, "autoload edit add busy_two")
    assert lines == ["approval_busy", "exit 76"], (
        "a second notification within 10 s must answer approval_busy, got %r"
        % lines)
    refused = [line.split() for line in audit_tail(server)
               if line.split()[1:4] == ["refuse", "busy_two", "approval_busy"]]
    assert refused, "the busy refusal must be audited"


def scenario_autoload_audit_failure_after_rename_stays_applied(server):
    """An applied autoload edit whose audit line fails answers audit_failed."""
    fresh = Server(server.binary)
    try:
        install_payload(fresh, "unlogged", healthy_build("unlogged-build"))
        approval, challenge = autoload_ask(fresh, "add", "unlogged")
        sign_and_grant(fresh, approval, challenge)

        log = audit_log_path(fresh)
        os.rename(log, log + ".saved")
        os.mkdir(log)

        assert autoload_apply(fresh, "add", "unlogged", approval) == [
            "audit_failed", "exit 1"], "an edit the log cannot record"
        assert "autoload unlogged" in autoload_listing(fresh), (
            "an edit applied before its audit failed must stay in the list")
        assert not os.path.exists(os.path.join(store_dir(fresh), JOURNAL_FILE)), (
            "the journal must be closed once the list is in place")
    finally:
        fresh.stop()


def scenario_audit_tail_order(server):
    """After a push, a grant and a commit, audit tail shows each one in order."""
    data = healthy_build("audited-build")
    digest = hashlib.sha256(data).hexdigest()
    staging, approval = approve_push(server, "audited", data)
    assert commit(server, staging) == [
        "installed audited %s" % digest, "exit 0"], (
        "an approved commit must install the build")

    lines = audit_tail(server)
    events = [line for line in lines if line != "exit 0"]
    assert lines and lines[-1] == "exit 0", (
        "audit tail must end with exit 0, got %r" % lines)
    for event in events:
        assert AUDIT_LINE.match(event), (
            "expected '<ms> <kind> <name> <id> <sha256>', got %r" % event)

    # Other scenarios share this server's log: only this build's events count.
    # Ids restart with Ariel, so on a console an older line can carry the same
    # id: count only from this build's push on.
    pushes = [i for i, event in enumerate(events)
              if event.split()[1:4] == ["push", "audited", staging]]
    assert pushes, "audit tail must show the push, got %r" % events
    ours = [event for event in events[pushes[-1]:]
            if event.split()[3] in (staging, approval)]
    kinds = [event.split()[1] for event in ours]
    assert kinds == ["push", "grant", "commit"], (
        "audit tail must show the push, then the grant, then the commit, "
        "got %r" % ours)
    for event in ours:
        match = AUDIT_LINE.match(event)
        assert match.group(3) == "audited", (
            "the event must name the payload, got %r" % event)
        assert match.group(5) == digest, (
            "the event must name the build's hash, got %r" % event)

    # The grant event names the approval, the commit event the staging object.
    assert ours[1].split()[3] == approval, (
        "the grant event must name the approval %s, got %r" % (approval, ours[1]))
    assert ours[2].split()[3] == staging, (
        "the commit event must name the staging ID %s, got %r" % (staging, ours[2]))

    # [n] keeps the newest n events, still in order.
    last = audit_tail(server, 3)
    assert last == events[-3:] + ["exit 0"], (
        "audit tail 3 must show the three newest events in order, got %r" % last)

    # The log is append-only through the port: reading it changes nothing.
    again = audit_tail(server)
    assert again == lines, "reading the log must not change it, got %r" % again


def scenario_audit_tail_readonly(server):
    """audit tail reads the log and never writes to it."""
    before = audit_tail(server)
    assert before and before[-1] == "exit 0", (
        "audit tail must answer the log and exit 0, got %r" % before)
    after = audit_tail(server)
    assert after == before, (
        "audit tail must not append anything, before %r after %r" % (before, after))

    # A tail with no count, a count and a count of one are all reads.
    for command in ("audit tail", "audit tail 1", "audit tail 0"):
        lines = send_command(server, command)
        assert lines and lines[-1] == "exit 0", (
            "%r must succeed as a read, got %r" % (command, lines))
    assert audit_tail(server) == before, (
        "reading the log with a count must not change it")

    # A count is digits only and fits in a number: anything else is refused.
    for command in ("audit tail x", "audit tail -1", "audit tail 1 2",
                    "audit tail 99999999999999999999999999"):
        lines = send_command(server, command)
        assert lines and lines[-1] != "exit 0", (
            "%r must not succeed, got %r" % (command, lines))
    assert audit_tail(server) == before, (
        "a refused count must not change the log")


def scenario_audit_log_not_rewritable(server):
    """No agent-port command can clear or rewrite the audit log."""
    # Every way an agent could name the log, or ask to clear it. The telnet
    # shell is out of scope (ADR-0008): this is the agent port only.
    attempts = (
        "audit clear",
        "audit reset",
        "audit rm",
        "audit delete",
        "audit truncate",
        "audit write hello",
        "audit tail --clear",
        "rm /data/ariel/audit",
        "rm /data/ariel/audit.log",
        "echo gone > /data/ariel/audit.log",
        "truncate /data/ariel/audit.log",
        "mv /data/ariel/audit.log /data/ariel/audit.log.bak",
        "ln -s /data/ariel/audit.log /data/gone",
        "chmod 777 /data/ariel/audit.log",
    )

    held = read_audit_log(server)
    assert held, "the log must hold events before the attempts"

    for index, command in enumerate(attempts):
        if index == len(attempts) // 2:
            # The server's own actions append, and the log must keep what it held.
            approve_push(server, "rewritten", b"rewritten bytes\n")
            grown = read_audit_log(server)
            assert len(grown) > len(held) and grown.startswith(held), (
                "an approved push must append to the log, not rewrite it")
            held = grown

        lines = send_command(server, command)
        if command.startswith("echo "):
            # The agent port has no redirection: echo prints its operands,
            # '>' included, and writes no file.
            assert lines == [command[len("echo "):], "exit 0"], (
                "%r must print its operands and write nothing, got %r"
                % (command, lines))
        else:
            assert lines and lines[-1] != "exit 0", (
                "%r must not succeed: a successful command here would be a "
                "way to clear or rewrite the log, got %r" % (command, lines))

        now = read_audit_log(server)
        assert now.startswith(held), (
            "%r rewrote the audit log: it no longer begins with what it held"
            % command)
        held = now

    assert held.endswith(b"\n"), "the log must end in a whole line"
    for line in held.decode("ascii").splitlines():
        assert AUDIT_LINE.match(line), (
            "the log must hold only whole event lines, got %r" % line)


def scenario_audit_tail_drops_long_lines(server):
    """A line too long to read whole is dropped, never shown in pieces."""
    fresh = Server(server.binary)
    try:
        with open(audit_log_path(fresh), "ab") as handle:
            handle.write(b"x" * 400 + b"\n")
        approve_push(fresh, "longline", b"long line bytes\n")

        lines = audit_tail(fresh)
        assert lines and lines[-1] == "exit 0", (
            "audit tail must answer exit 0, got %r" % lines)
        for line in lines[:-1]:
            assert AUDIT_LINE.match(line), (
                "a fragment of a long line must not be shown, got %r" % line)
    finally:
        fresh.stop()


def scenario_failed_audit_append_is_refused(server):
    """An action whose audit line cannot be written answers audit_failed."""
    fresh = Server(server.binary)
    try:
        # A directory where the log goes makes every append fail.
        os.mkdir(audit_log_path(fresh))
        lines = push(fresh, "unrecorded", b"unrecorded bytes\n")
        assert lines == ["audit_failed", "exit 1"], (
            "a push the log cannot record must be refused, got %r" % lines)
        staging_dir = os.path.join(fresh.root, "data", "ariel", "staging")
        assert not os.listdir(staging_dir), (
            "a refused push must stage nothing, found %r" % os.listdir(staging_dir))
    finally:
        fresh.stop()


def scenario_failed_audit_append_after_the_action(server):
    """A grant or commit that cannot be logged answers audit_failed, not success."""
    fresh = Server(server.binary)
    try:
        data = b"late audit bytes\n"
        lines = push(fresh, "lateaudit", data)
        staging, approval = assert_staged(fresh, lines, "lateaudit", data)

        log = audit_log_path(fresh)
        os.rename(log, log + ".saved")
        os.mkdir(log)

        signature = sign_challenge(fresh, challenge_of(lines))
        assert grant(fresh, approval, signature) == ["audit_failed", "exit 1"], (
            "a grant the log cannot record must answer audit_failed")
        assert commit(fresh, staging) == ["audit_failed", "exit 1"], (
            "a commit the log cannot record must answer audit_failed")
    finally:
        fresh.stop()


def scenario_one_canonical_function(server):
    """Exactly one source file builds the canonical action text."""
    del server
    owners = []
    for name in sorted(os.listdir(repo_dir())):
        if name.endswith(".c"):
            with open(os.path.join(repo_dir(), name)) as handle:
                if "ariel-action-v1" in handle.read():
                    owners.append(name)
    assert owners == ["approval.c"], (
        "only approval.c may spell the canonical action: %r" % owners)


def scenario_canonical_encoder(server):
    """The encoder's own tests pass (ambiguous inputs are refused)."""
    del server
    binary = os.path.join(os.path.dirname(os.path.abspath(SERVER_BINARY)),
                          "canonical_test")
    done = subprocess.run([binary], capture_output=True, text=True)
    assert done.returncode == 0, "canonical_test failed:\n" + done.stdout


# ---------------------------------------------------------------------------
# kill (issue #25): gated by the owner's signature, bound to the target pid,
# its signal and its start identity, and refused for critical processes.
# ---------------------------------------------------------------------------

KILL_PROMPT_LINE = re.compile(
    r"^prompt (a-[0-9a-f]+) kill (\d+) with (TERM|KILL|INT|HUP) "
    r"\(start (\S+)\) will run$")


def critical_pid(server):
    """A critical process: the host fixture, or SceShellCore on a console."""
    pid = getattr(server, "critical_pid", None)
    if pid is not None:
        return pid
    rows = rows_of(run_command(server, "ps"))
    for row in rows[1:]:
        if row[-1] == "SceShellCore":
            return int(row[0])
    raise AssertionError("the console lists no SceShellCore: %r" % rows)


def kill_audit(server, kind, name):
    """The audit lines of one kind that name one target."""
    return [event for event in audit_tail(server)
            if AUDIT_LINE.match(event)
            and event.split()[1] == kind and event.split()[2] == str(name)]


def kill_approval(server, pid, sig="TERM"):
    """Request a kill and check its 75, challenge and prompt.

    Returns the approval ID, the challenge line and the start identity the
    challenge binds to the process.
    """
    server.advance(120000)
    lines = run_command(server, "kill %d %s" % (pid, sig))
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "a kill needing approval must answer 75, got %r" % lines)
    approval = APPROVAL_LINE.match(lines[0])
    challenge = CHALLENGE_LINE.match(lines[1])
    assert approval and challenge and challenge.group(1) == approval.group(1), (
        "expected approval_required and a matching challenge, got %r" % lines)
    action = challenge_action(lines[1]).split("\n")
    assert "command=kill" in action and "target=%d" % pid in action and (
        "option.signal=%s" % sig in action), (
        "the challenge must name the kill, its pid and its signal: %r" % action)
    starts = [line[len("option.start="):] for line in action
              if line.startswith("option.start=")]
    assert len(starts) == 1, "the challenge must bind one start: %r" % action
    prompt = KILL_PROMPT_LINE.match(server.next_line() or "")
    assert prompt and prompt.group(1) == approval.group(1) and (
        prompt.group(2) == str(pid)) and prompt.group(3) == sig, (
        "expected the kill prompt for %d, got %r" % (pid, lines))
    assert prompt.group(4) == starts[0], "the prompt must show the bound start"
    return approval.group(1), lines[1], starts[0]


def spawn_victim():
    return subprocess.Popen(["sleep", "600"])


def scenario_kill_bad_arguments(server):
    """The signal is read before the pid; a bad pid is unknown, and a wrong
    arity is not a kill, so it is gated like any unlisted command."""
    assert run_command(server, "kill 99999999 NOPE") == [
        "bad_signal", "exit 1"]
    assert run_command(server, "kill 99999999 TERM") == [
        "no_such_process", "exit 1"]
    assert run_command(server, "kill x TERM") == ["unknown_command", "exit 1"]
    server.assert_no_line()
    assert_unlisted_gated(server, "kill TERM")


def scenario_kill_critical_refused(server):
    """A critical process is refused with exit 87: no approval, no signal."""
    pid = critical_pid(server)
    assert run_command(server, "kill %d TERM" % pid) == [
        "protected", "exit 87"], "a critical process must be refused"
    server.assert_no_line()
    assert kill_audit(server, "kill.protected", pid), (
        "the refusal must be in the audit log")


def scenario_kill_own_process_refused(server):
    """Ariel never signals its own process: exit 87, no approval asked."""
    pid = server.proc.pid
    assert run_command(server, "kill %d TERM" % pid) == [
        "protected", "exit 87"], "Ariel's own process must be refused"
    server.assert_no_line()


def scenario_kill_needs_grant_and_runs_once(server):
    """A kill waits for the owner's signature, then runs once and is audited."""
    victim = spawn_victim()
    try:
        pid = victim.pid
        approval, challenge, _start = kill_approval(server, pid, "TERM")
        assert victim.poll() is None, "the victim must live until the grant"
        sign_and_grant(server, approval, challenge)
        assert run_command(server, "kill %d TERM" % pid) == [
            "killed %d TERM" % pid, "exit 0"], "the granted kill must run"
        assert victim.wait(timeout=5) == -signal.SIGTERM, (
            "the victim must die of SIGTERM")
        assert approval_status(server, approval) == [
            "approval_status %s consumed" % approval, "exit 0"], (
            "a performed kill spends its approval")
        ours = [event.split()[1] for event in audit_tail(server)
                if AUDIT_LINE.match(event) and event.split()[3] == approval]
        assert ours == ["kill.request", "grant", "kill.done"], (
            "the audit log must show the request, the grant and the kill: %r"
            % ours)
    finally:
        victim.kill()
        victim.wait()


def scenario_kill_stale_after_restart(server):
    """A process restarted under the same pid answers 78 and is not signalled."""
    victim = spawn_victim()
    try:
        pid = victim.pid
        approval, challenge, start = kill_approval(server, pid, "TERM")
        sign_and_grant(server, approval, challenge)
        server.controller("restart %d" % pid, "restarted %d" % pid)
        assert run_command(server, "kill %d TERM" % pid) == [
            "approval_stale", "exit 78"], (
            "a restarted process must answer approval_stale")
        assert victim.poll() is None, "a stale approval must signal nothing"
        assert kill_audit(server, "kill.stale", pid), (
            "the stale refusal must be in the audit log")
        _approval, _challenge, restarted = kill_approval(server, pid, "TERM")
        assert restarted != start, (
            "the restarted process must bind a new start identity")
        assert victim.poll() is None
    finally:
        victim.kill()
        victim.wait()


def scenario_kill_retarget_refused(server):
    """A signature for another signal or start is refused; the real one runs."""
    victim = spawn_victim()
    try:
        pid = victim.pid
        approval, challenge, start = kill_approval(server, pid, "TERM")
        swaps = [
            ("signal", "option.signal=TERM", "option.signal=KILL"),
            ("start", "option.start=%s" % start, "option.start=h.9"),
        ]
        for what, old, new in swaps:
            signature = sign_challenge(server, retarget(challenge, old, new))
            assert grant(server, approval, signature) == [
                "signature_action_mismatch", "exit 85"], (
                "a signature for another %s must be refused" % what)
        assert victim.poll() is None, "a refused grant must signal nothing"
        sign_and_grant(server, approval, challenge)
        assert run_command(server, "kill %d TERM" % pid) == [
            "killed %d TERM" % pid, "exit 0"]
        assert victim.wait(timeout=5) == -signal.SIGTERM
    finally:
        victim.kill()
        victim.wait()


BUILTIN_PROMPT_LINE = re.compile(r"^prompt (a-[0-9a-f]+) (.+) will run$")


def builtin_scenario(scenario):
    """Clear the approval table and unread output, pass or fail, so no scenario leaks."""
    def run(server):
        server.fresh()
        try:
            scenario(server)
        finally:
            while server.next_line(timeout=0.2) is not None:
                pass
            server.fresh()
            while server.next_line(timeout=0.2) is not None:
                pass
    return run


def builtin_approval(server, line, command, target):
    """Request a gated built-in and check its 75, challenge and prompt.

    Returns the approval ID and the challenge line.
    """
    server.fresh()
    lines = run_command(server, line)
    prompt = BUILTIN_PROMPT_LINE.match(server.next_line() or "")
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "%r must answer 75 before it runs, got %r" % (line, lines))
    approval = APPROVAL_LINE.match(lines[0])
    challenge = CHALLENGE_LINE.match(lines[1])
    assert approval and challenge and challenge.group(1) == approval.group(1), (
        "expected approval_required and a matching challenge, got %r" % lines)
    action = action_facts(lines[1])
    assert "command=%s" % command in action and "target=%s" % target in action, (
        "the challenge of %r must name its command and target: %r"
        % (line, action))
    assert prompt and prompt.group(1) == approval.group(1), (
        "expected the prompt for %r, got %r" % (line, lines))
    return approval.group(1), lines[1]


@builtin_scenario
def scenario_builtins_ask_before_they_run(server):
    """Each gated built-in answers 75 with its challenge before anything runs."""
    app = write_scratch(server, "app", b"app\n")
    cases = [
        ("launch PPSA01234", "launch", "PPSA01234"),
        ("pkg_install %s" % app, "pkg_install", app),
        ("hbldr %s" % app, "hbldr", app),
        ("hbdbg %s" % app, "hbdbg", app),
        ("suspend", "suspend", "suspend"),
        ("notify hello", "notify", "hello"),
    ]
    for line, command, target in cases:
        builtin_approval(server, line, command, target)


@builtin_scenario
def scenario_builtin_grant_runs_once_on_host(server):
    """A granted launch runs once; the host build answers it as unavailable."""
    approval, challenge = builtin_approval(
        server, "launch PPSA01234", "launch", "PPSA01234")
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "launch PPSA01234") == [
        "not available on this platform", "exit 1"], (
        "the granted launch must reach the platform once")
    ours = [event.split()[1] for event in audit_tail(server)
            if AUDIT_LINE.match(event) and event.split()[3] == approval]
    assert ours == ["launch.request", "grant", "launch.done"], (
        "the audit log must show the request, the grant and the run: %r" % ours)


@builtin_scenario
def scenario_builtin_arguments_are_bound(server):
    """A grant for one argument does not run a built-in with another."""
    approval, challenge = builtin_approval(
        server, "launch PPSA01234 one", "launch", "PPSA01234")
    action = action_facts(challenge)
    assert "option.arg1=one" in action, (
        "the owner must read the argument itself, not a digest: %r" % action)
    sign_and_grant(server, approval, challenge)
    lines = run_command(server, "launch PPSA01234 two")
    assert lines == ["approval_stale", "exit 78"], (
        "a changed argument must not run on the grant, got %r" % (lines,))
    assert kill_audit(server, "launch.stale", "PPSA01234"), (
        "a stale built-in must be audited as launch.stale")


@builtin_scenario
def scenario_builtin_bad_arguments_are_refused_without_asking(server):
    """A missing operand, a relative path or a bad value answers without asking."""
    for command, answer in (
            ("hbldr", ["missing_operand", "exit 1"]),
            ("hbldr app", ["relative_path", "exit 1"]),
            ("notify a\x7fb", ["bad_path", "exit 1"]),
            ("launch PPSA01234 a\x7fb", ["bad_path", "exit 1"]),
            ("launch PPSA01234 %s" % ("x" * 65), ["bad_argument", "exit 1"]),
            ("launch PPSA01234 1 2 3 4 5 6", ["bad_argument", "exit 1"])):
        lines = run_command(server, command)
        assert lines == answer, (
            "%r must answer %r without asking, got %r" % (command, answer, lines))
    server.assert_no_line()


@builtin_scenario
def scenario_builtin_arguments_are_named_in_order(server):
    """Each argument after the target is an option of its own, in order."""
    app = write_scratch(server, "ordered", b"app\n")
    _, challenge = builtin_approval(
        server, "hbldr %s two one" % app, "hbldr", app)
    action = action_facts(challenge)
    assert "option.arg1=two" in action and "option.arg2=one" in action, (
        "the arguments must be named in the order given: %r" % action)
    assert not [field for field in action if field.startswith("option.args=")], (
        "a built-in must not bind its arguments by digest: %r" % action)


@builtin_scenario
def scenario_builtin_protected_is_refused_without_asking(server):
    """A built-in that names Ariel's token answers protected and asks nothing."""
    token = secret_path(server, "token")
    assert_protected(server, "hbldr %s" % token)
    assert_protected(server, "pkg_install %s" % token)
    server.assert_no_line()
    assert kill_audit(server, "hbldr.protected", token), (
        "the refusal must be in the audit log")


@builtin_scenario
def scenario_reptyr_restarted_process_is_stale(server):
    """A process restarted under the same pid answers 78 and is not reattached."""
    victim = spawn_victim()
    try:
        pid = victim.pid
        approval, challenge = builtin_approval(
            server, "reptyr %d" % pid, "reptyr", str(pid))
        sign_and_grant(server, approval, challenge)
        server.controller("restart %d" % pid, "restarted %d" % pid)
        assert run_command(server, "reptyr %d" % pid) == [
            "approval_stale", "exit 78"], (
            "a restarted process must answer approval_stale")
        assert victim.poll() is None, "a stale approval must touch nothing"
    finally:
        victim.kill()
        victim.wait()


@builtin_scenario
def scenario_reptyr_critical_is_refused(server):
    """reptyr of a critical process answers protected and exit 87, asking nothing."""
    pid = critical_pid(server)
    assert run_command(server, "reptyr %d" % pid) == [
        "protected", "exit 87"], "a critical process must be refused"
    server.assert_no_line()
    assert kill_audit(server, "reptyr.protected", pid), (
        "the refusal must be in the audit log")


@builtin_scenario
def scenario_builtin_file_replaced_is_stale(server):
    """A file replaced after approval answers approval_stale and exit 78."""
    app = write_scratch(server, "replaced", b"first\n")
    approval, challenge = builtin_approval(
        server, "hbldr %s" % app, "hbldr", app)
    sign_and_grant(server, approval, challenge)
    staged = app + "-new"
    with open(staged, "wb") as f:
        f.write(b"second\n")
    os.replace(staged, app)
    assert run_command(server, "hbldr %s" % app) == [
        "approval_stale", "exit 78"], "a replaced file must answer 78"


SERVER_BINARY = "./ariel-host"


# ---------------------------------------------------------------------------
# env, export and exec (issue #31): gated by the owner's signature. env reveals
# one named variable, export sets one, and exec runs one program by path with
# its arguments. Each signed action names the variable or the program.
# ---------------------------------------------------------------------------

def args_hash(*args):
    """The hash an exec challenge binds its arguments to: each one, then a NUL."""
    return hashlib.sha256(
        b"".join(arg.encode("ascii") + b"\0" for arg in args)).hexdigest()


def gated_request(server, command, expected_action, prompt, wait_ms=120000):
    """Request a gated command and check its 75, challenge, action and prompt.

    Returns the approval ID and the challenge line.
    """
    server.advance(wait_ms)
    lines = run_command(server, command)
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "%s must answer approval_required and exit 75, got %r" % (command, lines))
    approval = APPROVAL_LINE.match(lines[0])
    challenge = CHALLENGE_LINE.match(lines[1])
    assert approval and challenge and challenge.group(1) == approval.group(1), (
        "expected approval_required and a matching challenge, got %r" % lines)
    action = action_facts(lines[1])
    for line in expected_action:
        assert line in action, (
            "%s: the challenge must carry %r, got %r" % (command, line, action))
    shown = server.next_line() or ""
    assert shown == "prompt %s %s" % (approval.group(1), prompt), (
        "%s: expected the prompt %r, got %r" % (command, prompt, shown))
    return approval.group(1), lines[1]


def assert_asks_again(server, command):
    """A command whose grant was spent asks the owner again."""
    server.advance(120000)
    lines = run_command(server, command)
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "%s must ask again after its grant was used, got %r" % (command, lines))
    assert APPROVAL_LINE.match(lines[0]), (
        "%s must answer approval_required, got %r" % (command, lines))
    assert (server.next_line() or "").startswith("prompt "), (
        "%s must prompt the owner again" % command)


def scenario_env_needs_grant_and_reveals(server):
    """env waits for the owner's signature, reveals the one variable it names,
    and a second reveal asks again."""
    name = "PATH"
    approval, challenge = gated_request(
        server, "env " + name,
        ["command=env", "target=%s" % name, "sha256=none"],
        "env %s will run" % name)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "env " + name) == [
        "%s=%s" % (name, os.environ[name]), "exit 0"], (
        "the granted env must reveal the variable")
    assert approval_status(server, approval) == [
        "approval_status %s consumed" % approval, "exit 0"], (
        "a performed env spends its approval")
    assert_asks_again(server, "env " + name)
    ours = [event.split()[1] for event in audit_tail(server)
            if AUDIT_LINE.match(event) and event.split()[3] == approval]
    assert ours == ["env.request", "grant", "env.done"], (
        "the audit log must show the request, the grant and the reveal: %r"
        % ours)


def scenario_export_needs_grant_and_sets(server):
    """export waits for the owner's signature and sets the variable it names;
    env then reveals the value through its own grant."""
    name = "ARIEL_GATE_EXPORT"
    value = "first"
    approval, challenge = gated_request(
        server, "export %s=%s" % (name, value),
        ["command=export", "target=%s" % name,
         "sha256=%s" % hashlib.sha256(value.encode("ascii")).hexdigest()],
        "export %s will run" % name)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "export %s=%s" % (name, value)) == [
        "exported %s" % name, "exit 0"], "the granted export must run"
    reveal, reveal_challenge = gated_request(
        server, "env " + name, ["command=env", "target=%s" % name],
        "env %s will run" % name)
    sign_and_grant(server, reveal, reveal_challenge)
    assert run_command(server, "env " + name) == [
        "%s=%s" % (name, value), "exit 0"], "env must show the exported value"


def scenario_export_changed_value_is_stale(server):
    """An export whose value changed after the owner signed answers
    approval_stale, sets nothing and spends the approval."""
    name = "ARIEL_GATE_STALE"
    approval, challenge = gated_request(
        server, "export %s=one" % name,
        ["command=export", "target=%s" % name,
         "sha256=%s" % hashlib.sha256(b"one").hexdigest()],
        "export %s will run" % name)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "export %s=two" % name) == [
        "approval_stale", "exit 78"], "a changed value must answer approval_stale"
    assert approval_status(server, approval) == [
        "approval_status %s consumed" % approval, "exit 0"], (
        "a stale export spends its approval")
    assert not kill_audit(server, "export.done", name), (
        "a stale export must not be performed")
    assert kill_audit(server, "export.stale", name), (
        "a stale export must be audited")


def exec_request(server, path, data, args):
    """Ask for exec of path with args and check the challenge names the program."""
    command = " ".join(["exec", path] + list(args))
    return gated_request(
        server, command,
        ["command=exec", "target=%s" % path,
         "sha256=%s" % hashlib.sha256(data).hexdigest(),
         "option.argc=%d" % len(args),
         "option.args=%s" % args_hash(*args)],
        "exec %s will run" % path)


def scenario_exec_needs_grant_and_runs_once(server):
    """exec waits for the owner's signature for the program's bytes and its
    arguments, runs it once with them, and asks again after."""
    data = compile_payload(HELLO_SOURCE, "exec-hello")
    path = write_scratch(server, "exec-hello", data)
    approval, challenge = exec_request(server, path, data, ["one", "two"])
    sign_and_grant(server, approval, challenge)
    command = "exec %s one two" % path
    assert run_command(server, command) == [
        "Hello, world from Ariel!", "argv[1] = one", "argv[2] = two",
        "status 0", "exit 0"], "the granted exec must run the program once"
    assert approval_status(server, approval) == [
        "approval_status %s consumed" % approval, "exit 0"], (
        "a performed exec spends its approval")
    assert_asks_again(server, command)
    ours = [event.split()[1] for event in audit_tail(server)
            if AUDIT_LINE.match(event) and event.split()[3] == approval]
    assert ours == ["exec.request", "grant", "exec.done"], (
        "the audit log must show the request, the grant and the run: %r" % ours)


def scenario_exec_args_are_bound(server):
    """An exec with other arguments after the grant answers approval_stale,
    runs nothing and spends the approval."""
    data = compile_payload(HELLO_SOURCE, "exec-args")
    path = write_scratch(server, "exec-args", data)
    approval, challenge = exec_request(server, path, data, ["one"])
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "exec %s two" % path) == [
        "approval_stale", "exit 78"], "other arguments must answer approval_stale"
    assert approval_status(server, approval) == [
        "approval_status %s consumed" % approval, "exit 0"], (
        "a stale exec spends its approval")
    assert kill_audit(server, "exec.stale", path), "a stale exec must be audited"
    assert not kill_audit(server, "exec.done", path), (
        "a stale exec must not run the program")


def scenario_exec_replaced_is_stale(server):
    """A program replaced after the owner signed answers approval_stale and
    does not run."""
    data = compile_payload(HELLO_SOURCE, "exec-swap")
    path = write_scratch(server, "exec-swap", data)
    approval, challenge = exec_request(server, path, data, ["one"])
    sign_and_grant(server, approval, challenge)
    with open(path, "wb") as handle:
        handle.write(data + b"\0")
    assert run_command(server, "exec %s one" % path) == [
        "approval_stale", "exit 78"], "a replaced program must answer approval_stale"
    assert kill_audit(server, "exec.stale", path), "a stale exec must be audited"


def scenario_env_export_exec_refusals(server):
    """A bad variable name, a relative or missing program and a protected file
    are refused without a question, and each refusal is audited."""
    assert run_command(server, "env A=B") == ["bad_name", "exit 1"]
    assert run_command(server, "env 1X") == ["bad_name", "exit 1"]
    assert run_command(server, "export 9X=1") == ["bad_name", "exit 1"]
    assert run_command(server, "exec relative/prog") == [
        "relative_path", "exit 1"]
    missing = os.path.join(server.root, "data", "gate-missing")
    assert run_command(server, "exec " + missing) == [
        "no_such_file", "exit 1"]
    assert_protected(server, "exec " + secret_path(server, "token"))
    server.assert_no_line()
    kinds = {event.split()[1] for event in audit_tail(server)
             if AUDIT_LINE.match(event)}
    assert {"env.refused", "export.refused", "exec.refused",
            "exec.protected"} <= kinds, (
        "each refusal must reach audit tail, got %r" % sorted(kinds))


TAR_GOOD = [
    ("hello.txt", "file", b"hi\n"),
    ("sub", "dir", None),
    ("sub/a.txt", "file", b"a\n"),
]

# Each archive puts a good member first, so a naive extraction would write it
# before reaching the member that escapes.
TAR_ESCAPES = (
    ("parent", [("ok.txt", "file", b"ok\n"), ("../t-escape.txt", "file", b"x\n")]),
    ("absolute", [("ok.txt", "file", b"ok\n"), ("/t-escape.txt", "file", b"x\n")]),
    ("nested", [("ok.txt", "file", b"ok\n"),
                ("sub/../../t-escape.txt", "file", b"x\n")]),
    ("link-up", [("ok.txt", "file", b"ok\n"), ("up", "link", "../t-escape")]),
    ("link-absolute", [("ok.txt", "file", b"ok\n"), ("abs", "link", "/etc")]),
    ("link-nested", [("ok.txt", "file", b"ok\n"),
                     ("sub/deep/up", "link", "../../../t-escape")]),
    ("link-then-write", [("ok.txt", "file", b"ok\n"), ("jump", "link", "..")]),
    ("hard-up", [("ok.txt", "file", b"ok\n"), ("up", "hard", "../t-escape")]),
)

# A link that stays under the destination is not extracted in this slice.
TAR_LINKS_INSIDE = (
    ("link-inside", [("ok.txt", "file", b"ok\n"), ("alias", "link", "ok.txt")]),
    ("hard-inside", [("ok.txt", "file", b"ok\n"), ("alias", "hard", "ok.txt")]),
)


def make_tar_archive(server, name, members):
    """A ustar archive in the host test root's data directory.

    Each member is (name, kind, payload): kind is file, dir, link or hard;
    a link's payload is its target, and a file's payload is its bytes.
    """
    path = os.path.join(server.root, "data", name)
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as tar:
        for member_name, kind, payload in members:
            info = tarfile.TarInfo(member_name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind in ("link", "hard"):
                info.type = tarfile.SYMTYPE if kind == "link" else tarfile.LNKTYPE
                info.linkname = payload
                tar.addfile(info)
            else:
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    return path


def make_dest(server, name):
    path = os.path.join(server.root, "data", name)
    os.makedirs(path, exist_ok=True)
    return path


def scenario_tar_refusals_need_no_approval(server):
    """tar with a bad shape, a relative or protected path, or a missing archive answers at once and asks nothing."""
    for line, answer in (
            ("tar", ["bad_argument", "exit 1"]),
            ("tar -t", ["bad_argument", "exit 1"]),
            ("tar -x /data/t-a-tar", ["bad_argument", "exit 1"]),
            ("tar -t relative.tar", ["relative_path", "exit 1"]),
            ("tar -x /data/t-a-tar relative", ["relative_path", "exit 1"]),
            ("tar -t /system/t-a-tar", ["protected", "exit 87"]),
            ("tar -x /system/t-a-tar /data/t-out", ["protected", "exit 87"]),
            ("tar -x /data/t-a-tar /system/t-out", ["protected", "exit 87"]),
            ("tar -t " + os.path.join(server.root, "data", "t-no-such-tar"),
             ["no_such_file", "exit 1"])):
        assert run_command(server, line) == answer, (
            "%s must answer %s" % (line, answer[0]))


def scenario_tar_lists_members_at_once(server):
    """tar -t lists every member name in archive order at once, and a non-tar answers not_a_tar."""
    archive = make_tar_archive(server, "t-list-tar", TAR_GOOD)
    assert run_command(server, "tar -t " + archive) == [
        "hello.txt", "sub", "sub/a.txt", "exit 0"], (
        "tar -t must list the members at once and exit 0")
    notes = os.path.join(server.root, "data", "t-notes-tar")
    with open(notes, "wb") as handle:
        handle.write(b"not a tar archive\n" * 8)
    assert run_command(server, "tar -t " + notes) == ["not_a_tar", "exit 1"], (
        "a file that is not a tar archive must answer not_a_tar")


def scenario_tar_extract_needs_the_owner(server):
    """tar -x answers 75 with a challenge naming its facts, extracts after the grant, and never overwrites."""
    archive = make_tar_archive(server, "t-good-tar", TAR_GOOD)
    dest = make_dest(server, "t-good-out")
    line = "tar -x %s %s" % (archive, dest)
    approval, challenge = gate_request(server, line)
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=tar\n"), action
    assert "\ntarget=%s\n" % archive in action, action
    assert "\ndestination=%s\n" % dest in action, action
    digest = hashlib.sha256(read_bytes(archive)).hexdigest()
    assert "\nsha256=%s\n" % digest in action, action

    assert os.listdir(dest) == [], "an unsigned tar must not extract"
    sign_and_grant(server, approval, challenge)
    assert run_command(server, line) == ["exit 0"], "a signed tar must extract"
    assert read_bytes(os.path.join(dest, "hello.txt")) == b"hi\n"
    assert read_bytes(os.path.join(dest, "sub", "a.txt")) == b"a\n"
    assert run_command(server, line) == ["exists", "exit 1"], (
        "extracting over existing members must answer exists without asking")


def scenario_tar_refuses_escaping_members(server):
    """A member or link that escapes the destination is refused at once, and nothing is written."""
    for index, (label, members) in enumerate(TAR_ESCAPES + TAR_LINKS_INSIDE):
        archive = make_tar_archive(server, "t-e%d-tar" % index, members)
        dest = make_dest(server, "t-e%d-out" % index)
        word = "escaping_member" if (label, members) in TAR_ESCAPES else "bad_member"
        lines = run_command(server, "tar -x %s %s" % (archive, dest))
        assert lines == [word, "exit 1"], (
            "%s must answer %s, got %r" % (label, word, lines))
        assert os.listdir(dest) == [], (
            "a refused tar (%s) must write nothing" % label)
    for escaped in (os.path.join(server.root, "data", "t-escape.txt"),
                    os.path.join(server.root, "t-escape.txt")):
        assert not os.path.lexists(escaped), (
            "a member that escapes must never be written, found %s" % escaped)


def scenario_tar_archive_changed_after_grant_answers_78(server):
    """An archive replaced after the owner signs answers approval_stale and writes nothing."""
    archive = make_tar_archive(server, "t-swap-tar", TAR_GOOD)
    dest = make_dest(server, "t-swap-out")
    line = "tar -x %s %s" % (archive, dest)
    approval, challenge = gate_request(server, line)
    sign_and_grant(server, approval, challenge)

    make_tar_archive(server, "t-swap-tar", TAR_ESCAPES[0][1])
    assert run_command(server, line) == ["approval_stale", "exit 78"], (
        "an archive changed after approval must answer approval_stale")
    assert os.listdir(dest) == [], "a changed archive must write nothing"


def scenario_tar_protected_objects_answer_87(server):
    """tar refuses Ariel's own objects, and a member that names one, through any alias, without asking."""
    token = secret_path(server, "token")
    state = os.path.dirname(token)
    good = make_tar_archive(server, "t-prot-tar", TAR_GOOD)
    dest = make_dest(server, "t-prot-out")
    hard = os.path.join(server.root, "data", "t-prot-hard-tar")
    soft = os.path.join(server.root, "data", "t-prot-soft-tar")
    make_link(hard, token, hard=True)
    make_link(soft, token, hard=False)

    for archive in (token, hard, soft):
        assert_protected(server, "tar -t " + archive)
        assert_protected(server, "tar -x %s %s" % (archive, dest))
    assert_protected(server, "tar -x %s %s" % (good, state))
    assert os.listdir(dest) == [], "a protected tar must write nothing"

    before = read_bytes(token)
    clash = make_tar_archive(server, "t-clash-tar", [("clash", "file", b"x\n")])
    make_link(os.path.join(dest, "clash"), token, hard=True)
    assert_protected(server, "tar -x %s %s" % (clash, dest))
    assert read_bytes(token) == before, "a protected token must not change"


def scenario_tar_protected_after_grant_answers_87(server):
    """An archive swapped for a link to Ariel's token after the owner signs runs nothing."""
    token = secret_path(server, "token")
    archive = make_tar_archive(server, "t-alias-tar", TAR_GOOD)
    dest = make_dest(server, "t-alias-out")
    line = "tar -x %s %s" % (archive, dest)
    approval, challenge = gate_request(server, line)
    sign_and_grant(server, approval, challenge)

    os.unlink(archive)
    os.link(token, archive)
    assert run_command(server, line) == ["protected", "exit 87"], (
        "an approved tar of an archive that became the token must answer protected")
    assert os.listdir(dest) == [], "a protected archive must write nothing"


def scenario_tar_actions_are_audited(server):
    """tar listings, runs and refusals reach audit tail under their paths."""
    archive = make_tar_archive(server, "t-audit-tar", TAR_GOOD)
    dest = make_dest(server, "t-audit-out")
    line = "tar -x %s %s" % (archive, dest)
    approval, challenge = gate_request(server, line)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, line) == ["exit 0"]
    assert run_command(server, "tar -t " + archive)[-1] == "exit 0"

    bad = make_tar_archive(server, "t-bad-tar", TAR_ESCAPES[0][1])
    bad_dest = make_dest(server, "t-bad-out")
    assert run_command(server, "tar -x %s %s" % (bad, bad_dest)) == [
        "escaping_member", "exit 1"]
    token = secret_path(server, "token")
    assert_protected(server, "tar -t " + token)

    events = set()
    for line_text in run_exit_zero(server, "audit tail 64"):
        fields = line_text.split()
        if len(fields) == 5:
            events.add((fields[1], fields[2]))
    expected = (
        ("tar.request", "%s>%s" % (archive, dest)),
        ("tar.done", "%s>%s" % (archive, dest)),
        ("tar.list", archive),
        ("tar.refused", "%s>%s" % (bad, bad_dest)),
        ("tar.protected", token),
    )
    for event in expected:
        assert event in events, (
            "audit tail must show %r, got %r" % (event, sorted(events)))


def reboot_action(challenge):
    """The canonical action text that a reboot challenge carries."""
    return bytes.fromhex(challenge.split(" ")[6]).decode("ascii")


def reboot_approve(server):
    """Ask to reboot, sign the challenge and grant it; return the approval ID."""
    approval, challenge = gate_request(server, "reboot")
    sign_and_grant(server, approval, challenge)
    return approval


def reboot_and_wait(server):
    """Send the granted reboot and check the restarted Ariel prints its token again."""
    assert send_command(server, "reboot") == [
        "rebooting", "exit 0"], "a granted reboot must answer rebooting"
    line = server.next_line()
    assert line == "token %s" % server.token, (
        "the restarted Ariel must print its token line, got %r" % line)


def scenario_reboot_asks_the_owner(server):
    """reboot answers 75 with a challenge that names the boot list it will run."""
    listing = autoload_listing(server)
    _approval, challenge = gate_request(server, "reboot")
    action = reboot_action(challenge)
    assert "command=reboot" in action and (
        "sha256=%s" % autoload_list_sha(listing)) in action, (
        "the challenge must name reboot and the boot list, got %r" % action)


def scenario_reboot_granted_restarts_and_runs_autoload(server):
    """A granted reboot restarts Ariel: payloads stay listed and autoload runs."""
    install_hanging(server, "reboot_keep",
                    compile_payload(HANG_SOURCE, "reboot_keep"))
    install_hanging(server, "reboot_boot",
                    compile_payload(HANG_SOURCE, "reboot_boot"))
    approval = autoload_approve(server, "add", "reboot_boot")
    assert autoload_apply(server, "add", "reboot_boot", approval) == [
        "autoload add reboot_boot", "exit 0"], "the boot entry must be added"

    reboot_approve(server)
    reboot_and_wait(server)

    assert listed(payload_list(server), "reboot_keep") is not None, (
        "payload list must show the installed payloads after a reboot")
    listing = autoload_listing(server)
    assert listing[0] == "autoload ariel" and (
        "autoload reboot_boot" in listing), (
        "autoload show must list the boot entry after a reboot, got %r"
        % listing)
    assert running_flag(server, "reboot_boot") == "yes", (
        "the autoload entry must run after a reboot")
    assert running_flag(server, "reboot_keep") == "no", (
        "a payload that is not autoloaded must not run after a reboot")


def scenario_crash_restart_runs_no_autoload(server):
    """A crash restart runs no autoload entry and restarts nothing that was running."""
    install_hanging(server, "crashboot",
                    compile_payload(HANG_SOURCE, "crashboot"))
    install_hanging(server, "crashrun", compile_payload(HANG_SOURCE, "crashrun"))
    approval = autoload_approve(server, "add", "crashboot")
    assert autoload_apply(server, "add", "crashboot", approval) == [
        "autoload add crashboot", "exit 0"], "the boot entry must be added"
    reboot_approve(server)
    reboot_and_wait(server)
    assert running_flag(server, "crashboot") == "yes", (
        "the autoload entry must run after a reboot")

    assert background_run(server, "crashrun")[-1] == "exit 0"
    assert running_flag(server, "crashrun") == "yes"

    server.proc.kill()
    server.proc.wait()
    server.restart()

    assert running_flag(server, "crashboot") == "no", (
        "a crash restart must not run the autoload entries")
    assert running_flag(server, "crashrun") == "no", (
        "a payload running before a crash must not be restarted")
    assert "autoload crashboot" in autoload_listing(server), (
        "the autoload list must survive a crash")


def scenario_reboot_stale_list_answers_78(server):
    """A reboot granted for a boot list that has since changed is stale and does not restart."""
    install_payload(server, "stale_add", compile_payload(HELLO_SOURCE, "stale_add"))
    approval, challenge = gate_request(server, "reboot")

    other = autoload_approve(server, "add", "stale_add")
    assert autoload_apply(server, "add", "stale_add", other) == [
        "autoload add stale_add", "exit 0"], "the other edit must apply"

    sign_and_grant(server, approval, challenge)
    assert send_command(server, "reboot") == [
        "approval_stale", "exit 78"], (
        "a reboot granted for an older boot list is stale")
    server.assert_no_line()
    assert "reboot.stale" in [
        line.split()[1] for line in audit_tail(server)
        if line.split()[3:4] == [approval]], (
        "the stale reboot must be audited")


def scenario_reboot_denied_answers_77(server):
    """A reboot the owner denies answers approval_denied and does not restart."""
    approval, _challenge = gate_request(server, "reboot")
    server.controller("deny %s" % approval, "denied %s" % approval)
    assert send_command(server, "reboot") == [
        "approval_denied", "exit 77"], "a denied reboot must answer approval_denied"
    server.assert_no_line()
    assert "reboot.denied" in [
        line.split()[1] for line in audit_tail(server)
        if line.split()[3:4] == [approval]], (
        "the denied reboot must be audited")


def scenario_reboot_signature_wrong_action(server):
    """A signature for another action than reboot is refused and does not restart.

    The owner then denies the open request, so the next reboot asks afresh.
    """
    approval, challenge = gate_request(server, "reboot")
    signature = sign_challenge(
        server, retarget(challenge, "command=reboot", "command=kill"))
    assert grant(server, approval, signature) == [
        "signature_action_mismatch", "exit 85"], (
        "a signature for another command must be refused")
    server.assert_no_line()
    server.controller("deny %s" % approval, "denied %s" % approval)
    assert send_command(server, "reboot") == [
        "approval_denied", "exit 77"], "the denied request must answer 77"


def scenario_reboot_is_audited(server):
    """A granted reboot is audited as its request, its grant and its done line."""
    # Approval IDs restart with each boot, so only this reboot's lines count.
    before = len(read_audit_log(server))
    approval = reboot_approve(server)
    reboot_and_wait(server)
    lines = read_audit_log(server)[before:].decode("ascii").splitlines()
    ours = [line.split()[1] for line in lines
            if line.split()[3:4] == [approval]]
    assert ours == ["reboot.request", "grant", "reboot.done"], (
        "the reboot must be audited in order, got %r" % ours)


# The one-shot timeout a payload gets until payload config sets one.
DEFAULT_HEALTH_MS = 30_000


def health_events(server):
    """The newest audit lines as (kind, name, id, sha256) tuples, oldest first."""
    return [tuple(line.split()[1:5]) for line in audit_tail(server, 64)
            if line != "exit 0"]


def health_starts(server, name):
    return sum(1 for event in health_events(server)
               if event[0] == "health.start" and event[1] == name)


class Pending:
    """A command sent on its own thread, so a health check can wait on the test clock."""

    def __init__(self, fn, *args):
        self.result = None
        self.thread = threading.Thread(target=self._run, args=(fn, args),
                                       daemon=True)
        self.thread.start()

    def _run(self, fn, args):
        self.result = fn(*args)

    def alive(self):
        return self.thread.is_alive()

    def finish(self):
        self.thread.join(10.0)
        assert not self.thread.is_alive(), "the command never answered"
        return self.result


def wait_for_health(server, name, before):
    """Wait until a health check of name starts past the before count."""
    deadline = time.monotonic() + 5.0
    while health_starts(server, name) <= before:
        assert time.monotonic() < deadline, (
            "the health check of %s never started" % name)
        time.sleep(0.02)


def install_hanging(server, name, data):
    """Commit a build that never exits: its check is cut at the default timeout."""
    digest = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, name, data)
    before = health_starts(server, name)
    pending = Pending(commit, server, staging)
    wait_for_health(server, name, before)
    server.advance(DEFAULT_HEALTH_MS)
    assert pending.finish() == [
        "health_failed %s %s" % (name, digest), "exit 1"], (
        "a build that never exits must fail its one-shot check")
    return digest


def config_one_shot(server, name, timeout_s):
    """Ask, sign and apply payload config for a one-shot health check."""
    command = "payload config %s kind=one-shot timeout=%d" % (name, timeout_s)
    approval, challenge = gate_request(server, command)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, command) == [
        "configured %s kind=one-shot timeout=%d" % (name, timeout_s),
        "exit 0"], "a granted payload config must be applied"
    return approval


def scenario_failing_one_shot_is_replaced_by_previous(server):
    """A one-shot that exits nonzero after commit is replaced by the previous version."""
    good_hash = install_payload(
        server, "healthy", compile_payload(HELLO_SOURCE, "healthy"))
    bad = compile_payload(EXIT_SOURCE.replace("EXIT_CODE", "1"), "healthy-bad")
    bad_hash = hashlib.sha256(bad).hexdigest()

    staging, _ = approve_push(server, "healthy", bad)
    assert commit(server, staging) == [
        "health_failed healthy %s" % bad_hash, "exit 1"], (
        "a one-shot that exits nonzero after commit must answer "
        "health_failed and exit 1")
    assert listed(payload_list(server), "healthy") == expected_listing(
        "healthy", good_hash), (
        "the previous version must be current again, with no previous")

    lines = run_payload(server, "healthy")
    assert "Hello, world from Ariel!" in lines and lines[-2:] == [
        "status 0", "exit 0"], (
        "the restored build must run, got %r" % lines)

    events = health_events(server)
    assert ("health.fail", "healthy", "1", bad_hash) in events, (
        "the failed check must be audited, got %r" % events)
    assert ("health.replace", "healthy", good_hash, bad_hash) in events, (
        "the replacement must be audited, got %r" % events)


def scenario_one_shot_past_its_timeout_fails(server):
    """A one-shot past its timeout fails, and with no previous version it is marked failed."""
    data = compile_payload(HANG_SOURCE, "hunglate")
    digest = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, "hunglate", data)

    before = health_starts(server, "hunglate")
    pending = Pending(commit, server, staging)
    wait_for_health(server, "hunglate", before)
    server.advance(DEFAULT_HEALTH_MS - 1000)
    assert pending.alive(), "a one-shot must not fail before its timeout"
    server.advance(1000)

    assert pending.finish() == [
        "health_failed hunglate %s" % digest, "exit 1"], (
        "a one-shot past its timeout must answer health_failed and exit 1")
    assert listed(payload_list(server), "hunglate") == expected_listing(
        "hunglate", digest, failed=True), (
        "a build with no previous version must be marked failed")
    assert any(event[0] == "health.timeout" and event[1] == "hunglate"
               and event[3] == digest for event in health_events(server)), (
        "the timeout must be audited")


def scenario_failed_one_shot_leaves_autoload(server):
    """With no previous version, a one-shot that fails is removed from autoload."""
    data = compile_payload(SLEEP_SOURCE, "sleepy")
    digest = install_payload(server, "sleepy", data)
    approval = autoload_approve(server, "add", "sleepy")
    assert autoload_apply(server, "add", "sleepy", approval) == [
        "autoload add sleepy", "exit 0"], "a granted autoload add must apply"
    config_one_shot(server, "sleepy", 1)
    assert "autoload sleepy" in autoload_listing(server), (
        "the payload must be in autoload before its check fails")

    staging, _ = approve_push(server, "sleepy", data)
    before = health_starts(server, "sleepy")
    pending = Pending(commit, server, staging)
    wait_for_health(server, "sleepy", before)
    server.advance(1000)

    assert pending.finish() == [
        "health_failed sleepy %s" % digest, "exit 1"], (
        "a one-shot past its timeout must answer health_failed and exit 1")
    assert "autoload sleepy" not in autoload_listing(server), (
        "a failed payload with no previous version must leave autoload")
    assert listed(payload_list(server), "sleepy") == expected_listing(
        "sleepy", digest, failed=True), (
        "a build with no previous version must be marked failed")
    assert any(event[0] == "autoload_remove" and event[1] == "sleepy"
               for event in health_events(server)), (
        "the removal from autoload must be audited")


def scenario_health_log_unopenable_fails_and_is_audited(server):
    """A health check whose log cannot be opened fails, and is audited as health.fail."""
    fresh = Server(server.binary)
    try:
        data = healthy_build("nolog")
        digest = hashlib.sha256(data).hexdigest()
        # A directory where the payload's log goes makes the log unopenable.
        os.makedirs(os.path.join(fresh.root, "data", "ariel", "logs",
                                 "nolog.log"))
        staging, _ = approve_push(fresh, "nolog", data)
        assert commit(fresh, staging) == [
            "health_failed nolog %s" % digest, "exit 1"], (
            "a check whose log cannot be opened must fail")
        events = health_events(fresh)
        assert ("health.fail", "nolog", "-", digest) in events, (
            "a check that could not open its log must be audited as "
            "health.fail, got %r" % events)
    finally:
        fresh.stop()


def scenario_config_refuses_a_timeout_over_an_hour(server):
    """payload config refuses a timeout over one hour before it asks the owner."""
    install_payload(server, "capped", healthy_build("capped-build"))
    for seconds in ("3601", "999999999"):
        command = "payload config capped kind=one-shot timeout=%s" % seconds
        assert run_command(server, command) == ["bad_argument", "exit 1"], (
            "a timeout of %s s must be refused without a prompt" % seconds)


def scenario_ad_hoc_run_starts_no_health_check(server):
    """An ad-hoc payload run starts no health check, whatever its build did."""
    data = compile_payload(EXIT_SOURCE.replace("EXIT_CODE", "1"), "adhoc")
    digest = hashlib.sha256(data).hexdigest()
    staging, _ = approve_push(server, "adhoc", data)
    assert commit(server, staging) == [
        "health_failed adhoc %s" % digest, "exit 1"], (
        "a one-shot that exits nonzero after commit must answer health_failed")
    assert payload_logs(server, "adhoc") == ["exiting 1", "exit 0"], (
        "the health check's output must be in the payload's log")

    checks = health_starts(server, "adhoc")
    assert run_payload(server, "adhoc") == [
        "exiting 1", "status 1", "exit 0"], (
        "an ad-hoc run must answer the payload's own status")
    assert health_starts(server, "adhoc") == checks, (
        "an ad-hoc run must not start a health check")


def scenario_health_output_stays_in_the_log(server):
    """A healthy one-shot's output is in payload logs, and the commit reply holds none of it."""
    install_payload(
        server, "logged", compile_payload(HELLO_SOURCE, "logged"))
    assert payload_logs(server, "logged") == [
        "Hello, world from Ariel!", "exit 0"], (
        "the health check's output must be in the payload's log")


def scenario_payload_config_is_gated_and_audited(server):
    """payload config waits for the owner, applies after a grant and is audited."""
    install_payload(server, "tuned", compile_payload(HELLO_SOURCE, "tuned"))
    command = "payload config tuned kind=one-shot timeout=5"
    approval, challenge = gate_request(server, command)
    sign_and_grant(server, approval, challenge)
    assert run_command(server, command) == [
        "configured tuned kind=one-shot timeout=5", "exit 0"], (
        "a granted payload config must be applied")

    events = health_events(server)
    assert ("payload.config.request", "tuned", approval, "none") in events, (
        "the request must be audited, got %r" % events)
    assert ("payload.config.done", "tuned", approval, "none") in events, (
        "the applied config must be audited, got %r" % events)

    assert run_command(server, "payload config nosuch kind=one-shot timeout=5") == [
        "unknown_payload", "exit 1"], "an unknown payload must be refused"
    assert run_command(server, "payload config tuned kind=service timeout=5") == [
        "unsupported_kind", "exit 1"], "a kind that is not one-shot must be refused"
    assert run_command(server, "payload config tuned kind=one-shot timeout=0") == [
        "bad_argument", "exit 1"], "a timeout of 0 must be refused"


def scenario_failed_rollback_restores_the_build_it_replaced(server):
    """A rollback whose restored build fails its health check is replaced by the build it rolled back from."""
    old_hash = install_payload(
        server, "rollold", compile_payload(SLEEP_SOURCE, "rollold-sleep"))
    new_hash = install_payload(
        server, "rollold", compile_payload(HELLO_SOURCE, "rollold-hello"))
    config_one_shot(server, "rollold", 1)

    lines = rollback_request(server, "rollold")
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "a rollback without a grant must answer exit 75, got %r" % lines)
    approval = APPROVAL_LINE.match(lines[0]).group(1)
    server.next_line()
    sign_and_grant(server, approval, challenge_of(lines))

    before = health_starts(server, "rollold")
    pending = Pending(send_command, server, "payload rollback rollold")
    wait_for_health(server, "rollold", before)
    server.advance(1000)

    assert pending.finish() == [
        "health_failed rollold %s" % old_hash, "exit 1"], (
        "a rollback whose restored build fails must answer health_failed")
    assert listed(payload_list(server), "rollold") == expected_listing(
        "rollold", new_hash), (
        "the build rolled back from must be current again, with no previous")
    assert ("health.replace", "rollold", new_hash, old_hash) in health_events(
        server), "the replacement must be audited"


def safe_boot_approve(server):
    """Ask for autoload safe-boot, sign the challenge and grant it."""
    approval, challenge = gate_request(server, "autoload safe-boot")
    sign_and_grant(server, approval, challenge)
    return approval


def scenario_safe_boot_asks_the_owner(server):
    """autoload safe-boot answers 75 with a challenge that names the boot list it skips."""
    listing = autoload_listing(server)
    approval, challenge = gate_request(server, "autoload safe-boot")
    action = reboot_action(challenge)
    assert "command=autoload.safe-boot" in action and (
        "sha256=%s" % autoload_list_sha(listing)) in action, (
        "the challenge must name safe-boot and the boot list, got %r" % action)
    server.controller("deny %s" % approval, "denied %s" % approval)
    assert send_command(server, "autoload safe-boot") == [
        "approval_denied", "exit 77"], "a denied safe-boot must answer 77"
    assert autoload_listing(server) == listing, (
        "a denied safe-boot must leave the boot list as it was")


def scenario_safe_boot_skips_autoload_for_one_boot(server):
    """A granted safe-boot skips autoload on the next boot, and autoload is back after it."""
    install_hanging(server, "safe_keep",
                    compile_payload(HANG_SOURCE, "safe_keep"))
    install_hanging(server, "safe_boot",
                    compile_payload(HANG_SOURCE, "safe_boot"))
    approval = autoload_approve(server, "add", "safe_boot")
    assert autoload_apply(server, "add", "safe_boot", approval) == [
        "autoload add safe_boot", "exit 0"], "the boot entry must be added"

    approval = safe_boot_approve(server)
    assert send_command(server, "autoload safe-boot") == [
        "autoload safe-boot", "exit 0"], "a granted safe-boot must apply"
    assert autoload_listing(server) == ["autoload ariel", "exit 0"], (
        "safe-boot must leave only Ariel in the boot list")

    reboot_approve(server)
    reboot_and_wait(server)
    assert running_flag(server, "safe_boot") == "no", (
        "safe-boot must skip the autoload entry on the next boot")
    assert running_flag(server, "safe_keep") == "no", (
        "safe-boot must skip every autoload entry on the next boot")
    assert "autoload safe_boot" in autoload_listing(server), (
        "the next start must restore the boot list the skip left aside")

    reboot_approve(server)
    reboot_and_wait(server)
    assert running_flag(server, "safe_boot") == "yes", (
        "autoload must be back on the boot after the skipped one")

    events = [line.split() for line in audit_tail(server)
              if line.split()[3:4] == [approval]]
    assert [event[1] for event in events] == [
        "autoload.safe-boot.request", "grant", "autoload_safe_boot"], (
        "safe-boot must be audited as its request, grant and change, got %r"
        % events)
    assert "autoload_restore" in [event[0] for event in audit_events(server)], (
        "the restore at the next start must be audited")


def scenario_safe_boot_stale_answers_78(server):
    """A safe-boot granted for a boot list that has since changed answers 78 and changes nothing."""
    install_payload(server, "safe_stale",
                    compile_payload(HELLO_SOURCE, "safe_stale"))
    approval, challenge = gate_request(server, "autoload safe-boot")

    other = autoload_approve(server, "add", "safe_stale")
    assert autoload_apply(server, "add", "safe_stale", other) == [
        "autoload add safe_stale", "exit 0"], "the other edit must apply"

    sign_and_grant(server, approval, challenge)
    assert send_command(server, "autoload safe-boot") == [
        "approval_stale", "exit 78"], (
        "a safe-boot granted for an older boot list is stale")
    assert "autoload safe_stale" in autoload_listing(server), (
        "a stale safe-boot must leave the boot list as it was")
    assert "autoload.safe-boot.stale" in [
        line.split()[1] for line in audit_tail(server)
        if line.split()[3:4] == [approval]], (
        "the stale safe-boot must be audited")


def scenario_safe_boot_refused_while_pending(server):
    """A second safe-boot while one is pending answers safe_boot_pending and asks nothing."""
    listing = autoload_listing(server)
    safe_boot_approve_and_apply(server)
    assert send_command(server, "autoload safe-boot") == [
        "safe_boot_pending", "exit 1"], (
        "a second safe-boot must not replace the boot list it left aside")
    server.assert_no_line()
    assert "autoload.safe-boot.refused" in [
        line.split()[1] for line in audit_tail(server)], (
        "the refused safe-boot must be audited")
    reboot_approve(server)
    reboot_and_wait(server)
    assert autoload_listing(server) == listing, (
        "the next start must restore the boot list the first safe-boot left aside")


def safe_boot_approve_and_apply(server):
    """Approve and apply one safe-boot, leaving the boot list only Ariel's."""
    safe_boot_approve(server)
    assert send_command(server, "autoload safe-boot") == [
        "autoload safe-boot", "exit 0"], "a granted safe-boot must apply"


def make_tree(server, name, files, dirs=()):
    """A tree under the host test root's data directory: files maps paths to bytes."""
    root = os.path.join(server.root, "data", name)
    for rel in dirs:
        os.makedirs(os.path.join(root, rel), exist_ok=True)
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    return root


def scenario_ls_long_and_all(server):
    """ls -l shows detail, ls -a adds . and .., and plain ls is unchanged."""
    folder = make_tree(server, "ls-flags",
                       {"visible.txt": b"hello", ".hidden": b"", "sub/keep": b""})
    assert run_exit_zero(server, "ls " + folder) == [
        ".hidden", "sub", "visible.txt"], "plain ls must list the names only"
    assert run_exit_zero(server, "ls -a " + folder) == [
        ".", "..", ".hidden", "sub", "visible.txt"], "ls -a must add . and .."
    fields = {}
    for line in run_exit_zero(server, "ls -l " + folder):
        parts = line.split()
        fields[parts[-1]] = parts
    assert set(fields) == {".hidden", "sub", "visible.txt"}, (
        "ls -l must list each name once, got %r" % sorted(fields))
    assert fields["visible.txt"][0].startswith("-"), "a file's mode starts with -"
    assert fields["visible.txt"][1] == "5", "ls -l must show the size in bytes"
    assert fields["sub"][0].startswith("d"), "a directory's mode starts with d"
    both = run_exit_zero(server, "ls -l -a " + folder)
    assert [line.split()[-1] for line in both] == [
        ".", "..", ".hidden", "sub", "visible.txt"], "ls -l -a must give both"
    assert run_command(server, "ls -x " + folder) == ["bad_option", "exit 1"], (
        "an unsupported ls option must answer bad_option")


def scenario_grep_recursive_and_combined(server):
    """grep -r searches a tree; -l names files, -c counts, and -l wins over -c."""
    tree = make_tree(server, "grep-tree", {
        "a.txt": b"needle one\nnothing\nneedle two\n",
        "sub/b.txt": b"needle\n",
        "d.txt": b"no match\n",
    })
    a = os.path.join(tree, "a.txt")
    b = os.path.join(tree, "sub", "b.txt")
    d = os.path.join(tree, "d.txt")
    assert set(run_exit_zero(server, "grep -r needle " + tree)) == {
        a + ":needle one", a + ":needle two", b + ":needle"}, (
        "grep -r must print each matching line with its file")
    assert set(run_exit_zero(server, "grep -r -l needle " + tree)) == {a, b}, (
        "grep -r -l must name each file with a match")
    assert set(run_exit_zero(server, "grep -r -c needle " + tree)) == {
        a + ":2", b + ":1", d + ":0"}, "grep -r -c must count every file"
    assert set(run_exit_zero(server, "grep -l -c -r needle " + tree)) == {a, b}, (
        "-l must win over -c")
    assert run_command(server, "grep -r -l absent " + tree) == ["exit 1"], (
        "grep -r with no match must exit 1 and print nothing")
    assert run_exit_zero(server, "grep -c needle " + a) == ["2"], (
        "grep -c of one file must print its count")
    assert run_exit_zero(server, "grep -l needle " + a) == [a], (
        "grep -l of one file must print its name")
    assert run_command(server, "grep -r . " + os.path.join(
        server.root, "data", "ariel")) == ["protected", "exit 87"], (
        "grep -r of Ariel's state directory must answer protected")
    link = os.path.join(tree, "to-token")
    make_link(link, secret_path(server, "token"), hard=False)
    lines = run_command(server, "grep -r -l . " + tree)
    assert lines[-2:] == ["protected", "exit 87"], (
        "grep -r through a link to the token must answer protected, got %r"
        % lines)
    assert server.token not in "\n".join(lines), "the token must not be printed"
    os.unlink(link)


def scenario_grep_dash_pattern(server):
    """-- ends grep's options, -e names its pattern, and a dash word is refused."""
    folder = make_tree(server, "grep-dash", {"f.txt": b"-needle here\nplain\n"})
    f = os.path.join(folder, "f.txt")
    assert run_exit_zero(server, "grep -- -needle " + f) == ["-needle here"], (
        "grep -- must take a pattern that begins with a dash")
    assert run_exit_zero(server, "grep -e -needle " + f) == ["-needle here"], (
        "grep -e must name a pattern that begins with a dash")
    assert run_exit_zero(server, "grep -e plain " + f) == ["plain"], (
        "grep -e must search for the pattern it names")
    assert run_command(server, "grep -x a " + f) == ["bad_option", "exit 1"], (
        "an unknown grep option must answer bad_option")
    assert run_command(server, "grep -e") == ["bad_argument", "exit 1"], (
        "grep -e with no pattern must answer bad_argument")
    assert run_command(server, "grep -- -needle " + f + " x") == [
        "bad_argument", "exit 1"], (
        "grep -- must still take exactly a pattern and a path")


def scenario_find_predicates(server):
    """find -name and -type filter the walk; a bad predicate is refused."""
    tree = make_tree(server, "find-tree", {"a.txt": b"x", "sub/b.txt": b"y"},
                     dirs=("sub/dir",))
    a = os.path.join(tree, "a.txt")
    b = os.path.join(tree, "sub", "b.txt")
    sub = os.path.join(tree, "sub")
    empty = os.path.join(tree, "sub", "dir")
    assert set(run_exit_zero(server, "find %s -name a.txt" % tree)) == {a}, (
        "find -name must print the entry with that name")
    assert set(run_exit_zero(server, "find %s -type d" % tree)) == {
        tree, sub, empty}, "find -type d must print the directories"
    assert set(run_exit_zero(server, "find %s -type f" % tree)) == {a, b}, (
        "find -type f must print the regular files")
    assert set(run_exit_zero(server, "find %s -name '*.txt'" % tree)) == {
        a, b}, "find -name must expand a glob against the name, as bash does"
    assert run_exit_zero(server, "find %s -name '[a].txt'" % tree) == [a], (
        "find -name must accept a bracket expression")
    assert run_exit_zero(server, "find %s -name '*.log'" % tree) == [], (
        "a glob that matches nothing prints nothing and exits 0")
    link = os.path.join(tree, "a-link")
    make_link(link, a, hard=False)
    assert set(run_exit_zero(server, "find %s -type l" % tree)) == {link}, (
        "find -type l must print the symbolic link itself")
    os.unlink(link)
    assert run_command(server, "find %s -name" % tree) == [
        "missing_operand", "exit 1"], "find -name needs a name"
    assert run_command(server, "find %s -type x" % tree) == [
        "bad_argument", "exit 1"], "find -type takes f, d or l"
    assert run_command(server, "find %s -size 3" % tree) == [
        "bad_option", "exit 1"], "a predicate find lacks answers bad_option"
    assert run_command(server, "find /ariel-no-such-path -name a") == [
        "no_such_file", "exit 1"], "find of a missing path must refuse it"
    assert run_command(server, "find relative -name a") == [
        "relative_path", "exit 1"], "find of a relative path must refuse it"


def scenario_rm_recursive_needs_the_owner(server):
    """rm -r asks once for the whole tree, removes it after the signature, and binds -r."""
    tree = make_tree(server, "rm-tree", {"a.txt": b"x", "sub/b.txt": b"y"})
    approval, challenge = gate_request(server, "rm -r " + tree)
    assert os.path.isdir(tree), "an unsigned rm -r must not run"
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=rm\n"), action
    assert "\noption.recursive=1" in action, action
    sign_and_grant(server, approval, challenge)
    assert run_command(server, "rm -r " + tree) == ["exit 0"], (
        "a signed rm -r must run")
    assert stat_exit(server, tree) == "exit 1", "rm -r must remove the tree"


def scenario_rm_recursive_refusals(server):
    """rm -r refuses before the owner is asked, and never touches Ariel's state."""
    assert run_command(server, "rm -r") == ["missing_operand", "exit 1"]
    token = secret_path(server, "token")
    assert run_command(server, "rm -r " + token) == ["protected", "exit 87"], (
        "rm -r of the token must answer protected")
    state = os.path.join(server.root, "data", "ariel")
    assert run_command(server, "rm -r " + state) == ["protected", "exit 87"], (
        "rm -r of the state directory must answer protected")
    tree = make_tree(server, "rm-alias-tree", {"a.txt": b"x"})
    alias = os.path.join(tree, "to-token")
    make_link(alias, token, hard=False)
    assert run_command(server, "rm -r " + tree) == ["protected", "exit 87"], (
        "rm -r through a link to the token must answer protected")
    assert os.path.exists(token), "the token must survive"
    os.unlink(alias)
    make_link(os.path.join(tree, "plain"), os.path.join(tree, "a.txt"), hard=False)
    assert run_command(server, "rm -r " + tree) == ["symbolic_link", "exit 1"], (
        "rm -r over a symbolic link must refuse it before anything is removed")
    assert os.path.exists(os.path.join(tree, "a.txt")), (
        "a refused rm -r must remove nothing")
    server.assert_no_line()


def scenario_cp_recursive(server):
    """cp -r copies a tree after the owner signs, and refuses an existing destination."""
    src = make_tree(server, "cp-src", {"a.txt": TRANSFER_BYTES, "sub/b.txt": b"second\n"})
    dst = os.path.join(server.root, "data", "cp-dst")
    line = "cp -r %s %s" % (src, dst)
    approval, challenge = transfer_request(server, line)
    assert not os.path.lexists(dst), "an unsigned cp -r must not run"
    action = decoded_action(challenge_action(challenge))
    assert action.startswith("ariel-action-v1\ncommand=cp\n"), action
    assert "\noption.recursive=1" in action, action
    sign_and_grant(server, approval, challenge)
    assert run_command(server, line) == ["exit 0"], "a signed cp -r must run"
    assert read_bytes(os.path.join(dst, "a.txt")) == TRANSFER_BYTES, (
        "cp -r must copy the files")
    assert read_bytes(os.path.join(dst, "sub", "b.txt")) == b"second\n", (
        "cp -r must copy the files below a directory")
    assert os.path.isdir(src), "cp -r must leave the source"
    assert run_command(server, line) == ["exists", "exit 1"], (
        "cp -r over an existing destination must refuse it")


def scenario_cp_recursive_refusals(server):
    """cp -r refuses a tree into itself, a link, a protected alias and a bad option."""
    src = make_tree(server, "cp-refuse", {"a.txt": b"x"})
    token = secret_path(server, "token")
    state = os.path.join(server.root, "data", "ariel")
    assert run_command(server, "cp -r %s" % src) == ["missing_operand", "exit 1"]
    assert run_command(server, "cp -x %s %s" % (src, src + "-copy")) == [
        "bad_option", "exit 1"], "cp -x must answer bad_option"
    assert run_command(server, "cp -r %s %s" % (src, os.path.join(src, "inner"))) == [
        "bad_path", "exit 1"], "cp -r into its own tree must be refused"
    linked = make_tree(server, "cp-link", {"a.txt": b"x"})
    make_link(os.path.join(linked, "plain"), os.path.join(linked, "a.txt"), hard=False)
    dst = os.path.join(server.root, "data", "cp-link-dst")
    assert run_command(server, "cp -r %s %s" % (linked, dst)) == [
        "symbolic_link", "exit 1"], "cp -r over a symbolic link must refuse it"
    assert not os.path.lexists(dst), "a refused cp -r must create nothing"
    alias = make_tree(server, "cp-alias", {"a.txt": b"x"})
    make_link(os.path.join(alias, "to-token"), token, hard=False)
    assert run_command(server, "cp -r %s %s" % (alias, dst)) == [
        "protected", "exit 87"], "cp -r through a link to the token must answer protected"
    assert run_command(server, "cp -r %s %s" % (state, dst)) == [
        "protected", "exit 87"], "cp -r of the state directory must answer protected"
    assert run_command(server, "cp -r %s %s" % (src, os.path.join(state, "copy"))) == [
        "protected", "exit 87"], "cp -r into the state directory must answer protected"
    server.assert_no_line()


def scenario_unsupported_options_answer_bad_option(server):
    """An option a command does not take answers bad_option and asks nobody."""
    scratch = write_scratch(server, "bad-option.txt", b"x\n")
    folder = scratch_dir(server)
    data = os.path.join(server.root, "data")
    for command in (
            "cat -x " + scratch, "stat -x " + scratch, "file -x " + scratch,
            "hexdump -x " + scratch, "sha256sum -x " + scratch,
            "cmp -x %s %s" % (scratch, scratch), "df -x " + folder,
            "grep -x a " + scratch, "rm -x " + os.path.join(data, "none"),
            "mkdir -x " + os.path.join(data, "none"),
            "touch -x " + os.path.join(data, "none"),
            "rmdir -x " + os.path.join(data, "none"),
            "cp -x %s %s" % (scratch, data), "mv -x %s %s" % (scratch, data),
            "ln -x %s %s" % (scratch, data),
            "chmod -R 755 " + scratch, "chown -h 0 " + scratch,
            "chgrp -R 0 " + scratch,
            "rm -r -x " + os.path.join(data, "none"),
            "cp -r -x %s %s" % (scratch, data)):
        assert run_command(server, command) == ["bad_option", "exit 1"], (
            "%r must answer bad_option and exit 1" % command)
    server.assert_no_line()


HOST_ROOT_SCENARIOS.update({
    "ls -l shows detail, ls -a adds the hidden entries, and ls -x is bad_option",
    "grep -r searches a tree; -l names files, -c counts, -l wins over -c",
    "grep -- takes a dash-led pattern, -e names it, and -x stays bad_option",
    "find -name and -type filter the walk, and a bad predicate is refused",
    "rm -r asks once for the tree, removes it after the signature, and binds -r",
    "rm -r refuses protected objects and links before anything is removed",
    "cp -r copies a tree after the owner signs, and refuses an existing destination",
    "cp -r refuses a tree into itself, a link, a protected alias and bad_option",
    "an option a command does not take answers bad_option and asks nobody",
})


SCENARIOS = [
    ("missing auth closes with exit 70", scenario_missing_auth, None),
    ("missing auth after 5 s of test clock closes with exit 70",
     scenario_auth_deadline, CLOCK_REASON),
    ("a command line over 4 KiB answers too_many_arguments, and an auth "
     "line over its own limit closes", scenario_line_limit, None),
    ("a quoted path with a space runs, and a quote or backslash is escaped",
     scenario_quoted_path_runs, HOST_ROOT_REASON),
    ("an unbalanced quote answers bad_quoting before anything runs",
     scenario_dangling_quote_is_refused, None),
    ("a command line holds at most 64 tokens",
     scenario_token_count_is_bounded, None),
    ("a target outside printable ASCII answers bad_path and asks nothing",
     scenario_non_printable_gated_target_answers_bad_path, HOST_ROOT_REASON),
    ("a quoted path is escaped in the signed action and decoded by the "
     "signer", scenario_quoted_path_is_escaped_and_signed, CLOCK_REASON),
    ("a command still running at the 60 s deadline answers timed_out",
     scenario_a_slow_command_times_out, CLOCK_REASON),
    ("each command that predates Stage 1 answers a named error word and its "
     "exit", scenario_legacy_commands_name_their_error, None),
    ("a listing over 64 KiB is cut by ls and find with truncated and exit 0",
     scenario_a_large_listing_is_cut, HOST_ROOT_REASON),
    ("a directory under the cap answers its entries with no marker",
     scenario_a_small_listing_keeps_its_shape, HOST_ROOT_REASON),
    ("a file over 64 KiB is cut by cat, and head, tail and wc read it",
     scenario_a_large_file_is_cut, HOST_ROOT_REASON),
    ("a grep with many matches is cut, and --limit cuts it sooner",
     scenario_a_grep_with_many_matches_is_cut, HOST_ROOT_REASON),
    ("a limit of zero shows no line and says how many there are",
     scenario_a_limit_of_zero_shows_nothing, HOST_ROOT_REASON),
    ("date answers the host's wall clock as one UTC line",
     scenario_date_answers_the_wall_clock, HOST_MACHINE_REASON),
    ("du totals each directory's regular files, children before their parent",
     scenario_du_totals_a_tree, HOST_ROOT_REASON),
    ("du over more directories than 64 KiB holds is cut and exits 0",
     scenario_du_is_cut_past_the_cap, HOST_ROOT_REASON),
    ("the host build's dmesg names the platform refusal instead of an empty "
     "success", scenario_dmesg_names_the_platform_refusal, HOST_MACHINE_REASON),
    ("sysinfo aggregates uname, uptime and memory, plainly and as JSON",
     scenario_sysinfo_aggregates_the_machine, HOST_MACHINE_REASON),
    ("wrong token closes with exit 70", scenario_wrong_token, None),
    ("right token and a Stage 1 command outside the set answers "
     "unknown_command", scenario_unknown_command, None),
    ("the agent port opens no system change outside the gate and the "
     "telnet shell stays out of scope",
     scenario_no_system_change_on_agent_port, None),
    ("mkdir, rmdir, touch and rm run only after the owner signs, once each",
     scenario_file_commands_need_the_owner, True),
    ("a file replaced after approval answers approval_stale and exit 78",
     scenario_file_replaced_after_approval_answers_78, HOST_ROOT_REASON),
    ("a command nothing implements asks the owner and then does nothing",
     scenario_unlisted_command_is_gated, True),
    ("writes outside /data, /user and /mnt/usb* answer protected and exit 87 "
     "without asking, and so does Ariel's token",
     scenario_protected_paths_answer_87_without_asking, HOST_ROOT_REASON),
    ("a file command's audit lines reach audit tail",
     scenario_file_commands_are_audited, True),
    ("chmod, chown and chgrp run only after the owner signs, once each, and "
     "are audited", scenario_attribute_commands_need_the_owner, True),
    ("a chmod approved for one mode answers approval_stale for another, and "
     "the signed mode runs", scenario_attribute_mode_is_bound_to_approval, True),
    ("a file replaced after a chmod approval answers approval_stale and keeps "
     "its mode", scenario_attribute_file_replaced_answers_78,
     HOST_ROOT_REASON),
    ("chmod, chown and chgrp answer protected through hard and symbolic links "
     "to a protected object, even when approved",
     scenario_attribute_commands_refuse_protected_aliases, HOST_ROOT_REASON),
    ("bad mode, owner or group and a missing operand answer their word, exit 1, "
     "and are audited", scenario_attribute_operands_are_checked_first, None),
    ("the challenge of a file command names its path, sha256 none and identity",
     scenario_file_action_names_its_facts, True),
    ("cp, mv and ln ask the owner first, run once after the signature, and "
     "ask again", scenario_transfer_commands_need_the_owner, HOST_ROOT_REASON),
    ("a source swapped after approval answers approval_stale and exit 78 for "
     "cp, mv and ln", scenario_transfer_source_swapped_answers_78,
     HOST_ROOT_REASON),
    ("cp, mv and ln refuse an existing destination with exists, without asking",
     scenario_transfer_refuses_existing_destination, HOST_ROOT_REASON),
    ("cp, mv and ln refuse paths outside /data, /user and /mnt/usb* with "
     "protected and exit 87 without asking",
     scenario_transfer_outside_writable_roots_answers_87, None),
    ("cp, mv and ln refuse the token, approval state, nonces and the state "
     "directory through any alias with protected and exit 87",
     scenario_transfer_protected_objects_answer_87, HOST_ROOT_REASON),
    ("a source swapped after approval for a link to the token answers "
     "protected and exit 87, even when approved",
     scenario_transfer_protected_after_approval_answers_87, HOST_ROOT_REASON),
    ("cp, mv and ln audit each action and refusal, and audit tail shows them",
     scenario_transfer_actions_are_audited, HOST_ROOT_REASON),
    ("the challenge of cp names both paths, sha256 none and the source's "
     "identity", scenario_transfer_action_names_its_facts, HOST_ROOT_REASON),
    ("ls -l shows detail, ls -a adds the hidden entries, and ls -x is bad_option",
     scenario_ls_long_and_all, HOST_ROOT_REASON),
    ("grep -r searches a tree; -l names files, -c counts, -l wins over -c",
     scenario_grep_recursive_and_combined, HOST_ROOT_REASON),
    ("grep -- takes a dash-led pattern, -e names it, and -x stays bad_option",
     scenario_grep_dash_pattern, HOST_ROOT_REASON),
    ("find -name and -type filter the walk, and a bad predicate is refused",
     scenario_find_predicates, HOST_ROOT_REASON),
    ("rm -r asks once for the tree, removes it after the signature, and binds -r",
     scenario_rm_recursive_needs_the_owner, HOST_ROOT_REASON),
    ("rm -r refuses protected objects and links before anything is removed",
     scenario_rm_recursive_refusals, HOST_ROOT_REASON),
    ("cp -r copies a tree after the owner signs, and refuses an existing destination",
     scenario_cp_recursive, HOST_ROOT_REASON),
    ("cp -r refuses a tree into itself, a link, a protected alias and bad_option",
     scenario_cp_recursive_refusals, HOST_ROOT_REASON),
    ("an option a command does not take answers bad_option and asks nobody",
     scenario_unsupported_options_answer_bad_option, HOST_ROOT_REASON),
    ("mount, umount, chroot and mknod ask the owner, and once signed answer "
     "not available on this platform",
     scenario_system_commands_need_the_owner, CLOCK_REASON),
    ("a system command with a bad argument answers bad_argument before the "
     "owner is asked",
     scenario_system_command_bad_argument, None),
    ("a system command on Ariel's token or outside the writable roots answers "
     "protected and exit 87 without asking",
     scenario_system_commands_protected_without_asking, HOST_ROOT_REASON),
    ("an object created under a mknod's name after approval answers "
     "approval_stale and exit 78",
     scenario_system_command_stale_answers_78, CLOCK_REASON),
    ("the challenge of mount and mknod names its command, target and options",
     scenario_system_command_names_its_facts, CLOCK_REASON),
    ("a system command's audit lines reach audit tail",
     scenario_system_commands_are_audited, CLOCK_REASON),


    ("unzip -l lists the members at once, and a file that is no zip answers "
     "bad_archive", scenario_unzip_list_runs_at_once, HOST_ROOT_REASON),
    ("unzip asks the owner first, extracts after the signature, and asks again",
     scenario_unzip_extract_needs_the_owner, HOST_ROOT_REASON),
    ("a member with ../ or an absolute path refuses the whole archive with "
     "unsafe_member, asked of no one and written nowhere",
     scenario_unzip_refuses_escaping_members, HOST_ROOT_REASON),
    ("an archive replaced or rewritten after approval answers approval_stale "
     "and exit 78", scenario_unzip_archive_changed_answers_78, HOST_ROOT_REASON),
    ("unzip refuses the token, approval state, nonces and the state directory "
     "through any alias with protected and exit 87, even when approved",
     scenario_unzip_protected_objects_answer_87, HOST_ROOT_REASON),
    ("unzip refuses a destination outside /data, /user and /mnt/usb* with "
     "protected and exit 87 without asking",
     scenario_unzip_outside_writable_roots_answers_87, None),
    ("unzip lists, runs and refusals reach audit tail under their paths",
     scenario_unzip_actions_are_audited, HOST_ROOT_REASON),
    ("a file run by path prints nothing until the owner signs, then runs once",
     scenario_elf_run_needs_the_owner, True),
    ("a run of a file rewritten after approval answers approval_stale and "
     "exit 78", scenario_elf_changed_after_approval_answers_78, True),
    ("a run of a file replaced by another object with the same bytes answers "
     "approval_stale and exit 78", scenario_elf_replaced_answers_78, True),
    ("a bare name found on the PATH is gated as the file it resolves to",
     scenario_elf_on_path_needs_the_owner, True),
    ("a run of a missing path, a directory or a file without execute bits "
     "answers its word and exit 1 without asking",
     scenario_elf_refusals_need_no_owner, HOST_ROOT_REASON),
    ("a run of Ariel's token answers protected and exit 87 without asking",
     scenario_elf_token_refused, HOST_ROOT_REASON),
    ("a run's request, grant, start and status reach audit tail in order",
     scenario_elf_run_is_audited, True),
    ("the challenge of a run names its path, its sha256 and its identity",
     scenario_elf_action_names_its_facts, True),
    ("a run's arguments are part of the signed action, and other arguments "
     "answer approval_stale", scenario_elf_arguments_are_signed, True),
    ("a run with an argument outside printable ASCII answers bad_path, and a "
     "run with too many arguments answers unknown_command, without asking",
     scenario_elf_arguments_the_signer_cannot_show_are_refused, HOST_ROOT_REASON),
    ("a run of a file over 64 MiB answers too_large and exit 1 without asking",
     scenario_elf_too_large_answers_too_large, HOST_ROOT_REASON),
    ("a run never follows a symbolic link, by path or on the PATH, and answers "
     "symbolic_link", scenario_elf_symbolic_link_is_refused, HOST_ROOT_REASON),
    ("pwd and ls <absolute path> run through the agent port",
     scenario_pwd_and_ls, None),
    ("cd on the agent port answers an error: no working directory",
     scenario_cd_is_an_error, False),
    ("each read-only command runs with no approval and exits 0 with its output",
     scenario_read_only_commands, HOST_ROOT_REASON),
    ("a read-only command refuses a relative path",
     scenario_read_only_relative_paths, False),
    ("sha256sum prints the digest openssl dgst -sha256 prints",
     scenario_sha256sum_matches_openssl, HOST_ROOT_REASON),
    ("read answers the file's size and SHA-256, its raw bytes, then exit 0",
     scenario_read_small_file, HOST_ROOT_REASON),
    ("read of a file over the cap returns ranges that reassemble and verify "
     "by the whole file's hash", scenario_read_ranges_over_the_cap,
     HOST_ROOT_REASON),
    ("a cut read from an offset marks the range's length in truncated",
     scenario_read_cut_at_an_offset, HOST_ROOT_REASON),
    ("read past the end answers bad_range and exit 1, and a bad option "
     "answers bad_option", scenario_read_bad_range, HOST_ROOT_REASON),
    ("the token, approval state and nonces answer protected and exit 87 when "
     "read directly", scenario_secrets_read_directly, HOST_ROOT_REASON),
    ("the token, approval state and nonces answer protected and exit 87 "
     "through a symbolic link", scenario_secrets_read_through_symlink,
     HOST_ROOT_REASON),
    ("the token, approval state and nonces answer protected and exit 87 "
     "through a hard link", scenario_secrets_read_through_hard_link,
     HOST_ROOT_REASON),
    ("echo, sleep, sync, id and help run at once on the agent port",
     scenario_inspection_runs_at_once, False),
    ("ps and procstat list Ariel's own process and refuse a missing or "
     "unknown pid", scenario_ps_and_procstat, False),
    ("ls --json answers one object per entry", scenario_ls_json_is_one_object_per_entry, False),
    ("stat --json answers one object and plain stat keeps its line", scenario_stat_json_is_one_object, False),
    ("df --json answers one object and plain df keeps its line", scenario_df_json_is_one_object, False),
    ("find --json answers one object per path", scenario_find_json_is_one_object_per_path, False),
    ("a JSON row longer than a line is shown whole when the answer fits",
     scenario_json_row_longer_than_a_line_is_shown_whole, False),
    ("ls --json over the cap is cut at whole objects",
     scenario_json_listing_over_the_cap_is_cut, False),
    ("ls and find take --limit with --json, in either order, and no other command does",
     scenario_json_limit_is_taken_by_ls_and_find_only, False),
    ("ps --json answers one object per row from a fixed ps", scenario_ps_json_from_a_fixed_ps, False),
    ("table commands without --json print what they printed", scenario_table_plain_output_is_unchanged, False),
    ("table commands answer bad_option with no partial output", scenario_table_bad_option_answers_nothing_else, False),
    ("table commands' JSON failures answer their error word", scenario_table_json_errors_answer_their_word, False),
    ("the table commands' JSON keys are documented", scenario_table_json_keys_are_documented, False),
    ("sysctl reads a kernel parameter, and a sysctl write is refused and "
     "changes nothing", scenario_sysctl_reads_and_refuses_writes, False),
    ("sum and sfoinfo read absolute paths and refuse relative ones",
     scenario_sum_and_sfoinfo_read_absolute_paths, False),
    ("authid answers 'not available on this platform' on the host and "
     "exit 1", scenario_authid_is_not_available_on_the_host, False),
    ("two connections are served at the same time",
     scenario_two_connections, None),
    ("a fifth concurrent connection answers busy and exit 82",
     scenario_connection_limit, None),
    ("a ninth connection answers busy and exit 82 with every refusal slot "
     "taken", scenario_refusal_slots_exhausted, None),
    ("a stalled upload does not block another connection",
     scenario_stalled_upload_does_not_block, CLOCK_REASON),
    ("a truncated upload answers upload_mismatch and exit 81",
     scenario_truncated_upload, None),
    ("bytes past the declared size answer upload_mismatch and exit 81",
     scenario_extra_bytes, None),
    ("a hash mismatch answers upload_mismatch and exit 81",
     scenario_hash_mismatch, None),
    ("a name outside the grammar answers bad_name", scenario_bad_name, None),
    ("a matching push is staged, asks for approval and exits 75",
     scenario_matching_push, None),
    ("an upload in many small fragments arrives intact",
     scenario_fragmented_upload, None),
    ("an ELF containing 0xff bytes arrives intact",
     scenario_elf_with_ff, None),
    ("a denied push is answered on the virtual controller",
     scenario_denied_push, None),
    ("a commit before the decision answers approval_required and exit 75",
     scenario_commit_before_decision, None),
    ("an approved commit answers installed <name> <hash> and exit 0",
     scenario_commit_installed, None),
    ("after a commit, payload list shows the payload with every field",
     scenario_list_after_commit, None),
    ("the state file records a commit, survives a restart and is not "
     "rewritten by listing", scenario_state_survives_restart, None),
    ("a restart reads only the new server's output, even when the old one's "
     "stream closes late", scenario_restart_ignores_the_old_server_stream,
     HOST_RESTART_REASON),
    ("a store written by Stage 1 is migrated on the first start, and a "
     "second start changes nothing", scenario_stage1_store_migrates_once,
     HOST_FILE_REASON),
    ("a state file whose payload lines have eight fields starts and lists "
     "previous=-", scenario_state_without_previous_starts, HOST_FILE_REASON),
    ("a state file in format v1 starts, lists its payloads, and the next save "
     "writes v2", scenario_state_v1_nine_fields_loads_and_saves_as_v2,
     HOST_FILE_REASON),
    ("a build two names share is kept while either still names it",
     scenario_shared_build_survives_a_replacement, None),
    ("a second commit of the same name replaces the first build",
     scenario_commit_replaces, None),
    ("an approval does not survive a restart of Ariel",
     scenario_commit_after_restart, None),
    ("a staging object changed after approval answers approval_stale and "
     "exit 78", scenario_commit_stale, None),
    ("an approval is single-use when two commits race",
     scenario_commit_single_use, None),
    ("a denied commit answers approval_denied and exit 77 and deletes the "
     "staging object", scenario_commit_denied, None),
    ("a run streams the payload's output, then status 0 and exit 0",
     scenario_run_streams_output, None),
    ("a payload exiting 3 answers status 3, and one exiting 75 answers "
     "status 75, never an approval request",
     scenario_run_reports_payload_status, None),
    ("an unknown payload name is an error", scenario_run_unknown_name, None),
    ("an object changed behind Ariel's back answers approval_stale and "
     "exit 78 and does not run", scenario_run_stale_object, None),
    ("a FIFO in place of a committed object answers approval_stale and "
     "exit 78 without blocking other clients",
     scenario_run_fifo_object, None),
    ("a run of a committed build needs no new approval, and a push of a "
     "different build asks again", scenario_run_needs_no_new_approval, None),
    ("a stored object that cannot be executed answers spawn_failed and "
     "exit 1", scenario_run_exec_failure, None),
    ("a finished connection reaches end of stream while a payload runs",
     scenario_run_does_not_leak_connections, None),
    ("the quick start's 'After Stage 1' section passes headless",
     scenario_quick_start, None),
    ("a change to the 'After Stage 1' section without a change to Ariel "
     "makes the fixture fail", scenario_quick_start_doc_drift, None),
    ("a broken setup command or a wrong exported token makes the fixture "
     "fail", scenario_quick_start_broken_setup, None),
    ("a failing '$' command in a block of any label makes the fixture fail",
     scenario_quick_start_unlabeled_block, None),
    ("an approval expires after 120 s of test clock and answers exit 88",
     scenario_approval_expired, CLOCK_REASON),
    ("approval status answers pending, granted, denied, expired and consumed, "
     "and an unknown id is an error", scenario_approval_status, CLOCK_REASON),
    ("a full approval table gives up an approval with no staged object first, "
     "and an expired staged object still answers approval_expired",
     scenario_approval_slot_reclaim, CLOCK_REASON),
    ("the challenge names the command, target, hash, size and run of the "
     "approval", scenario_challenge_fields, CLOCK_REASON),
    ("an expired approval does not count among the pending ones",
     scenario_expired_not_pending, CLOCK_REASON),
    ("an upload over 64 MiB answers staging_full and exit 80",
     scenario_upload_too_large, None),
    ("staging past 64 MiB in total answers staging_full",
     scenario_staging_total, None),
    ("an unanswered staging object disappears after 15 min",
     scenario_staging_ttl, CLOCK_REASON),
    ("a fourth pending approval answers approval_busy and exit 76 with no "
     "prompt", scenario_pending_limit, None),
    ("a second notification within 10 s answers approval_busy with no "
     "prompt", scenario_notification_rate, CLOCK_REASON),
    ("the test clock is host-only and cannot enter the PS5 build",
     scenario_test_clock_host_only, CLOCK_REASON),
    ("the virtual controller is host-only and cannot enter the PS5 build",
     scenario_vcontroller_host_only, None),
    ("a valid signature decides the approval and the gated command runs "
     "once", scenario_signature_loop, CLOCK_REASON),
    ("a forged signature answers signature_invalid and runs nothing",
     scenario_signature_forged, CLOCK_REASON),
    ("a signature for a different command, target or hash answers "
     "signature_action_mismatch", scenario_signature_wrong_action, CLOCK_REASON),
    ("a signature for another console answers signature_console_mismatch",
     scenario_signature_wrong_console, CLOCK_REASON),
    ("the signer refuses an action with bytes it cannot show",
     scenario_signer_refuses_hidden_bytes, CLOCK_REASON),
    ("a signature after the challenge expired answers approval_expired and "
     "exit 88", scenario_signature_expired, CLOCK_REASON),
    ("a malformed signature answers signature_malformed and exit 83",
     scenario_signature_malformed, CLOCK_REASON),
    ("the same signature twice is refused the second time",
     scenario_signature_twice, CLOCK_REASON),
    ("a consumed nonce is refused after Ariel restarts",
     scenario_signature_replay_after_restart, CLOCK_REASON),
    ("ADR-0009 defines the key hierarchy and the index lists it",
     scenario_adr_names_the_key_hierarchy, False),
    ("key rotate accepts only the current primary and refuses the recovery "
     "key's signature", scenario_key_rotate_needs_current_primary, CLOCK_REASON),
    ("key rotate refuses a recovery-key target and malformed keys before "
     "asking the owner", scenario_key_rotate_refuses_bad_targets, False),
    (RECOVERY_SIGNED_TITLE, scenario_key_rotate_recovery_needs_current_recovery,
     CLOCK_REASON),
    (RECOVERY_TARGETS_TITLE, scenario_key_rotate_recovery_refuses_bad_targets,
     False),
    (RECOVERY_RETIRED_TITLE, scenario_key_rotate_recovery_refuses_retired_recovery,
     CLOCK_REASON),
    (ROTATE_CRASH_TITLE, scenario_key_rotate_crash_leaves_one_keyring,
     FAULT_REASON),
    (RECOVERY_CRASH_TITLE, scenario_key_rotate_recovery_crash_leaves_one_keyring,
     FAULT_REASON),
    (ADR_RECOVERY_TITLE, scenario_adr_names_recovery_rotation_and_crash_steps,
     False),
    ("key rotate refuses a retired primary's signature",
     scenario_key_rotate_refuses_retired_primary, CLOCK_REASON),
    ("a signature over another generation's message is refused",
     scenario_signature_from_another_generation_is_refused, CLOCK_REASON),
    ("a challenge issued before a rotation stops verifying after it",
     scenario_pending_approval_stops_after_rotation, CLOCK_REASON),
    ("a nonce consumed before a rotation stays consumed after a restart",
     scenario_consumed_nonce_survives_rotation_restart, CLOCK_REASON),
    ("key rotate refuses a retired primary and the current primary, also "
     "after a restart", scenario_key_rotate_refuses_revoked_keys, CLOCK_REASON),
    ("an unused approval granted under a retired primary answers "
     "approval_stale", scenario_unused_approval_stops_after_rotation,
     CLOCK_REASON),
    (KEYRING_MISSING_TITLE, scenario_keyring_missing_refuses_approvals,
     CLOCK_REASON),
    (KEYRING_CORRUPT_TITLE, scenario_keyring_corrupt_refuses_approvals,
     CLOCK_REASON),
    (KEYRING_OLDER_TITLE, scenario_keyring_older_than_state_refuses_approvals,
     CLOCK_REASON),
    (REVIVE_TITLE, scenario_recovery_then_corrupt_keyring_never_revives_recovery,
     CLOCK_REASON),
    (ANCHOR_MISMATCH_TITLE, scenario_anchor_mismatch_refuses_until_adopted,
     CLOCK_REASON),
    (ADOPT_SIGNER_TITLE, scenario_adopt_anchor_needs_the_new_recovery_key,
     CLOCK_REASON),
    (ADOPT_AUDIT_TITLE, scenario_adopt_anchor_keeps_nonces_and_audit,
     CLOCK_REASON),
    (ADOPT_MATCH_TITLE, scenario_adopt_anchor_refused_when_anchor_matches,
     False),
    ("the PS5 makefile refuses an owner key pinned without its recovery key",
     scenario_ps5_pubkey_needs_recovery, None),
    ("the README and the quick start document ARIEL_RECOVERY_PUBKEY",
     scenario_recovery_pubkey_is_documented, None),
    ("the PS5 admission rule refuses the host test key as a new primary",
     scenario_ps5_refuses_test_key_as_primary, None),
    ("the keyring is a protected object", scenario_keyring_is_protected,
     HOST_ROOT_REASON),
    ("kill with a bad signal, a bad pid or no such process answers an "
     "error and exit 1, and a wrong arity is gated", scenario_kill_bad_arguments, False),
    ("kill of the critical process answers protected and exit 87 and asks "
     "no approval", scenario_kill_critical_refused, False),
    ("kill of Ariel's own process answers protected and exit 87",
     scenario_kill_own_process_refused, HOST_FIXTURE_REASON),
    ("kill asks for approval, and a grant runs it once and audits the request, "
     "grant and kill", scenario_kill_needs_grant_and_runs_once, True),
    ("a restarted process under the same pid answers approval_stale and exit "
     "78 and is not signalled", scenario_kill_stale_after_restart, True),
    ("a kill signal or start changed in the challenge answers "
     "signature_action_mismatch, and the real grant still runs it",
     scenario_kill_retarget_refused, True),
    ("env asks for approval, and a grant reveals the one variable it names",
     scenario_env_needs_grant_and_reveals, True),
    ("export asks for approval, and a grant sets the variable it names",
     scenario_export_needs_grant_and_sets, True),
    ("an export whose value changed after approval answers approval_stale and "
     "exit 78", scenario_export_changed_value_is_stale, True),
    ("exec asks for approval of the program's bytes and arguments, and a grant "
     "runs it once", scenario_exec_needs_grant_and_runs_once, True),
    ("exec with other arguments after approval answers approval_stale and "
     "exit 78", scenario_exec_args_are_bound, True),
    ("exec of a program replaced after approval answers approval_stale and "
     "exit 78", scenario_exec_replaced_is_stale, True),
    ("env, export and exec refuse a bad name, a relative or missing path and "
     "the token without asking, and audit each refusal",
     scenario_env_export_exec_refusals, False),
    ("each gated built-in answers 75 and its challenge before anything runs",
     scenario_builtins_ask_before_they_run, HOST_ROOT_REASON),
    ("a granted built-in on the host answers not available once and audits "
     "the grant and the run", scenario_builtin_grant_runs_once_on_host, True),
    ("a built-in run with another argument answers approval_stale and exit 78",
     scenario_builtin_arguments_are_bound, True),
    ("a built-in with a missing operand, a relative path or a bad value "
     "answers without asking", scenario_builtin_bad_arguments_are_refused_without_asking,
     False),
    ("a built-in's challenge names each argument after the target, in order",
     scenario_builtin_arguments_are_named_in_order, HOST_ROOT_REASON),
    ("a built-in that names Ariel's token answers protected and asks nothing",
     scenario_builtin_protected_is_refused_without_asking, HOST_ROOT_REASON),
    ("reptyr of a restarted process answers approval_stale and exit 78 and "
     "touches nothing", scenario_reptyr_restarted_process_is_stale,
     HOST_FIXTURE_REASON),
    ("reptyr of a critical process answers protected and exit 87 and asks "
     "no approval", scenario_reptyr_critical_is_refused, False),
    ("a file replaced after a built-in grant answers approval_stale and exit 78",
     scenario_builtin_file_replaced_is_stale, HOST_ROOT_REASON),
    ("the PS5 build rejects the host test key",
     scenario_ps5_rejects_test_key, None),
    ("the PS5 platform no longer reads the controller",
     scenario_ps5_has_no_pad, None),
    ("one function builds the canonical action text",
     scenario_one_canonical_function, None),
    ("the canonical encoder refuses ambiguous inputs",
     scenario_canonical_encoder, None),
    ("after a push, a grant and a commit, audit tail shows each one in order",
     scenario_audit_tail_order, None),
    ("audit tail is read-only", scenario_audit_tail_readonly, None),
    ("no agent-port command can clear or rewrite the audit log",
     scenario_audit_log_not_rewritable, None),
    ("a long audit line is dropped whole, never shown in pieces",
     scenario_audit_tail_drops_long_lines, None),
    ("a push the audit log cannot record is refused and stages nothing",
     scenario_failed_audit_append_is_refused, None),
    ("a grant or commit the audit log cannot record answers audit_failed",
     scenario_failed_audit_append_after_the_action, False),
    ("a background run answers a pid at once, and logs of a one-shot show "
     "its output after it exits", scenario_background_run_returns_pid, False),
    ("logs of a one-shot payload started in the background show its full "
     "output", scenario_background_logs_one_shot, False),
    ("a hung background payload is listed as running, then cut at its "
     "timeout and listed as not running",
     scenario_background_hung_payload_is_cut, True),
    ("a background run refuses an unknown, never-run or running payload and "
     "a bad name, and audits each refusal", scenario_background_run_refusals,
     False),
    ("console mode with PS5_HOST set names the console scenarios and every "
     "scenario that needs the test clock", scenario_console_mode_plan, None),
    ("console mode prints what the owner should see on the console and "
     "waits for the owner's signature",
     scenario_console_approval_prompts, None),
    ("console mode runs its checks over an injected transport",
     scenario_console_run_reaches_checks, None),
    ("console mode's quick start waits out the notification gap before its "
     "push", scenario_console_quick_start_waits_for_the_gap, None),
    ("console mode activates only builds the console can run",
     scenario_console_checks_push_runnable_builds, None),
    ("console mode's reboot and sysctl write wait out approval_busy",
     scenario_console_gated_asks_wait_out_busy, None),
    ("console mode's stale autoload check installs both names before it asks",
     scenario_console_stale_check_installs_both_names, None),
    ("console mode's audit check allows appended lines and refuses a removed "
     "one", scenario_console_audit_check_allows_appended_lines, None),
    ("console mode's cp -r and rm -r check lists the copy and removes both "
     "throwaway paths, pass or fail", scenario_console_recursive_copy_check_cleans_up,
     None),
    ("console mode's read check matches cat and the header's size and hash",
     scenario_console_read_check_matches_cat, None),
    ("a crash in prepared leaves the old version in payload list after restart",
     scenario_crash_in_prepared_leaves_old_version, FAULT_REASON),
    ("a crash in committed leaves the new version in payload list after restart",
     scenario_crash_in_committed_leaves_new_version, FAULT_REASON),
    ("a committed change whose new object is gone is refused at start and "
     "audited, and the state file is left as it was",
     scenario_committed_journal_without_its_object_is_refused, FAULT_REASON),
    ("a recovery killed after its renames, then a clean start, leaves the "
     "listing, state file and audit of one crash",
     scenario_recovery_crash_matches_one_crash, FAULT_REASON),
    ("the previous version is kept and listed, and the one before it is dropped",
     scenario_previous_version_is_kept_then_dropped, None),
    ("payload rollback answers 75 with its challenge, then restores the "
     "previous version after a grant",
     scenario_rollback_restores_the_previous_version, None),
    ("payload rollback with no previous version answers no_previous_version, "
     "an unknown name unknown_payload, both with exit 1 and no prompt",
     scenario_rollback_without_previous_version_answers_error, None),
    ("a rollback whose store moved on after the grant answers approval_stale "
     "and exit 78",
     scenario_rollback_refused_when_the_store_moved_on, None),
    ("a denied rollback answers approval_denied and exit 77 and changes nothing",
     scenario_rollback_denied_answers_77, None),
    ("rollbacks that end, and requests left to expire, free their approval "
     "rows, so a push still asks for approval",
     scenario_rollbacks_give_their_approval_rows_back, CLOCK_REASON),
    ("a rollback whose record the store cannot read answers rollback_failed "
     "and keeps the grant",
     scenario_unreadable_record_answers_rollback_failed, HOST_FILE_REASON),
    ("a crash in prepared during a rollback leaves the newer build current "
     "after restart",
     scenario_crash_in_prepared_rolls_back_the_rollback, FAULT_REASON),
    ("a crash in committed during a rollback leaves the previous build current "
     "after restart",
     scenario_crash_in_committed_rolls_forward_the_rollback, FAULT_REASON),
    ("a payload the record marks running is not started again on restart",
     scenario_running_mark_does_not_restart_payload, None),
    ("autoload show lists the boot entries, Ariel first, and writes nothing",
     scenario_autoload_show_lists_entries, None),
    ("autoload edit without a grant answers 75 and leaves the list as it was",
     scenario_autoload_edit_asks_before_it_applies, None),
    ("a granted autoload add is applied, shown by autoload show and audited",
     scenario_autoload_edit_applies_after_grant, None),
    ("autoload edit remove ariel is refused with ariel_pinned and audited",
     scenario_autoload_pins_ariel, None),
    ("autoload refuses an unknown payload, a present entry and an absent one",
     scenario_autoload_refusals_answer_their_words, None),
    ("a stale autoload grant answers approval_stale, 78, and leaves the list "
     "as it was", scenario_autoload_stale_grant_answers_78, None),
    ("a crash in prepared of an autoload edit leaves the old list after restart",
     scenario_crash_in_autoload_prepared_keeps_old_list, FAULT_REASON),
    ("a crash in committed of an autoload edit leaves the new list after restart",
     scenario_crash_in_autoload_committed_keeps_new_list, FAULT_REASON),
    ("a journal written as v1 before autoload existed rolls a committed change "
     "forward after restart", scenario_v1_journal_rolls_forward, FAULT_REASON),
    ("a journal written as v1 before autoload existed rolls a prepared change "
     "back after restart", scenario_v1_journal_rolls_back, FAULT_REASON),
    ("a committed autoload edit whose list file is gone rolls forward at the "
     "next start", scenario_committed_autoload_without_its_file_rolls_forward,
     FAULT_REASON),
    ("an autoload edit refused as busy answers approval_busy and is audited",
     scenario_autoload_busy_is_audited, CLOCK_REASON),
    ("an autoload edit whose audit line fails after the rename answers "
     "audit_failed and stays applied",
     scenario_autoload_audit_failure_after_rename_stays_applied, CLOCK_REASON),
    ("tar with a bad shape, a relative or protected path, or a missing archive "
     "answers at once and asks nothing", scenario_tar_refusals_need_no_approval,
     None),
    ("tar -t lists every member name in archive order at once, and a non-tar "
     "answers not_a_tar", scenario_tar_lists_members_at_once, HOST_ROOT_REASON),
    ("tar -x answers 75 with a challenge naming its facts, extracts after the "
     "grant, and never overwrites", scenario_tar_extract_needs_the_owner,
     CLOCK_REASON),
    ("a member or link that escapes the destination is refused at once, and "
     "nothing is written", scenario_tar_refuses_escaping_members,
     HOST_ROOT_REASON),
    ("an archive replaced after the owner signs answers approval_stale and "
     "writes nothing", scenario_tar_archive_changed_after_grant_answers_78,
     CLOCK_REASON),
    ("tar refuses Ariel's own objects, and a member that names one, through "
     "any alias, without asking", scenario_tar_protected_objects_answer_87,
     HOST_ROOT_REASON),
    ("an archive swapped for a link to Ariel's token after the owner signs "
     "runs nothing", scenario_tar_protected_after_grant_answers_87, CLOCK_REASON),
    ("tar listings, runs and refusals reach audit tail under their paths",
     scenario_tar_actions_are_audited, CLOCK_REASON),
    ("reboot answers 75 with a challenge that names the boot list",
     scenario_reboot_asks_the_owner, None),
    ("a granted reboot restarts Ariel, keeps payloads listed and runs the "
     "autoload entries", scenario_reboot_granted_restarts_and_runs_autoload,
     HOST_RESTART_REASON),
    ("a crash restart runs no autoload entry and restarts nothing that was "
     "running", scenario_crash_restart_runs_no_autoload, HOST_RESTART_REASON),
    ("a reboot granted for a changed boot list answers approval_stale, 78, "
     "and does not restart", scenario_reboot_stale_list_answers_78, None),
    ("a reboot the owner denies answers approval_denied, 77, and does not "
     "restart", scenario_reboot_denied_answers_77, None),
    ("a signature for another action than reboot answers "
     "signature_action_mismatch and does not restart",
     scenario_reboot_signature_wrong_action, None),
    ("a granted reboot is audited as its request, grant and done",
     scenario_reboot_is_audited, HOST_RESTART_REASON),


    ("a one-shot that exits nonzero after commit is replaced by the previous "
     "version, and that version runs",
     scenario_failing_one_shot_is_replaced_by_previous, None),
    ("a one-shot past its timeout fails, and with no previous version it is "
     "marked failed", scenario_one_shot_past_its_timeout_fails, CLOCK_REASON),
    ("a failed one-shot with no previous version is removed from autoload",
     scenario_failed_one_shot_leaves_autoload, CLOCK_REASON),
    ("a health check whose log cannot be opened fails and is audited as "
     "health.fail", scenario_health_log_unopenable_fails_and_is_audited,
     HOST_ROOT_REASON),
    ("payload config refuses a timeout over one hour before it asks",
     scenario_config_refuses_a_timeout_over_an_hour, None),
    ("an ad-hoc payload run starts no health check",
     scenario_ad_hoc_run_starts_no_health_check, None),
    ("a healthy one-shot's output is in payload logs, never in the reply",
     scenario_health_output_stays_in_the_log, None),
    ("payload config is gated, applied after a grant and audited, and refuses "
     "unknown payloads, other kinds and a zero timeout",
     scenario_payload_config_is_gated_and_audited, CLOCK_REASON),
    ("a rollback whose restored build fails its health check is replaced by "
     "the build it rolled back from",
     scenario_failed_rollback_restores_the_build_it_replaced, CLOCK_REASON),
    ("autoload safe-boot answers 75 with a challenge that names the boot list "
     "it skips, and a denial answers 77",
     scenario_safe_boot_asks_the_owner, None),
    ("a granted autoload safe-boot skips autoload on the next boot only",
     scenario_safe_boot_skips_autoload_for_one_boot, HOST_RESTART_REASON),
    ("autoload safe-boot granted for a changed boot list answers "
     "approval_stale, 78, and changes nothing",
     scenario_safe_boot_stale_answers_78, None),
    ("a second autoload safe-boot while one is pending answers "
     "safe_boot_pending, exit 1, and asks nothing",
     scenario_safe_boot_refused_while_pending, HOST_RESTART_REASON),
]

BOUNDED_READER_TITLES = {
    "a listing over 64 KiB is cut by ls and find with truncated and exit 0",
    "a directory under the cap answers its entries with no marker",
    "a file over 64 KiB is cut by cat, and head, tail and wc read it",
    "a grep with many matches is cut, and --limit cuts it sooner",
    "a limit of zero shows no line and says how many there are",
}
HOST_ROOT_SCENARIOS.update(BOUNDED_READER_TITLES)
HOST_ROOT_SCENARIOS.update({
    "du totals each directory's regular files, children before their parent",
    "du over more directories than 64 KiB holds is cut and exits 0",
})

HOST_MACHINE_SCENARIOS = {
    "date answers the host's wall clock as one UTC line",
    "the host build's dmesg names the platform refusal instead of an empty "
    "success",
    "sysinfo aggregates uname, uptime and memory, plainly and as JSON",
}


# Payload install from an allowlisted release (SPEC 2, #42). The fake release
# server stands in for the release API and its CDN; the allowlist it needs is
# test data, written into the state directory before Ariel starts.

INSTALL_REPO = "owner/app"
INSTALL_ASSET = "app.elf"
INSTALL_NAME = "fetched"
INSTALL_TAG = "v1"
RELEASE_ID = 7
ASSET_ID = 11
CDN_SUFFIX = "localhost"


class FakeRelease:
    """A local release API and CDN, with one release per tag.

    The first release added is the default; add_release(latest=True) moves
    the latest pointer. Adding a tag again moves that tag to the new release.
    mode picks how the asset download misbehaves.

    ok: the asset redirects once to the CDN host and is served there.
    off_cdn: the redirect goes to a host outside the CDN suffix.
    second_hop: the CDN answers with a further redirect.
    fail: the asset request answers 500.
    """

    def __init__(self, data, mode="ok", url_id=ASSET_ID, asset_id=ASSET_ID):
        self.mode = mode
        self.requests = []
        self.tags = {}
        self.blobs = {}
        self.latest = None
        self.add_release(INSTALL_TAG, RELEASE_ID, asset_id, url_id, data,
                         latest=True)
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body=b"", location=None):
                self.send_response(status)
                if location is not None:
                    self.send_header("Location", location)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def reply_release(self, release):
                body = json.dumps(fake.release_json(release)).encode("ascii")
                return self.reply(200, body)

            def do_GET(self):
                fake.requests.append(self.path)
                cdn = "http://%s:%d" % (CDN_SUFFIX, fake.port)
                if self.path == "/repos/%s/releases/latest" % INSTALL_REPO:
                    return self.reply_release(fake.tags[fake.latest])
                tag_prefix = "/repos/%s/releases/tags/" % INSTALL_REPO
                if self.path.startswith(tag_prefix):
                    release = fake.tags.get(self.path[len(tag_prefix):])
                    if release is None:
                        return self.reply(404)
                    return self.reply_release(release)
                asset = re.fullmatch(r"/(assets|hop|cdn)/(\d+)", self.path)
                if asset is None or int(asset.group(2)) not in fake.blobs:
                    return self.reply(404)
                kind, url_id = asset.group(1), int(asset.group(2))
                if kind == "cdn":
                    return self.reply(200, fake.blobs[url_id])
                if kind == "hop":
                    return self.reply(302, location="%s/cdn/%d" % (cdn, url_id))
                if fake.mode == "fail":
                    return self.reply(500)
                if fake.mode == "off_cdn":
                    return self.reply(302, location="http://127.0.0.1:%d/cdn/%d"
                                      % (fake.port, url_id))
                if fake.mode == "second_hop":
                    return self.reply(302, location="%s/hop/%d" % (cdn, url_id))
                return self.reply(302, location="%s/cdn/%d" % (cdn, url_id))

        self.httpd = http.server.ThreadingHTTPServer((HOST, 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def add_release(self, tag, release_id, asset_id, url_id, data,
                    tag_name=None, latest=False):
        """Name the release a tag resolves to; tag_name overrides what it answers."""
        self.tags[tag] = {
            "id": release_id,
            "tag_name": tag_name or tag,
            "asset_id": asset_id,
            "url_id": url_id,
            "data": data,
        }
        self.blobs[url_id] = data
        if latest or self.latest is None:
            self.latest = tag

    def release_json(self, release):
        return {
            "id": release["id"],
            "tag_name": release["tag_name"],
            "assets": [{
                "id": release["asset_id"],
                "name": INSTALL_ASSET,
                "size": len(release["data"]),
                "url": "http://%s:%d/assets/%d" % (HOST, self.port,
                                                   release["url_id"]),
            }],
        }

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class InstallFixture:
    """A fresh Ariel whose allowlist names the fake release server.

    allowlist=None writes no allowlist at all. pin, when given, and each
    (name, sha256) pair in pins, is a hash the allowlist pins.
    """

    def __init__(self, data, mode="ok", url_id=ASSET_ID, asset_id=ASSET_ID,
                 allowlist="default", pin=None, pins=()):
        self.fake = FakeRelease(data, mode=mode, url_id=url_id, asset_id=asset_id)
        if allowlist == "default":
            lines = ["host %s:%d" % (HOST, self.fake.port),
                     "cdn %s" % CDN_SUFFIX,
                     "repo %s" % INSTALL_REPO]
            for pair in ([pin] if pin is not None else []) + list(pins):
                lines.append("pin %s %s" % pair)
            allowlist = "\n".join(lines) + "\n"
        self.allowlist = allowlist
        self.server = Server(SERVER_BINARY, setup=self._setup)

    def _setup(self, root):
        state = os.path.join(root, "data", "ariel")
        os.makedirs(state, exist_ok=True)
        if self.allowlist is not None:
            with open(os.path.join(state, "allowlist"), "w") as fh:
                fh.write(self.allowlist)

    def allowlist_path(self):
        return os.path.join(self.server.root, "data", "ariel", "allowlist")

    def close(self):
        self.server.stop()
        self.fake.stop()


def install_request(server, name, repo=INSTALL_REPO, asset=INSTALL_ASSET, tag=None):
    """Send one payload install and return the lines the server answered."""
    command = "payload install %s %s %s" % (name, repo, asset)
    if tag is not None:
        command += " " + tag
    server.advance(10_000)
    return send_command(server, command)


def with_install(data, scenario, **kwargs):
    fixture = InstallFixture(data, **kwargs)
    try:
        return scenario(fixture)
    finally:
        fixture.close()


def scenario_install_refused_outside_the_allowlist_host(_server):
    """A host the allowlist does not name is refused before anything is fetched."""
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["not_allowlisted", "exit 1"], lines
        assert fx.fake.requests == [], "no request may leave for a refused host"
    with_install(healthy_build(INSTALL_NAME), run,
                 allowlist="cdn %s\nrepo %s\n" % (CDN_SUFFIX, INSTALL_REPO))


def scenario_install_refused_without_allowlist(_server):
    """An install with no allowlist at all is refused."""
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["not_allowlisted", "exit 1"], lines
    with_install(healthy_build(INSTALL_NAME), run, allowlist=None)


def scenario_install_refused_outside_the_allowlist_repository(_server):
    """A repository the allowlist does not name is refused, even on a listed host."""
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME, repo="owner/other")
        assert lines == ["not_allowlisted", "exit 1"], lines
        assert fx.fake.requests == [], "no request may leave for a refused repository"
    with_install(healthy_build(INSTALL_NAME), run)


def scenario_install_failed_download_is_refused(_server):
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["download_failed", "exit 1"], lines
    with_install(healthy_build(INSTALL_NAME), run, mode="fail")


def scenario_install_redirect_off_the_cdn_is_refused(_server):
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["redirect_refused", "exit 1"], lines
    with_install(healthy_build(INSTALL_NAME), run, mode="off_cdn")


def scenario_install_second_redirect_hop_is_refused(_server):
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["second_redirect", "exit 1"], lines
    with_install(healthy_build(INSTALL_NAME), run, mode="second_hop")


def scenario_install_asset_id_mismatch_is_refused(_server):
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["asset_mismatch", "exit 1"], lines
    with_install(healthy_build(INSTALL_NAME), run, url_id=ASSET_ID + 1)


def scenario_install_pinned_hash_installs_and_joins_autoload(_server):
    data = healthy_build(INSTALL_NAME)
    digest = hashlib.sha256(data).hexdigest()

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["installed %s %s" % (INSTALL_NAME, digest), "exit 0"], lines
        listing = listed(payload_list(fx.server), INSTALL_NAME)
        assert listing == (
            "payload %s source=release version=%s release=%d asset=%d "
            "sha256=%s path=/data/ariel/store/objects/%s running=no "
            "failed=no previous=-" % (INSTALL_NAME, INSTALL_TAG, RELEASE_ID,
                                      ASSET_ID, digest, digest)), listing
        assert "autoload %s" % INSTALL_NAME in autoload_listing(fx.server), (
            "install must join autoload")
    with_install(data, run, pin=(INSTALL_NAME, digest))


def scenario_install_different_hash_is_refused_and_nothing_kept(_server):
    data = healthy_build(INSTALL_NAME)

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["hash_mismatch", "exit 1"], lines
        assert listed(payload_list(fx.server), INSTALL_NAME) is None, (
            "a refused hash must not be recorded")
        assert "autoload %s" % INSTALL_NAME not in autoload_listing(fx.server), (
            "a refused hash must not join autoload")
    with_install(data, run, pin=(INSTALL_NAME, "0" * 64))


def scenario_install_runs_the_health_check(_server):
    data = compile_payload(EXIT_SOURCE.replace("EXIT_CODE", "1"), "broken")
    digest = hashlib.sha256(data).hexdigest()

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["health_failed %s %s" % (INSTALL_NAME, digest), "exit 1"], lines
        listing = listed(payload_list(fx.server), INSTALL_NAME)
        assert listing is not None and "failed=yes" in listing, listing
        assert "autoload %s" % INSTALL_NAME not in autoload_listing(fx.server), (
            "a failed install must leave autoload")
    with_install(data, run, pin=(INSTALL_NAME, digest))


def scenario_ariel_never_installs_itself(_server):
    def run(fx):
        lines = install_request(fx.server, "ariel")
        assert lines == ["protected", "exit 87"], lines
        assert fx.fake.requests == [], "Ariel's own install must not fetch anything"
    with_install(healthy_build("ariel"), run)


def scenario_unpinned_install_asks_then_commit_pins_and_joins(_server):
    data = healthy_build(INSTALL_NAME)
    digest = hashlib.sha256(data).hexdigest()

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        staging, approval = assert_staged(fx.server, lines, INSTALL_NAME, data)
        sign_and_grant(fx.server, approval, challenge_of(lines))
        assert commit(fx.server, staging) == [
            "installed %s %s" % (INSTALL_NAME, digest), "exit 0"], (
            "an approved install must commit the build")
        with open(fx.allowlist_path()) as fh:
            assert "pin %s %s" % (INSTALL_NAME, digest) in fh.read().splitlines(), (
                "a committed install must pin its hash")
        assert "autoload %s" % INSTALL_NAME in autoload_listing(fx.server), (
            "install must join autoload")
    with_install(data, run, allowlist="default")


def scenario_protected_allowlist_answers_87_even_when_asked(_server):
    def run(fx):
        path = fx.allowlist_path()
        spare = os.path.join(fx.server.root, "data", "ariel", "spare")
        commands = [
            "cat " + path,
            "rm " + path,
            "mv " + path + " " + spare,
            "cp " + path + " " + spare,
            "chmod 600 " + path,
            "ln " + path + " " + spare,
        ]
        for command in commands:
            assert run_command(fx.server, command) == ["protected", "exit 87"], (
                "%s must answer protected and exit 87" % command)
        fx.server.assert_no_line()
        assert os.path.exists(path), "the allowlist must survive"
    with_install(healthy_build(INSTALL_NAME), run, pin=(INSTALL_NAME, "0" * 64))


def scenario_install_actions_reach_audit_tail(_server):
    data = healthy_build(INSTALL_NAME)
    digest = hashlib.sha256(data).hexdigest()

    def run(fx):
        install_request(fx.server, INSTALL_NAME, repo="owner/other")
        install_request(fx.server, INSTALL_NAME)
        events = audit_events(fx.server)
        kinds = [event[0] for event in events]
        assert "payload.install.refused" in kinds, kinds
        assert "payload.install.done" in kinds, kinds
    with_install(data, run, pin=(INSTALL_NAME, digest))


NEWEST_TAG = "v2"
NEWEST_RELEASE_ID = 8
NEWEST_ASSET_ID = 12
MOVED_RELEASE_ID = 9
MOVED_ASSET_ID = 13


def release_listing(name, tag, release, asset, digest):
    return ("payload %s source=release version=%s release=%d asset=%d "
            "sha256=%s path=/data/ariel/store/objects/%s running=no "
            "failed=no previous=-" % (name, tag, release, asset, digest, digest))


def install_audit(server):
    """The install actions and refusals in audit tail as (kind, name, id)."""
    return [event[:3] for event in audit_events(server)
            if event[0].startswith("payload.install.")]


def scenario_install_latest_and_pinned_tag_record_their_ids(_server):
    """Latest and a pinned tag each install the release and asset they name."""
    pinned = healthy_build("pinned-tag")
    newest = healthy_build("newest-release")
    pinned_digest = hashlib.sha256(pinned).hexdigest()
    newest_digest = hashlib.sha256(newest).hexdigest()

    def run(fx):
        fx.fake.add_release(NEWEST_TAG, NEWEST_RELEASE_ID, NEWEST_ASSET_ID,
                            NEWEST_ASSET_ID, newest, latest=True)
        lines = install_request(fx.server, "newest")
        assert lines == ["installed newest %s" % newest_digest, "exit 0"], lines
        lines = install_request(fx.server, "pinned", tag=INSTALL_TAG)
        assert lines == ["installed pinned %s" % pinned_digest, "exit 0"], lines

        listing = payload_list(fx.server)
        assert listed(listing, "newest") == release_listing(
            "newest", NEWEST_TAG, NEWEST_RELEASE_ID, NEWEST_ASSET_ID,
            newest_digest), listing
        assert listed(listing, "pinned") == release_listing(
            "pinned", INSTALL_TAG, RELEASE_ID, ASSET_ID, pinned_digest), listing
        assert ("payload.install.done", "newest", str(NEWEST_RELEASE_ID)) in (
            install_audit(fx.server)), install_audit(fx.server)
        assert ("payload.install.done", "pinned", str(RELEASE_ID)) in (
            install_audit(fx.server)), install_audit(fx.server)
    with_install(pinned, run,
                 pins=[("newest", newest_digest), ("pinned", pinned_digest)])


def scenario_moved_tag_keeps_the_installed_release(_server):
    """A tag that moves after an install does not change what was installed."""
    data = healthy_build(INSTALL_NAME)
    moved = healthy_build("moved-tag")
    digest = hashlib.sha256(data).hexdigest()
    moved_digest = hashlib.sha256(moved).hexdigest()

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME, tag=INSTALL_TAG)
        assert lines == ["installed %s %s" % (INSTALL_NAME, digest), "exit 0"], lines
        fx.fake.add_release(INSTALL_TAG, MOVED_RELEASE_ID, MOVED_ASSET_ID,
                            MOVED_ASSET_ID, moved)
        expected = release_listing(INSTALL_NAME, INSTALL_TAG, RELEASE_ID,
                                   ASSET_ID, digest)

        lines = install_request(fx.server, INSTALL_NAME, tag=INSTALL_TAG)
        assert lines == ["hash_mismatch", "exit 1"], (
            "the moved tag's build differs from the pin, got %r" % lines)
        listing = payload_list(fx.server)
        assert listed(listing, INSTALL_NAME) == expected, (
            "the install must keep its release and asset, got %r" % listing)
        assert ("payload.install.refused", INSTALL_NAME, "hash_mismatch") in (
            install_audit(fx.server)), install_audit(fx.server)
    with_install(data, run, pins=[(INSTALL_NAME, digest)])


def scenario_install_tag_naming_another_release_is_refused(_server):
    """A tag whose release names another tag is refused before its asset is fetched."""
    data = healthy_build(INSTALL_NAME)

    def run(fx):
        fx.fake.add_release(INSTALL_TAG, RELEASE_ID, ASSET_ID, ASSET_ID, data,
                            tag_name="v9")
        lines = install_request(fx.server, INSTALL_NAME, tag=INSTALL_TAG)
        assert lines == ["tag_mismatch", "exit 1"], lines
        assert all(path.startswith("/repos/") for path in fx.fake.requests), (
            "no asset may be fetched for a mismatched tag, got %r"
            % fx.fake.requests)
        assert listed(payload_list(fx.server), INSTALL_NAME) is None, (
            "a mismatched tag must not be recorded")
        assert ("payload.install.refused", INSTALL_NAME, "tag_mismatch") in (
            install_audit(fx.server)), install_audit(fx.server)
    with_install(data, run)


def scenario_install_invalid_tag_is_refused_and_audited(_server):
    """A tag the encoder cannot carry is refused before anything is fetched, and audited."""
    def run(fx):
        # A slash is an ordinary byte the encoder escapes, so the tag that is
        # invalid is one over the 64 bytes an option value carries.
        lines = install_request(fx.server, INSTALL_NAME, tag="v" * 65)
        assert lines == ["bad_path", "exit 1"], lines
        assert fx.fake.requests == [], "an invalid tag must fetch nothing"
        assert ("payload.install.refused", INSTALL_NAME, "bad_path") in (
            install_audit(fx.server)), install_audit(fx.server)
    with_install(healthy_build(INSTALL_NAME), run)


def scenario_install_tag_not_on_the_server_is_refused_and_audited(_server):
    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME, tag="v9")
        assert lines == ["download_failed", "exit 1"], lines
        assert ("payload.install.refused", INSTALL_NAME, "download_failed") in (
            install_audit(fx.server)), install_audit(fx.server)
    with_install(healthy_build(INSTALL_NAME), run)


# An unpinned install's signed action (SPEC 2, #44): the release facts, the
# hash, and the two facts the approval grants, that the hash will be pinned
# and that the payload joins autoload.
def install_action_facts(data):
    return [
        "command=payload.install\n",
        "target=%s\n" % INSTALL_REPO,
        "sha256=%s\n" % hashlib.sha256(data).hexdigest(),
        "option.asset=%d\n" % ASSET_ID,
        "option.autoload=yes\n",
        "option.name=%s\n" % INSTALL_NAME,
        "option.pinned=yes\n",
        "option.release=%d\n" % RELEASE_ID,
        "option.tag=%s\n" % INSTALL_TAG,
    ]


def scenario_unknown_hash_asks_with_release_facts(_server):
    """An unpinned release answers 75, and its challenge carries every release fact."""
    data = healthy_build(INSTALL_NAME)

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        assert_staged(fx.server, lines, INSTALL_NAME, data)
        action = decoded_action(challenge_action(challenge_of(lines)))
        for fact in install_action_facts(data):
            assert fact in action, (
                "the challenge must carry %r, got %r" % (fact, action))
    with_install(data, run, allowlist="default")


def scenario_signature_over_a_challenge_missing_a_fact_is_refused(_server):
    """A signature over an action without one of its facts is refused, and nothing installs."""
    data = healthy_build(INSTALL_NAME)

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        staging, approval = assert_staged(fx.server, lines, INSTALL_NAME, data)
        challenge = challenge_of(lines)
        for fact in install_action_facts(data):
            signature = sign_challenge(
                fx.server, retarget(challenge, escape_option_line(fact), ""))
            assert grant(fx.server, approval, signature) == [
                "signature_action_mismatch", "exit 85"], (
                "a signature over an action without %r must be refused" % fact)
            assert grant(fx.server, approval, signature_of(signature)) == [
                "signature_invalid", "exit 79"], (
                "a bare signature over an action without %r must be refused"
                % fact)
        assert commit(fx.server, staging) == [
            "approval_required %s" % approval, "exit 75"], (
            "refused grants must leave the approval pending")
        assert listed(payload_list(fx.server), INSTALL_NAME) is None, (
            "a refused grant must install nothing")

        sign_and_grant(fx.server, approval, challenge)
        digest = hashlib.sha256(data).hexdigest()
        assert commit(fx.server, staging) == [
            "installed %s %s" % (INSTALL_NAME, digest), "exit 0"], (
            "the full challenge, once signed, must still install")
    with_install(data, run, allowlist="default")


def scenario_granted_install_pins_and_the_next_needs_no_approval(_server):
    data = healthy_build(INSTALL_NAME)
    digest = hashlib.sha256(data).hexdigest()

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        staging, approval = assert_staged(fx.server, lines, INSTALL_NAME, data)
        sign_and_grant(fx.server, approval, challenge_of(lines))
        assert commit(fx.server, staging) == [
            "installed %s %s" % (INSTALL_NAME, digest), "exit 0"]
        again = install_request(fx.server, INSTALL_NAME)
        assert again == ["installed %s %s" % (INSTALL_NAME, digest), "exit 0"], (
            "the pinned hash must install at once, got %r" % again)
        events = [event[0] for event in audit_events(fx.server)]
        for kind in ("payload.install.staged", "grant", "payload.install.done"):
            assert kind in events, "%s must reach audit tail, got %r" % (kind, events)
    with_install(data, run, allowlist="default")


def scenario_commit_after_its_pin_moved_answers_78(_server):
    """Two unpinned builds of one name wait; once the first is pinned, the second's approval is stale."""
    first = healthy_build(INSTALL_NAME)
    second = healthy_build("second-build")
    first_digest = hashlib.sha256(first).hexdigest()

    def run(fx):
        lines_one = install_request(fx.server, INSTALL_NAME)
        staging_one, approval_one = assert_staged(
            fx.server, lines_one, INSTALL_NAME, first)
        fx.fake.add_release(INSTALL_TAG, RELEASE_ID, ASSET_ID, ASSET_ID,
                            second, latest=True)
        lines_two = install_request(fx.server, INSTALL_NAME)
        staging_two, approval_two = assert_staged(
            fx.server, lines_two, INSTALL_NAME, second)

        sign_and_grant(fx.server, approval_one, challenge_of(lines_one))
        assert commit(fx.server, staging_one) == [
            "installed %s %s" % (INSTALL_NAME, first_digest), "exit 0"]

        sign_and_grant(fx.server, approval_two, challenge_of(lines_two))
        assert commit(fx.server, staging_two) == ["approval_stale", "exit 78"], (
            "a build whose hash can no longer be pinned must answer approval_stale")
        assert commit(fx.server, staging_two) == ["approval_stale", "exit 78"], (
            "the refused object must have left the console")

        listing = listed(payload_list(fx.server), INSTALL_NAME)
        assert listing is not None and "sha256=%s" % first_digest in listing, (
            "the refused build must not become current, got %r" % listing)
        events = audit_events(fx.server)
        assert any(event[0] == "payload.commit.stale" for event in events), (
            "a stale commit must reach audit tail, got %r" % events)
    with_install(first, run, allowlist="default")


def scenario_install_bad_name_is_refused_and_audited(_server):
    def run(fx):
        lines = send_command(fx.server, "payload install ../escape %s %s"
                             % (INSTALL_REPO, INSTALL_ASSET))
        assert lines == ["bad_name", "exit 1"], lines
        events = [event[0] for event in audit_events(fx.server)]
        assert "payload.install.refused" in events, (
            "a refused install must reach audit tail, got %r" % events)
    with_install(healthy_build(INSTALL_NAME), run)


def scenario_install_refused_while_approvals_are_full_is_audited(_server):
    data = healthy_build(INSTALL_NAME)

    def run(fx):
        fx.server.fresh()
        for i in range(3):
            name = "pinstall%d" % i
            pending = b"pending install %d" % i
            assert_staged(fx.server, push(fx.server, name, pending), name, pending)
        lines = install_request(fx.server, INSTALL_NAME)
        assert lines == ["approval_busy", "exit 76"], lines
        events = audit_events(fx.server)
        assert any(event[:2] == ("payload.install.refused", INSTALL_NAME)
                   for event in events), (
            "a refused install must reach audit tail, got %r" % events)
    with_install(data, run, allowlist="default")


def scenario_push_after_install_still_commits(_server):
    """A pushed build of a name whose hash is pinned still commits once the owner approves it."""
    first = healthy_build(INSTALL_NAME)
    second = healthy_build("pushed-build")

    def run(fx):
        lines = install_request(fx.server, INSTALL_NAME)
        staging, approval = assert_staged(fx.server, lines, INSTALL_NAME, first)
        sign_and_grant(fx.server, approval, challenge_of(lines))
        assert commit(fx.server, staging) == [
            "installed %s %s" % (INSTALL_NAME, hashlib.sha256(first).hexdigest()),
            "exit 0"]

        pushed, _ = approve_push(fx.server, INSTALL_NAME, second)
        assert commit(fx.server, pushed) == [
            "installed %s %s" % (INSTALL_NAME, hashlib.sha256(second).hexdigest()),
            "exit 0"], (
            "an approved push must still install when the name's hash is pinned "
            "to another build")
    with_install(first, run, allowlist="default")


INSTALL_SCENARIOS = [
    ("install refuses a host outside the allowlist",
     scenario_install_refused_outside_the_allowlist_host, RELEASE_FIXTURE_REASON),
    ("install refuses without an allowlist",
     scenario_install_refused_without_allowlist, RELEASE_FIXTURE_REASON),
    ("install refuses a repository outside the allowlist",
     scenario_install_refused_outside_the_allowlist_repository,
     RELEASE_FIXTURE_REASON),
    ("install refuses a failed download",
     scenario_install_failed_download_is_refused, RELEASE_FIXTURE_REASON),
    ("install refuses a redirect off the CDN suffix",
     scenario_install_redirect_off_the_cdn_is_refused, RELEASE_FIXTURE_REASON),
    ("install refuses a second redirect hop",
     scenario_install_second_redirect_hop_is_refused, RELEASE_FIXTURE_REASON),
    ("install refuses an asset ID mismatch",
     scenario_install_asset_id_mismatch_is_refused, RELEASE_FIXTURE_REASON),
    ("a pinned install records release and asset IDs and joins autoload",
     scenario_install_pinned_hash_installs_and_joins_autoload,
     RELEASE_FIXTURE_REASON),
    ("a different hash than the pin is refused and nothing is kept",
     scenario_install_different_hash_is_refused_and_nothing_kept,
     RELEASE_FIXTURE_REASON),
    ("an install runs the health check",
     scenario_install_runs_the_health_check, RELEASE_FIXTURE_REASON),
    ("Ariel never installs itself",
     scenario_ariel_never_installs_itself, RELEASE_FIXTURE_REASON),
    ("an unpinned install asks, then commit pins the hash and joins autoload",
     scenario_unpinned_install_asks_then_commit_pins_and_joins,
     RELEASE_FIXTURE_REASON),
    ("the allowlist answers protected even when asked",
     scenario_protected_allowlist_answers_87_even_when_asked,
     RELEASE_FIXTURE_REASON),
    ("install refusals and installs reach audit tail",
     scenario_install_actions_reach_audit_tail, RELEASE_FIXTURE_REASON),
    ("latest and a pinned tag record the release and asset IDs they resolved",
     scenario_install_latest_and_pinned_tag_record_their_ids,
     RELEASE_FIXTURE_REASON),
    ("a tag that moves after an install does not change the installed release",
     scenario_moved_tag_keeps_the_installed_release, RELEASE_FIXTURE_REASON),
    ("a tag whose release names another tag is refused and audited",
     scenario_install_tag_naming_another_release_is_refused,
     RELEASE_FIXTURE_REASON),
    ("an invalid tag is refused and audited, and fetches nothing",
     scenario_install_invalid_tag_is_refused_and_audited, RELEASE_FIXTURE_REASON),
    ("a tag the server does not name is refused and audited",
     scenario_install_tag_not_on_the_server_is_refused_and_audited,
     RELEASE_FIXTURE_REASON),
    ("an unknown hash answers 75 with the release facts in the challenge",
     scenario_unknown_hash_asks_with_release_facts, RELEASE_FIXTURE_REASON),
    ("a signature over a challenge missing a fact is refused",
     scenario_signature_over_a_challenge_missing_a_fact_is_refused, RELEASE_FIXTURE_REASON),
    ("a granted install pins, and the next install needs no approval",
     scenario_granted_install_pins_and_the_next_needs_no_approval, RELEASE_FIXTURE_REASON),
    ("a commit after its pin moved answers approval_stale, 78",
     scenario_commit_after_its_pin_moved_answers_78, RELEASE_FIXTURE_REASON),
    ("an install refused for its name is audited",
     scenario_install_bad_name_is_refused_and_audited, RELEASE_FIXTURE_REASON),
    ("an install refused while approvals are full is audited",
     scenario_install_refused_while_approvals_are_full_is_audited, RELEASE_FIXTURE_REASON),
    ("an approved push still commits when its name's hash is pinned",
     scenario_push_after_install_still_commits, RELEASE_FIXTURE_REASON),
]

RELEASE_SCENARIOS = {title for title, _check, _reason in INSTALL_SCENARIOS}

SCENARIOS.extend(INSTALL_SCENARIOS)


HTTP2_BODY = b"fetched body"


class FetchServer:
    """A local origin for http2_get. /redirect answers with a 302 to a host
    the allowlist does not name, so a followed hop would show in requests."""

    def __init__(self):
        self.requests = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body=b"", location=None):
                self.send_response(status)
                if location is not None:
                    self.send_header("Location", location)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                fake.requests.append(self.path)
                if self.path == "/file":
                    return self.reply(200, HTTP2_BODY)
                if self.path == "/redirect":
                    return self.reply(302, location="http://localhost:%d/offlist"
                                      % fake.port)
                return self.reply(404)

        self.httpd = http.server.ThreadingHTTPServer((HOST, 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path):
        return "http://%s:%d%s" % (HOST, self.port, path)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def with_fetch(scenario):
    """Run scenario against a fresh Ariel whose allowlist names the origin only."""
    origin = FetchServer()

    def setup(root):
        state = os.path.join(root, "data", "ariel")
        os.makedirs(state, exist_ok=True)
        with open(os.path.join(state, "allowlist"), "w") as fh:
            fh.write("host %s:%d\n" % (HOST, origin.port))

    server = Server(SERVER_BINARY, setup=setup)
    server.origin = origin
    try:
        return scenario(server)
    finally:
        server.stop()
        origin.stop()


def audit_kinds(server):
    return [event[0] for event in audit_events(server)]


def scenario_http2_refuses_off_allowlist_without_asking(_server):
    """A host the allowlist does not name is refused before anything is asked."""
    def run(server):
        url = "http://localhost:%d/file" % server.origin.port
        assert run_command(server, "http2_get " + url) == [
            "not_allowlisted", "exit 1"], (
            "a host outside the allowlist must be refused")
        assert server.origin.requests == [], "nothing may be fetched"
        assert "http2_get.refused" in audit_kinds(server), audit_kinds(server)
    with_fetch(run)


def scenario_http2_asks_with_its_url_in_the_signed_bytes(_server):
    """http2_get answers 75 and its challenge carries the URL."""
    def run(server):
        url = server.origin.url("/file")
        gated_request(server, "http2_get " + url,
                      ["command=http2_get", "target=download",
                       "option.url=" + url],
                      "fetch %s will run" % url)
    with_fetch(run)


def scenario_http2_fetches_its_body_after_a_grant(_server):
    """After the owner's grant the body is replied and the request is audited."""
    def run(server):
        url = server.origin.url("/file")
        command = "http2_get " + url
        approval, challenge = gated_request(
            server, command, ["option.url=" + url], "fetch %s will run" % url)
        sign_and_grant(server, approval, challenge)
        assert run_command(server, command) == ["fetched body", "exit 0"], (
            "a granted http2_get must reply the body and exit 0")
        assert server.origin.requests == ["/file"], server.origin.requests
        kinds = audit_kinds(server)
        assert "http2_get.request" in kinds and "http2_get.done" in kinds, kinds
    with_fetch(run)


def scenario_http2_output_file_is_written_after_a_grant(_server):
    """-o writes the body to the named file once the owner has granted it."""
    def run(server):
        url = server.origin.url("/file")
        dest = os.path.join(server.root, "data", "fetched")
        command = "http2_get -o %s %s" % (dest, url)
        approval, challenge = gated_request(
            server, command, ["destination=" + dest, "option.url=" + url],
            "fetch %s to %s will run" % (url, dest))
        sign_and_grant(server, approval, challenge)
        assert run_command(server, command) == ["exit 0"], (
            "a granted -o fetch must answer exit 0 and reply nothing else")
        path = os.path.join(server.root, "data", "fetched")
        with open(path, "rb") as fh:
            assert fh.read() == HTTP2_BODY, "the body must land in the file"
    with_fetch(run)


def scenario_http2_output_refuses_the_token_and_its_alias(_server):
    """-o answers protected for the token and for a hard link to it, unasked."""
    def run(server):
        url = server.origin.url("/file")
        token = secret_path(server, "token")
        assert_protected(server, "http2_get -o %s %s" % (token, url))
        alias = os.path.join(server.root, "data", "alias")
        make_link(alias, token, hard=True)
        assert_protected(server, "http2_get -o %s %s" % (alias, url))
        assert server.origin.requests == [], "nothing may be fetched"
    with_fetch(run)


def scenario_http2_refuses_a_url_that_left_the_allowlist_after_its_grant(_server):
    """An approved URL is refused once the allowlist no longer names its host."""
    def run(server):
        url = server.origin.url("/file")
        command = "http2_get " + url
        approval, challenge = gated_request(
            server, command, ["option.url=" + url], "fetch %s will run" % url)
        sign_and_grant(server, approval, challenge)
        with open(os.path.join(server.root, "data", "ariel", "allowlist"), "w") as fh:
            fh.write("host %s:%d\n" % (HOST, server.origin.port + 1))
        assert run_command(server, command) == ["not_allowlisted", "exit 1"], (
            "a URL the allowlist no longer names must be refused even when approved")
        assert server.origin.requests == [], "nothing may be fetched"
    with_fetch(run)


def scenario_http2_destination_replaced_after_a_grant_is_stale(_server):
    """A destination that appeared after the grant answers approval_stale, unwritten."""
    def run(server):
        url = server.origin.url("/file")
        path = os.path.join(server.root, "data", "fetched")
        command = "http2_get -o %s %s" % (path, url)
        approval, challenge = gated_request(
            server, command, ["destination=" + path, "option.url=" + url],
            "fetch %s to %s will run" % (url, path))
        sign_and_grant(server, approval, challenge)
        with open(path, "wb") as fh:
            fh.write(b"someone else")
        assert run_command(server, command) == ["approval_stale", "exit 78"], (
            "a destination that changed after the grant must answer approval_stale")
        with open(path, "rb") as fh:
            assert fh.read() == b"someone else", "the stale fetch must not write"
        assert server.origin.requests == [], "nothing may be fetched"
    with_fetch(run)


def scenario_http2_refuses_a_redirect_without_following_it(_server):
    """A redirect is refused, and the hop it names is never requested."""
    def run(server):
        url = server.origin.url("/redirect")
        command = "http2_get " + url
        approval, challenge = gated_request(
            server, command, ["option.url=" + url], "fetch %s will run" % url)
        sign_and_grant(server, approval, challenge)
        assert run_command(server, command) == ["redirect_refused", "exit 1"], (
            "a redirect must be refused")
        assert server.origin.requests == ["/redirect"], (
            "the redirect's hop must never be requested: %r" % server.origin.requests)
    with_fetch(run)


HTTP2_SCENARIOS = [
    ("http2_get refuses a URL off the allowlist without asking",
     scenario_http2_refuses_off_allowlist_without_asking, HOST_FIXTURE_REASON),
    ("http2_get answers 75 with its URL in the signed bytes",
     scenario_http2_asks_with_its_url_in_the_signed_bytes, HOST_FIXTURE_REASON),
    ("http2_get fetches its body after a grant and is audited",
     scenario_http2_fetches_its_body_after_a_grant, HOST_FIXTURE_REASON),
    ("http2_get -o writes the body to the file after a grant",
     scenario_http2_output_file_is_written_after_a_grant, HOST_FIXTURE_REASON),
    ("http2_get -o answers protected for the token and its hard link, unasked",
     scenario_http2_output_refuses_the_token_and_its_alias, HOST_ROOT_REASON),
    ("http2_get refuses an approved URL that left the allowlist",
     scenario_http2_refuses_a_url_that_left_the_allowlist_after_its_grant,
     HOST_FIXTURE_REASON),
    ("http2_get answers approval_stale when the destination changed after a grant",
     scenario_http2_destination_replaced_after_a_grant_is_stale, HOST_FIXTURE_REASON),
    ("http2_get refuses a redirect without following it",
     scenario_http2_refuses_a_redirect_without_following_it, HOST_FIXTURE_REASON),
]

SCENARIOS.extend(HTTP2_SCENARIOS)


# ---------------------------------------------------------------------------
# Freeze (SPEC 2, #47): the owner creates /data/ariel/freeze and Ariel records
# it in the keyring. From then on every ordinary approval, gated commit and run
# answers frozen and exit 89, including one granted or installed before the
# freeze. Only a recovery-signed key unfreeze passes and lifts it; deleting the
# file does not. key rotate-recovery is refused too (owner's proxy, 2026-10-24).
# ---------------------------------------------------------------------------

FROZEN_REPLY = ["frozen", "exit 89"]
FREEZE_STEPS = ("prepared", "committed", "renamed", "audited")
RUN_OK = ["status 0", "exit 0"]
APPROVALS_TABLE_SIZE = 16  # APPROVALS_MAX in store.c

FREEZE_NEW_TITLE = ("a freeze refuses new approvals and gated commands with "
                    "frozen and exit 89")
FREEZE_COMMIT_TITLE = ("a freeze refuses a commit granted before it and "
                       "installs nothing")
FREEZE_RUN_TITLE = "a freeze refuses to run a payload installed before it"
FREEZE_DELETE_TITLE = ("deleting the freeze file does not lift a freeze, and "
                       "a recovery-signed key unfreeze does")
FREEZE_RESTART_TITLE = ("a freeze holds after a restart with its file "
                        "deleted")
FREEZE_SLOTS_TITLE = ("while frozen, a recovery-signed key unfreeze passes "
                      "with the approval table full")
FREEZE_ROTATE_TITLE = ("a freeze refuses key rotate and key rotate-recovery "
                       "with frozen and exit 89")
FREEZE_PRIMARY_TITLE = ("a freeze is lifted only by the recovery key: a "
                        "primary signature over key unfreeze answers 79")
FREEZE_RACE_TITLE = ("a freeze racing a grant, a commit and a run admits "
                     "nothing after the cutoff")
FREEZE_RECORD_CRASH_TITLE = ("a crash at each durable step of the freeze "
                             "record leaves the console frozen or unfrozen, "
                             "never between")
FREEZE_UNFREEZE_CRASH_TITLE = ("a crash at each durable step of a key "
                               "unfreeze leaves the console frozen or "
                               "unfrozen, never between")


def freeze_file(server):
    return os.path.join(server.root, "data", "ariel", "freeze")


def set_freeze(server):
    with open(freeze_file(server), "w"):
        pass


def pending_challenge(server, command):
    """Request a gated command that is not signed yet: (approval, challenge)."""
    lines = run_command(server, command)
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "%s must answer approval_required and exit 75, got %r" % (command, lines))
    approval = APPROVAL_LINE.match(lines[0])
    challenge = CHALLENGE_LINE.match(lines[1])
    assert approval and challenge and challenge.group(1) == approval.group(1), (
        "expected approval_required and a matching challenge, got %r" % lines)
    prompt = server.next_line(timeout=5.0)
    assert prompt and prompt.startswith("prompt %s " % approval.group(1)), (
        "%s must show its approval prompt, got %r" % (command, prompt))
    return approval.group(1), lines[1]


def request_unfreeze(server):
    # A notification is shown at most once in ten seconds of test clock.
    server.advance(10_000)
    return pending_challenge(server, "key unfreeze")


def sign_and_grant_with(server, approval, challenge, key):
    """The owner's step with the named key: sign, submit, expect the grant."""
    assert grant(server, approval, sign_challenge(server, challenge, key=key)) == [
        "approval_granted %s" % approval, "exit 0"], (
        "the signature of the named key must grant the approval")


def scenario_freeze_refuses_new_approvals(server):
    del server  # each freeze needs an Ariel of its own
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-new"})
    try:
        set_freeze(keys)
        assert run_command(keys, "env PATH") == FROZEN_REPLY, (
            "a gated command must answer frozen and exit 89 while frozen")
        assert push(keys, "frozennew", healthy_build("frozennew")) == FROZEN_REPLY, (
            "a push must not ask for approval while frozen")
    finally:
        keys.stop()


def scenario_freeze_refuses_commit_granted_before_it(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-commit"})
    try:
        staging, approval, challenge = push_for_challenge(
            keys, "frozencommit", healthy_build("frozencommit"))
        sign_and_grant(keys, approval, challenge)
        set_freeze(keys)
        assert commit(keys, staging) == FROZEN_REPLY, (
            "a commit granted before the freeze must answer frozen and exit 89")
        assert listed(payload_list(keys), "frozencommit") is None, (
            "a refused commit must install nothing")
    finally:
        keys.stop()


def scenario_freeze_refuses_run_of_installed_payload(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-run"})
    try:
        install_payload(keys, "frozenrun", healthy_build("frozenrun"))
        set_freeze(keys)
        assert run_payload(keys, "frozenrun") == FROZEN_REPLY, (
            "a payload installed before the freeze must not run while frozen")
    finally:
        keys.stop()


def scenario_freeze_survives_deleting_its_file(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-delete"})
    try:
        install_payload(keys, "frozendel", healthy_build("frozendel"))
        set_freeze(keys)
        assert run_payload(keys, "frozendel") == FROZEN_REPLY
        os.unlink(freeze_file(keys))
        assert run_payload(keys, "frozendel") == FROZEN_REPLY, (
            "deleting the freeze file must not lift the freeze")
        assert run_command(keys, "env PATH") == FROZEN_REPLY
        approval, challenge = request_unfreeze(keys)
        sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
        assert run_command(keys, "key unfreeze") == ["key_unfrozen 0", "exit 0"], (
            "a recovery-signed unfreeze must lift the freeze")
        assert run_payload(keys, "frozendel")[-2:] == RUN_OK, (
            "after the unfreeze the installed payload must run again")
    finally:
        keys.stop()


def scenario_freeze_holds_after_restart(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-restart"})
    try:
        install_payload(keys, "frozenrestart", healthy_build("frozenrestart"))
        set_freeze(keys)
        assert run_payload(keys, "frozenrestart") == FROZEN_REPLY
        os.unlink(freeze_file(keys))
        keys.restart()
        assert run_payload(keys, "frozenrestart") == FROZEN_REPLY, (
            "the recorded freeze must hold after a restart, file deleted")
    finally:
        keys.stop()


def scenario_freeze_unfreeze_with_slots_full(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-slots"})
    try:
        # Each unanswered payload approval expires and keeps its row, so
        # sixteen of them fill the table.
        for index in range(APPROVALS_TABLE_SIZE):
            push_for_challenge(keys, "fill%d" % index, b"fill %d" % index)
        set_freeze(keys)
        approval, challenge = request_unfreeze(keys)
        sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
        assert run_command(keys, "key unfreeze") == ["key_unfrozen 0", "exit 0"], (
            "a recovery-signed unfreeze must pass with the approval table full")
        keys.advance(10_000)
        assert run_command(keys, "env PATH")[-1] == "exit 75", (
            "an unfrozen Ariel must ask for an ordinary approval again")
    finally:
        keys.stop()


def scenario_freeze_refuses_key_rotate(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-rotate"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        set_freeze(keys)
        assert run_command(keys, "key rotate " + second) == FROZEN_REPLY, (
            "a primary key rotate must not be asked while frozen")
        assert run_command(keys, "key rotate-recovery " + second) == (
            FROZEN_REPLY), (
            "while frozen only key unfreeze may be asked; key rotate-recovery "
            "must answer frozen")
    finally:
        keys.stop()


def scenario_freeze_unfreeze_refuses_primary_signature(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-primary"})
    try:
        set_freeze(keys)
        approval, challenge = request_unfreeze(keys)
        assert grant(keys, approval, sign_challenge(keys, challenge)) == [
            "signature_invalid", "exit 79"], (
            "a primary signature over key unfreeze must be refused")
        assert run_command(keys, "env PATH") == FROZEN_REPLY, (
            "a refused primary signature must not lift the freeze")
        sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
        assert run_command(keys, "key unfreeze") == ["key_unfrozen 0", "exit 0"], (
            "the recovery signature must still lift the freeze")
    finally:
        keys.stop()


def scenario_freeze_racing_admissions(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "freeze-race"})
    try:
        install_payload(keys, "racerun", healthy_build("racerun"))
        keys.advance(10_000)
        staging, _ = approve_push(keys, "racecommit", healthy_build("racecommit"))
        keys.advance(10_000)
        approval, challenge = pending_challenge(keys, "env PATH")
        signature = signature_of(sign_challenge(keys, challenge))
        keys.advance(10_000)
        late_staging, _ = approve_push(keys, "racelate", healthy_build("racelate"))
        keys.advance(10_000)
        late_approval, late_challenge = pending_challenge(keys, "env HOME")

        results = []
        results_lock = threading.Lock()
        stop = threading.Event()

        def admit(kind, attempt):
            start = time.monotonic_ns()
            lines = attempt()
            with results_lock:
                results.append((start, kind, lines))

        def run_until_stopped():
            while not stop.is_set():
                admit("run", lambda: run_payload(keys, "racerun"))
                time.sleep(0.005)

        def admitted_runs(after=None):
            with results_lock:
                return [start for start, kind, _ in results
                        if kind == "run" and (after is None or start > after)]

        def wait_until(predicate, what, timeout=30.0):
            deadline = time.monotonic() + timeout
            while not predicate():
                assert time.monotonic() < deadline, "timed out waiting for %s" % what
                time.sleep(0.005)

        workers = [threading.Thread(target=run_until_stopped) for _ in range(2)]
        for worker in workers:
            worker.start()
        wait_until(lambda: admitted_runs(), "a run before the freeze")
        set_freeze(keys)
        cutoff = time.monotonic_ns()
        late_workers = [
            threading.Thread(target=admit, args=("commit", lambda: commit(keys, staging))),
            threading.Thread(target=admit, args=("grant", lambda: grant(keys, approval, signature))),
        ]
        for worker in late_workers:
            worker.start()
        wait_until(lambda: len(admitted_runs(cutoff)) >= 2, "runs after the freeze")
        stop.set()
        for worker in workers + late_workers:
            worker.join(timeout=30)

        late = [(kind, lines) for start, kind, lines in results if start > cutoff]
        assert any(kind == "run" for kind, _ in late), (
            "the runs must overlap the cutoff, got %r" % results)
        for kind, lines in late:
            assert lines == FROZEN_REPLY, (
                "a %s started after the freeze must be refused, got %r"
                % (kind, lines))

        assert run_payload(keys, "racerun") == FROZEN_REPLY
        assert commit(keys, late_staging) == FROZEN_REPLY, (
            "a commit granted before the freeze must be refused after it")
        assert grant(keys, late_approval, sign_challenge(
            keys, late_challenge)) == FROZEN_REPLY, (
            "a grant after the freeze must be refused")
        assert listed(payload_list(keys), "racelate") is None, (
            "a refused commit must install nothing")
    finally:
        keys.stop()


def scenario_freeze_record_crash(server):
    del server
    for step in FREEZE_STEPS:
        keys = Server(SERVER_BINARY, env={
            "ARIEL_HOST_NONCE_SEED": "freeze-record-" + step})
        try:
            install_payload(keys, "crashrecord", healthy_build("crashrecord"))
            set_freeze(keys)
            keys.env = {FAULT_ENV: step}
            keys.restart()
            command_until_crash(keys, "payload run --wait crashrecord")
            keys.env = None
            keys.restart()
            # Only the record itself can keep the freeze now.
            os.unlink(freeze_file(keys))
            if step == "prepared":
                assert run_payload(keys, "crashrecord")[-2:] == RUN_OK, (
                    "a freeze record crashed at prepared is not recorded: the "
                    "run must go through once the file is gone")
            else:
                assert run_payload(keys, "crashrecord") == FROZEN_REPLY, (
                    "a freeze record crashed at %s is recorded: it must hold "
                    "with the file gone" % step)
        finally:
            keys.stop()


def scenario_freeze_unfreeze_crash(server):
    del server
    for step in FREEZE_STEPS:
        keys = Server(SERVER_BINARY, env={
            "ARIEL_HOST_NONCE_SEED": "freeze-unfreeze-" + step})
        try:
            install_payload(keys, "crashunfreeze", healthy_build("crashunfreeze"))
            set_freeze(keys)
            assert run_payload(keys, "crashunfreeze") == FROZEN_REPLY
            keys.env = {FAULT_ENV: step}
            keys.restart()
            approval, challenge = request_unfreeze(keys)
            sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
            command_until_crash(keys, "key unfreeze")
            keys.env = None
            keys.restart()
            if step == "prepared":
                assert run_payload(keys, "crashunfreeze") == FROZEN_REPLY, (
                    "an unfreeze crashed at prepared leaves the keyring frozen")
            else:
                assert run_payload(keys, "crashunfreeze")[-2:] == RUN_OK, (
                    "an unfreeze crashed at %s is recorded: the console must "
                    "be unfrozen" % step)
        finally:
            keys.stop()


FREEZE_SCENARIOS = [
    (FREEZE_NEW_TITLE, scenario_freeze_refuses_new_approvals, HOST_ROOT_REASON),
    (FREEZE_COMMIT_TITLE, scenario_freeze_refuses_commit_granted_before_it,
     CLOCK_REASON),
    (FREEZE_RUN_TITLE, scenario_freeze_refuses_run_of_installed_payload,
     HOST_ROOT_REASON),
    (FREEZE_DELETE_TITLE, scenario_freeze_survives_deleting_its_file,
     CLOCK_REASON),
    (FREEZE_RESTART_TITLE, scenario_freeze_holds_after_restart,
     HOST_RESTART_REASON),
    (FREEZE_SLOTS_TITLE, scenario_freeze_unfreeze_with_slots_full,
     CLOCK_REASON),
    (FREEZE_ROTATE_TITLE, scenario_freeze_refuses_key_rotate, HOST_ROOT_REASON),
    (FREEZE_PRIMARY_TITLE, scenario_freeze_unfreeze_refuses_primary_signature,
     CLOCK_REASON),
    (FREEZE_RACE_TITLE, scenario_freeze_racing_admissions, CLOCK_REASON),
    (FREEZE_RECORD_CRASH_TITLE, scenario_freeze_record_crash, FAULT_REASON),
    (FREEZE_UNFREEZE_CRASH_TITLE, scenario_freeze_unfreeze_crash, FAULT_REASON),
]

CLOCK_SCENARIOS.update({FREEZE_COMMIT_TITLE, FREEZE_DELETE_TITLE,
                        FREEZE_SLOTS_TITLE, FREEZE_PRIMARY_TITLE,
                        FREEZE_RACE_TITLE, FREEZE_UNFREEZE_CRASH_TITLE})
HOST_ROOT_SCENARIOS.update({FREEZE_NEW_TITLE, FREEZE_COMMIT_TITLE,
                            FREEZE_RUN_TITLE, FREEZE_DELETE_TITLE,
                            FREEZE_RESTART_TITLE, FREEZE_SLOTS_TITLE,
                            FREEZE_ROTATE_TITLE, FREEZE_PRIMARY_TITLE,
                            FREEZE_RACE_TITLE, FREEZE_RECORD_CRASH_TITLE,
                            FREEZE_UNFREEZE_CRASH_TITLE})
FAULT_SCENARIOS.update({FREEZE_RECORD_CRASH_TITLE, FREEZE_UNFREEZE_CRASH_TITLE})
HOST_RESTART_SCENARIOS.add(FREEZE_RESTART_TITLE)

SCENARIOS.extend(FREEZE_SCENARIOS)


# ---------------------------------------------------------------------------
# Revocation by lineage (SPEC 2, #52): `key revoke --since <generation>
# <primary>`, signed by the current recovery key, declares every key from that
# generation on compromised, installs a new primary and suspends every
# persistent grant those keys approved: installs, pins and autoload entries. A
# suspended install answers suspended and exit 90; a suspended autoload entry
# leaves the autoload file in the revocation's own journal transaction; a
# suspended pin installs nothing without a new approval. Re-approving with the
# new primary restores a grant. A pin the allowlist set in advance was approved
# by no key, so no revocation suspends it.
# ---------------------------------------------------------------------------

SUSPENDED_REPLY = ["suspended", "exit 90"]
REVOKE_PROMPT = "key revoke will run"
REVOKE_STEPS = ("prepared", "committed", "suspended", "autoload", "renamed",
                "audited")

REVOKE_LINEAGE_TITLE = ("a P0 -> P1 -> P2 compromise: after key revoke --since "
                        "0 every grant of P0, P1 and P2 stays suspended across "
                        "a reboot and a payload rollback")
REVOKE_EARLIER_TITLE = ("key revoke keeps the grants made before the "
                        "compromise point, and the grants of a key retired by "
                        "key rotate, active")
REVOKE_SIGNER_TITLE = ("key revoke is refused unless signed by the current "
                       "recovery key, and refuses a generation it has not "
                       "reached before asking")
REVOKE_FROZEN_TITLE = ("key revoke passes while frozen with the approval table "
                       "full, and its autoload entries are gone before the "
                       "freeze lifts")
REVOKE_REAPPROVE_TITLE = ("a grant re-approved with the new primary is active "
                          "again, and the grant ledger is protected")
REVOKE_PIN_TITLE = ("a revoked pin installs nothing without a new approval, "
                    "and a pin set in advance stays active")
REVOKE_RACE_TITLE = ("a rotate or revoke racing a grant, a commit and a run "
                     "admits nothing after the cutoff")
REVOKE_CRASH_TITLE = ("a crash at each durable step of key revoke leaves no "
                      "grant active that the revocation suspended")
REVOKE_DOC_TITLE = ("the exit-code registry names suspended (90) and key "
                    "revoke, and the glossary names the grant ledger")


def revoke_action(since, new_pub):
    return ["command=key.revoke", "target=keyring", "sha256=none",
            "option.primary=" + new_pub, "option.since=%d" % since]


def revoke_command(since, new_pub):
    return "key revoke --since %d %s" % (since, new_pub)


def request_revoke(server, since, new_pub):
    return gated_request(server, revoke_command(since, new_pub),
                         revoke_action(since, new_pub), REVOKE_PROMPT,
                         wait_ms=10_000)


def revoke(server, since, new_pub, generation):
    """Request, sign with the recovery key, grant and perform one revocation."""
    approval, challenge = request_revoke(server, since, new_pub)
    sign_and_grant_with(server, approval, challenge, RECOVERY_KEY)
    assert run_command(server, revoke_command(since, new_pub)) == [
        "key_revoked %d" % generation, "exit 0"], (
        "a recovery-signed revocation must answer key_revoked %d" % generation)


def install_with(server, name, data, key):
    """Push, sign with key, grant and commit one build; return its hash."""
    server.advance(10_000)
    lines = push(server, name, data)
    staging, approval = assert_staged(server, lines, name, data)
    sign_and_grant_with(server, approval, challenge_of(lines), key)
    digest = hashlib.sha256(data).hexdigest()
    assert commit(server, staging) == [
        "installed %s %s" % (name, digest), "exit 0"], (
        "a commit signed by the active primary must install the build")
    return digest


def autoload_add_with(server, name, key):
    approval, challenge = autoload_ask(server, "add", name)
    sign_and_grant_with(server, approval, challenge, key)
    assert autoload_apply(server, "add", name, approval) == [
        "autoload add %s" % name, "exit 0"], "a granted autoload add must apply"


def autoload_file_names(server):
    with open(autoload_path(server)) as handle:
        return handle.read().splitlines()


def assert_grants_suspended(server, names, when):
    for name in names:
        assert run_payload(server, name) == SUSPENDED_REPLY, (
            "%s, a payload approved by a revoked key must answer suspended "
            "and exit 90" % when)
        assert "autoload %s" % name not in autoload_listing(server), (
            "%s, a suspended autoload entry must not be listed" % when)
        assert name not in autoload_file_names(server), (
            "%s, a suspended autoload entry must be gone from the loader's "
            "file" % when)


def assert_grants_active(server, names, when):
    for name in names:
        assert run_payload(server, name)[-2:] == RUN_OK, (
            "%s, a payload approved before the compromise must still run"
            % when)
        assert name in autoload_file_names(server), (
            "%s, an autoload entry approved before the compromise must stay"
            % when)


def scenario_revoke_lineage_suspends_every_grant(server):
    del server  # each revocation needs an Ariel of its own
    # No nonce seed: a seeded sequence starts over at the reboot's exec and
    # offers only nonces already consumed.
    keys = Server(SERVER_BINARY)
    try:
        with tempfile.TemporaryDirectory() as scratch:
            p0, p1 = test_key(), SECOND_PRIMARY_KEY
            p2 = make_key(scratch, "p2.key")
            p3 = make_key(scratch, "p3.key")
            install_with(keys, "linzero", healthy_build("linzero"), p0)
            autoload_add_with(keys, "linzero", p0)
            rotate_primary(keys, public_key(keys, p1), 1, p0)
            first = install_with(keys, "linone", healthy_build("linone-a"), p1)
            autoload_add_with(keys, "linone", p1)
            rotate_primary(keys, public_key(keys, p2), 2, p1)
            install_with(keys, "linone", healthy_build("linone-b"), p2)
            install_with(keys, "lintwo", healthy_build("lintwo"), p2)
            autoload_add_with(keys, "lintwo", p2)

            revoke(keys, 0, public_key(keys, p3), 3)
            names = ("linzero", "linone", "lintwo")
            assert_grants_suspended(keys, names, "after the revocation")

            approval, challenge = gate_request(keys, "reboot")
            sign_and_grant_with(keys, approval, challenge, p3)
            reboot_and_wait(keys)
            assert_grants_suspended(keys, names, "after a reboot")

            lines = rollback_request(keys, "linone")
            approval = APPROVAL_LINE.match(lines[0]).group(1)
            sign_and_grant_with(keys, approval, challenge_of(lines), p3)
            # The rollback happens, but the build it restores was approved by
            # a revoked key: it is current, suspended, and not health-checked.
            assert send_command(keys, "payload rollback linone") == (
                SUSPENDED_REPLY), (
                "a rollback to a suspended build must answer suspended")
            assert "sha256=%s " % first in listed(payload_list(keys), "linone"), (
                "the new primary's rollback must make the previous build "
                "current")
            assert_grants_suspended(keys, names, "after a payload rollback")
            events = [kind for kind, _name, _id, _sha in audit_events(keys)]
            assert "key_revoke" in events and "grant_suspended" in events, (
                "the revocation and each suspension must be audited, got %r"
                % events)
    finally:
        keys.stop()


def scenario_revoke_keeps_earlier_grants_active(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "revoke-earlier"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            p0, p1 = test_key(), SECOND_PRIMARY_KEY
            p2 = make_key(scratch, "p2.key")
            p3 = make_key(scratch, "p3.key")
            install_with(keys, "honest", healthy_build("honest"), p0)
            autoload_add_with(keys, "honest", p0)
            # A planned rotation retires P0; P1 then leaks.
            rotate_primary(keys, public_key(keys, p1), 1, p0)
            install_with(keys, "leaked", healthy_build("leaked"), p1)
            autoload_add_with(keys, "leaked", p1)
            rotate_primary(keys, public_key(keys, p2), 2, p1)
            install_with(keys, "hostile", healthy_build("hostile"), p2)

            revoke(keys, 1, public_key(keys, p3), 3)
            assert_grants_active(keys, ("honest",), "after key revoke --since 1")
            assert_grants_suspended(keys, ("leaked", "hostile"),
                                    "after key revoke --since 1")
            keys.restart()
            assert_grants_active(keys, ("honest",), "after a restart")
            assert_grants_suspended(keys, ("leaked", "hostile"),
                                    "after a restart")
    finally:
        keys.stop()


def scenario_revoke_needs_current_recovery(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "revoke-signer"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            second = public_key(keys, SECOND_PRIMARY_KEY)
            assert run_command(keys, revoke_command(1, second)) == [
                "key_refused", "exit 1"], (
                "a revocation from a generation not reached yet must be "
                "refused before the owner is asked")
            assert run_command(keys, "key revoke --since x " + second) == [
                "bad_argument", "exit 1"], (
                "a generation that is not a number must be refused")
            assert run_command(keys, revoke_command(
                0, public_key(keys, RECOVERY_KEY))) == ["key_refused", "exit 1"], (
                "the recovery key must not become the primary")

            approval, challenge = request_revoke(keys, 0, second)
            for what, key in [("the primary", test_key()),
                              ("the key being installed", SECOND_PRIMARY_KEY)]:
                assert grant(keys, approval, sign_challenge(
                    keys, challenge, key=key)) == ["signature_invalid",
                                                   "exit 79"], (
                    "a revocation signed by %s must be refused" % what)
            sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
            assert run_command(keys, revoke_command(0, second)) == [
                "key_revoked 1", "exit 0"]

            fourth_key = make_key(scratch, "fourth.key")
            rotate_recovery(keys, public_key(keys, fourth_key), 2, RECOVERY_KEY)
            third = public_key(keys, make_key(scratch, "third.key"))
            approval, challenge = request_revoke(keys, 2, third)
            assert grant(keys, approval, sign_challenge(
                keys, challenge, key=RECOVERY_KEY)) == ["signature_invalid",
                                                        "exit 79"], (
                "a retired recovery key must not sign a revocation")
            sign_and_grant_with(keys, approval, challenge, fourth_key)
            assert run_command(keys, revoke_command(2, third)) == [
                "key_revoked 3", "exit 0"]
    finally:
        keys.stop()


def scenario_revoke_while_frozen_with_slots_full(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "revoke-frozen"})
    try:
        second = public_key(keys, SECOND_PRIMARY_KEY)
        install_with(keys, "frozenrev", healthy_build("frozenrev"), test_key())
        autoload_add_with(keys, "frozenrev", test_key())
        for index in range(APPROVALS_TABLE_SIZE):
            push_for_challenge(keys, "fill%d" % index, b"fill %d" % index)
        set_freeze(keys)
        assert run_payload(keys, "frozenrev") == FROZEN_REPLY
        keys.advance(10_000)
        approval, challenge = pending_challenge(keys, revoke_command(0, second))
        sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
        assert run_command(keys, revoke_command(0, second)) == [
            "key_revoked 1", "exit 0"], (
            "a recovery-signed revocation must pass while frozen with the "
            "approval table full")
        assert run_payload(keys, "frozenrev") == FROZEN_REPLY, (
            "a revocation must not lift the freeze")
        assert "frozenrev" not in autoload_file_names(keys), (
            "the suspended autoload entry must leave the loader's file before "
            "the freeze lifts")
        approval, challenge = request_unfreeze(keys)
        sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
        assert run_command(keys, "key unfreeze") == ["key_unfrozen 1", "exit 0"]
        assert_grants_suspended(keys, ("frozenrev",), "after the unfreeze")
    finally:
        keys.stop()


def scenario_revoke_reapproval_restores_grants(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "revoke-again"})
    try:
        data = healthy_build("again")
        install_with(keys, "again", data, test_key())
        autoload_add_with(keys, "again", test_key())
        revoke(keys, 0, public_key(keys, SECOND_PRIMARY_KEY), 1)
        assert_grants_suspended(keys, ("again",), "after the revocation")
        install_with(keys, "again", data, SECOND_PRIMARY_KEY)
        autoload_add_with(keys, "again", SECOND_PRIMARY_KEY)
        assert_grants_active(keys, ("again",), "after a re-approval")
        keys.restart()
        assert_grants_active(keys, ("again",), "after a restart")
        path = secret_path(keys, "grants")
        for template in SECRET_READS:
            assert_protected(keys, template.format(p=path))
    finally:
        keys.stop()


def scenario_revoke_suspends_approved_pin(_server):
    data = healthy_build(INSTALL_NAME)
    digest = hashlib.sha256(data).hexdigest()
    installed = ["installed %s %s" % (INSTALL_NAME, digest), "exit 0"]

    def approved(fx):
        server = fx.server
        lines = install_request(server, INSTALL_NAME)
        staging, approval = assert_staged(server, lines, INSTALL_NAME, data)
        sign_and_grant(server, approval, challenge_of(lines))
        assert commit(server, staging) == installed
        revoke(server, 0, public_key(server, SECOND_PRIMARY_KEY), 1)
        assert_grants_suspended(server, (INSTALL_NAME,), "after the revocation")
        lines = install_request(server, INSTALL_NAME)
        assert lines[-1] == "exit 75", (
            "a revoked pin must not install without a new approval, got %r"
            % lines)
        staging, approval = assert_staged(server, lines, INSTALL_NAME, data)
        sign_and_grant_with(server, approval, challenge_of(lines),
                            SECOND_PRIMARY_KEY)
        assert commit(server, staging) == installed
        assert run_payload(server, INSTALL_NAME)[-2:] == RUN_OK, (
            "an install re-approved by the new primary must run")
        assert install_request(server, INSTALL_NAME) == installed, (
            "a re-approved pin must install again without asking")

    def preset(fx):
        server = fx.server
        assert install_request(server, INSTALL_NAME) == installed
        revoke(server, 0, public_key(server, SECOND_PRIMARY_KEY), 1)
        assert run_payload(server, INSTALL_NAME)[-2:] == RUN_OK, (
            "a build installed through a pin set in advance was approved by "
            "no key, so no revocation suspends it")
        assert install_request(server, INSTALL_NAME) == installed, (
            "a pin set in advance must still install without asking")

    with_install(data, approved, allowlist="default")
    with_install(data, preset, pin=(INSTALL_NAME, digest))


def scenario_revoke_racing_admissions(server):
    del server
    keys = Server(SERVER_BINARY, env={"ARIEL_HOST_NONCE_SEED": "revoke-race"})
    try:
        with tempfile.TemporaryDirectory() as scratch:
            third = public_key(keys, make_key(scratch, "third.key"))
        second = public_key(keys, SECOND_PRIMARY_KEY)

        # A rotation is a cutoff too: what generation 0 granted is spent.
        keys.advance(10_000)
        staging = approve_push_with(keys, "rotcommit", healthy_build("rotcommit"),
                                    test_key())
        keys.advance(10_000)
        approval, challenge = pending_challenge(keys, "env PATH")
        signature = signature_of(sign_challenge(keys, challenge))
        rotate_primary(keys, second, 1, test_key(), wait_ms=10_000)
        assert commit(keys, staging) == ["approval_stale", "exit 78"], (
            "a commit granted before a rotation must answer approval_stale")
        assert grant(keys, approval, signature) == ["signature_invalid",
                                                    "exit 79"], (
            "a grant signed before a rotation must be refused after it")
        assert listed(payload_list(keys), "rotcommit") is None

        install_with(keys, "racerev", healthy_build("racerev"),
                     SECOND_PRIMARY_KEY)
        keys.advance(10_000)
        staging = approve_push_with(keys, "revcommit", healthy_build("revcommit"),
                                    SECOND_PRIMARY_KEY)
        keys.advance(10_000)
        approval, challenge = pending_challenge(keys, "env HOME")
        signature = signature_of(sign_challenge(keys, challenge,
                                                key=SECOND_PRIMARY_KEY))
        revoke_approval, revoke_challenge = request_revoke(keys, 1, third)
        sign_and_grant_with(keys, revoke_approval, revoke_challenge,
                            RECOVERY_KEY)

        results = []
        results_lock = threading.Lock()
        stop = threading.Event()

        def run_until_stopped():
            while not stop.is_set():
                start = time.monotonic_ns()
                lines = run_payload(keys, "racerev")
                with results_lock:
                    results.append((start, lines))
                time.sleep(0.005)

        workers = [threading.Thread(target=run_until_stopped) for _ in range(2)]
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + 30
        while not results:
            assert time.monotonic() < deadline, "no run before the revocation"
            time.sleep(0.005)
        assert run_command(keys, revoke_command(1, third)) == [
            "key_revoked 2", "exit 0"]
        cutoff = time.monotonic_ns()
        late_results = {}

        def late(kind, attempt):
            late_results[kind] = attempt()

        late_workers = [
            threading.Thread(target=late, args=("commit", lambda: commit(keys, staging))),
            threading.Thread(target=late, args=("grant", lambda: grant(keys, approval, signature))),
        ]
        for worker in late_workers:
            worker.start()
        deadline = time.monotonic() + 30
        while True:
            with results_lock:
                after = [lines for start, lines in results if start > cutoff]
            if len(after) >= 2:
                break
            assert time.monotonic() < deadline, "no run after the revocation"
            time.sleep(0.005)
        stop.set()
        for worker in workers + late_workers:
            worker.join(timeout=30)

        with results_lock:
            after = [lines for start, lines in results if start > cutoff]
        for lines in after:
            assert lines == SUSPENDED_REPLY, (
                "a run started after the revocation must be refused, got %r"
                % lines)
        assert late_results["commit"] == ["approval_stale", "exit 78"], (
            "a commit granted before the revocation must answer approval_stale")
        assert late_results["grant"] == ["signature_invalid", "exit 79"], (
            "a grant signed before the revocation must be refused")
        assert listed(payload_list(keys), "revcommit") is None, (
            "a refused commit must install nothing")
    finally:
        keys.stop()


def approve_push_with(server, name, data, key):
    lines = push(server, name, data)
    staging, approval = assert_staged(server, lines, name, data)
    sign_and_grant_with(server, approval, challenge_of(lines), key)
    return staging


def scenario_revoke_crash(server):
    del server
    for step in REVOKE_STEPS:
        keys = Server(SERVER_BINARY, env={
            "ARIEL_HOST_NONCE_SEED": "revoke-crash-" + step})
        try:
            second = public_key(keys, SECOND_PRIMARY_KEY)
            install_with(keys, "crashrev", healthy_build("crashrev"), test_key())
            autoload_add_with(keys, "crashrev", test_key())
            keys.env = {FAULT_ENV: step}
            keys.restart()
            approval, challenge = request_revoke(keys, 0, second)
            sign_and_grant_with(keys, approval, challenge, RECOVERY_KEY)
            command_until_crash(keys, revoke_command(0, second))
            keys.env = None
            keys.restart()
            if step == "prepared":
                assert_grants_active(keys, ("crashrev",),
                                     "after a revocation crashed at prepared")
                generation = "0"
            else:
                assert_grants_suspended(
                    keys, ("crashrev",),
                    "after a revocation crashed at %s" % step)
                generation = "1"
            _approval, challenge = gated_request(
                keys, "env HOME", ["command=env", "target=HOME", "sha256=none"],
                "env HOME will run", wait_ms=10_000)
            assert generation_of(challenge) == generation, (
                "a revocation crashed at %s must leave the keyring at "
                "generation %s" % (step, generation))
        finally:
            keys.stop()


def scenario_revoke_is_documented(server):
    del server
    with open(os.path.join(repo_dir(), "docs", "exit-codes.md")) as handle:
        registry = handle.read()
    assert "| 90 | `suspended` |" in registry, (
        "docs/exit-codes.md must assign exit 90 to suspended")
    assert "key revoke" in registry, "docs/exit-codes.md must name key revoke"
    with open(os.path.join(repo_dir(), "GLOSSARY.md")) as handle:
        glossary = handle.read()
    for term in ("**Grant ledger**", "**Suspended grant**",
                 "**Revocation by lineage**"):
        assert term in glossary, "GLOSSARY.md must define %s" % term


REVOKE_SCENARIOS = [
    (REVOKE_LINEAGE_TITLE, scenario_revoke_lineage_suspends_every_grant,
     CLOCK_REASON),
    (REVOKE_EARLIER_TITLE, scenario_revoke_keeps_earlier_grants_active,
     CLOCK_REASON),
    (REVOKE_SIGNER_TITLE, scenario_revoke_needs_current_recovery,
     CLOCK_REASON),
    (REVOKE_FROZEN_TITLE, scenario_revoke_while_frozen_with_slots_full,
     CLOCK_REASON),
    (REVOKE_REAPPROVE_TITLE, scenario_revoke_reapproval_restores_grants,
     CLOCK_REASON),
    (REVOKE_PIN_TITLE, scenario_revoke_suspends_approved_pin,
     RELEASE_FIXTURE_REASON),
    (REVOKE_RACE_TITLE, scenario_revoke_racing_admissions, CLOCK_REASON),
    (REVOKE_CRASH_TITLE, scenario_revoke_crash, FAULT_REASON),
    (REVOKE_DOC_TITLE, scenario_revoke_is_documented, None),
]

CLOCK_SCENARIOS.update({REVOKE_LINEAGE_TITLE, REVOKE_EARLIER_TITLE,
                        REVOKE_SIGNER_TITLE, REVOKE_FROZEN_TITLE,
                        REVOKE_REAPPROVE_TITLE, REVOKE_RACE_TITLE,
                        REVOKE_CRASH_TITLE})
HOST_ROOT_SCENARIOS.update({REVOKE_LINEAGE_TITLE, REVOKE_EARLIER_TITLE,
                            REVOKE_SIGNER_TITLE, REVOKE_FROZEN_TITLE,
                            REVOKE_REAPPROVE_TITLE, REVOKE_RACE_TITLE,
                            REVOKE_CRASH_TITLE})
FAULT_SCENARIOS.add(REVOKE_CRASH_TITLE)
HOST_RESTART_SCENARIOS.update({REVOKE_LINEAGE_TITLE, REVOKE_EARLIER_TITLE,
                               REVOKE_REAPPROVE_TITLE})
RELEASE_SCENARIOS.add(REVOKE_PIN_TITLE)

SCENARIOS.extend(REVOKE_SCENARIOS)
HOST_ROOT_SCENARIOS.update(title for title, _, _ in WRITE_SCENARIOS)
SCENARIOS.extend(WRITE_SCENARIOS)
HOST_ROOT_SCENARIOS.update(title for title, _, _ in SFOCREATE_SCENARIOS)
SCENARIOS.extend(SFOCREATE_SCENARIOS)

ADDON_DIRECTORY_TITLE = ("a path under the addon directory or the state "
                         "directory answers protected and exit 87 for every "
                         "command, through a link and a hard link too")
ADDON_COMMANDS = (
    "ls {addons}", "ls {sight}", "stat {elf}", "file {elf}", "cat {elf}",
    "head {elf}", "grep . {elf}", "sha256sum {elf}", "read {elf}",
    "cmp {elf} {elf}", "find {addons}", "du {addons}", "tar -t {tar}",
    "unzip -l {zip}", "cp {elf} {out}", "mv {elf} {out}", "ln {elf} {out}",
    "rm {elf}", "rm -r {sight}", "touch {sight}/new", "mkdir {sight}/newdir",
    "tar -x {tar} {out}", "unzip {zip} {out}", "ls {state}",
    "touch {state}/new",
)
ADDON_LINK_COMMANDS = (
    "ls {p}", "cat {p}", "rm {p}", "cp {p} {out}", "mv {p} {out}",
    "ln {p} {out}", "touch {p}/new",
)


def addon_fixtures(server):
    addons = os.path.join(server.root, "data", "ariel", "addons")
    sight = os.path.join(addons, "sight")
    os.makedirs(sight, exist_ok=True)
    elf = os.path.join(sight, "elf")
    with open(elf, "wb") as f:
        f.write(b"\x7fELF" + bytes(range(256)))
    tar = os.path.join(sight, "pack.tar")
    with tarfile.open(tar, "w") as archive:
        member = tarfile.TarInfo("a.txt")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    zip_path = os.path.join(sight, "pack.zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("a.txt", b"x")
    return {
        "addons": addons, "sight": sight, "elf": elf, "tar": tar,
        "zip": zip_path, "state": os.path.join(server.root, "data", "ariel"),
        "out": os.path.join(server.root, "data", "addon-out"),
    }


def scenario_addon_directory_answers_protected(server):
    """Addon paths, nested, linked or hard linked, answer protected for every command."""
    paths = addon_fixtures(server)
    data = os.path.join(server.root, "data")
    dir_link = os.path.join(data, "addon-dir-link")
    elf_link = os.path.join(data, "addon-elf-link")
    elf_hard = os.path.join(data, "addon-elf-hard")
    make_link(dir_link, paths["addons"], hard=False)
    make_link(elf_link, paths["elf"], hard=False)
    make_link(elf_hard, paths["elf"], hard=True)

    failures = []
    for template in ADDON_COMMANDS:
        command = template.format(**paths)
        lines = run_command(server, command)
        if lines != ["protected", "exit 87"]:
            failures.append("%s answered %r" % (command, lines))
    nested_by_dir_link = os.path.join(dir_link, "sight", "elf")
    for link in (dir_link, nested_by_dir_link, elf_link, elf_hard):
        for template in ADDON_LINK_COMMANDS:
            command = template.format(p=link, out=paths["out"])
            lines = run_command(server, command)
            if lines != ["protected", "exit 87"]:
                failures.append("%s answered %r" % (command, lines))

    lines = run_command(server, "ls " + data)
    if lines[-1:] != ["exit 0"]:
        failures.append("ls of the data directory must still list, got %r"
                        % lines)
    assert not failures, "\n".join(failures)


ADDON_DEEP_DEPTH = 40
ADDON_DEEP_TITLE = ("a hard link to an addon file nested 40 directories deep "
                    "answers protected, and an overwrite through it is refused")
ADDON_WALK_TITLE = ("find and du from the data directory skip the addon "
                    "directory, the state directory and a hard link to an "
                    "addon file")
ADDON_UNREADABLE_TITLE = ("an unreadable addon directory refuses a path it "
                          "cannot rule out, until it is readable again")
ADDON_FETCH_TITLE = ("http2_get -o answers protected for an addon file 40 "
                     "directories deep and its hard link, unasked")


ADDON_DEEP_BYTES = b"\x7fELF deep addon"


def deep_addon(paths):
    """An addon file nested ADDON_DEEP_DEPTH directories below the addon directory."""
    deep = paths["addons"]
    for _ in range(ADDON_DEEP_DEPTH):
        deep = os.path.join(deep, "d")
    os.makedirs(deep)
    elf = os.path.join(deep, "elf")
    with open(elf, "wb") as f:
        f.write(ADDON_DEEP_BYTES)
    return elf


def scenario_addon_deep_hard_link(server):
    """A hard link to an addon file at any depth is the addon file, for every command."""
    paths = addon_fixtures(server)
    data = os.path.join(server.root, "data")
    elf = deep_addon(paths)
    link = os.path.join(data, "addon-deep-hard")
    source = os.path.join(data, "addon-deep-source")
    with open(source, "wb") as f:
        f.write(b"overwrite")
    try:
        make_link(link, elf, hard=True)
        failures = []
        for template in ("cat {p}", "stat {p}", "sha256sum {p}", "rm {p}",
                         "cp {p} {out}", "cp {src} {p}", "mv {src} {p}"):
            command = template.format(p=link, out=paths["out"], src=source)
            lines = run_command(server, command)
            if lines != ["protected", "exit 87"]:
                failures.append("%s answered %r" % (command, lines))
        with open(elf, "rb") as f:
            if f.read() != ADDON_DEEP_BYTES:
                failures.append("the addon file changed through its alias")
        assert not failures, "\n".join(failures)
    finally:
        if os.path.lexists(link):
            os.unlink(link)
        shutil.rmtree(os.path.join(paths["addons"], "d"), ignore_errors=True)


def scenario_addon_output_refuses_deep_link(_server):
    """http2_get -o answers protected for an addon file at any depth and for its hard link, unasked."""
    def run(server):
        url = server.origin.url("/file")
        paths = addon_fixtures(server)
        elf = deep_addon(paths)
        link = os.path.join(server.root, "data", "addon-fetch-hard")
        try:
            make_link(link, elf, hard=True)
            assert_protected(server, "http2_get -o %s %s" % (link, url))
            assert server.origin.requests == [], "nothing may be fetched"
        finally:
            if os.path.lexists(link):
                os.unlink(link)
            shutil.rmtree(os.path.join(paths["addons"], "d"), ignore_errors=True)
    with_fetch(run)


def state_identities(state):
    """The identity of the state directory and of every object below it."""
    ids = {(os.stat(state).st_dev, os.stat(state).st_ino)}
    for dirpath, dirnames, filenames in os.walk(state):
        for name in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, name))
            ids.add((st.st_dev, st.st_ino))
    return ids


def du_expected(root, state):
    """The bytes du must total under root: regular files, not the state tree or its identities."""
    protected = state_identities(state)
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if os.path.join(dirpath, d) != state]
        for name in filenames:
            st = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) not in protected:
                total += st.st_size
    return total


def scenario_addon_walk_skips_protected(server):
    """find and du from the data directory list and total nothing protected."""
    paths = addon_fixtures(server)
    data = os.path.join(server.root, "data")
    state = os.path.join(data, "ariel")
    plain = os.path.join(data, "find-plain.txt")
    hard = os.path.join(data, "find-elf-hard")
    with open(plain, "wb") as f:
        f.write(b"plain")
    try:
        make_link(hard, paths["elf"], hard=True)
        found = run_exit_zero(server, "find " + data)
        failures = []
        if plain not in found:
            failures.append("find must still list %s, got %r" % (plain, found))
        for line in found:
            if line == hard or line == state or line.startswith(state + "/"):
                failures.append("find listed a protected path: %s" % line)
            if "addons" in line.split("/"):
                failures.append("find listed the addon directory: %s" % line)

        du_lines = run_exit_zero(server, "du " + data)
        root_line = "%d %s" % (du_expected(data, state), data)
        if root_line not in du_lines:
            failures.append("du must total %r, got %r" % (root_line, du_lines))
        for line in du_lines:
            if line.split(" ", 1)[1].startswith(state):
                failures.append("du reported a protected path: %s" % line)
        assert not failures, "\n".join(failures)
    finally:
        if os.path.lexists(hard):
            os.unlink(hard)
        if os.path.lexists(plain):
            os.unlink(plain)


def scenario_addon_unreadable_refuses(server):
    """An addon directory Ariel cannot read makes every path it cannot rule out protected."""
    paths = addon_fixtures(server)
    data = os.path.join(server.root, "data")
    plain = os.path.join(data, "unreadable-plain.txt")
    locked = os.path.join(paths["addons"], "locked")
    with open(plain, "wb") as f:
        f.write(b"plain\n")
    os.makedirs(locked, exist_ok=True)
    try:
        os.chmod(locked, 0)
        assert run_command(server, "cat " + plain) == ["protected", "exit 87"], (
            "a path the addon walk cannot rule out must answer protected")
    finally:
        os.chmod(locked, 0o755)
        os.rmdir(locked)
    assert run_command(server, "cat " + plain) == ["plain", "exit 0"], (
        "once the addon directory is readable, the path answers again")
    os.unlink(plain)


ADDON_SCENARIOS = [
    (ADDON_DIRECTORY_TITLE, scenario_addon_directory_answers_protected,
     HOST_ROOT_REASON),
    (ADDON_DEEP_TITLE, scenario_addon_deep_hard_link, HOST_ROOT_REASON),
    (ADDON_WALK_TITLE, scenario_addon_walk_skips_protected, HOST_ROOT_REASON),
    (ADDON_UNREADABLE_TITLE, scenario_addon_unreadable_refuses,
     HOST_ROOT_REASON),
    (ADDON_FETCH_TITLE, scenario_addon_output_refuses_deep_link,
     HOST_ROOT_REASON),
]
HOST_ROOT_SCENARIOS.update(title for title, _, _ in ADDON_SCENARIOS)
SCENARIOS.extend(ADDON_SCENARIOS)


MANIFEST_ACCEPTED_TITLE = ("an addon whose manifest names this build's ABI and "
                           "platform is accepted, and the owner is not asked")
MANIFEST_ABI_TITLE = ("an addon built for another ABI answers addon_refused with "
                      "its abi field, and the owner is not asked")
MANIFEST_PLATFORM_TITLE = ("an addon built for another platform answers addon_refused "
                           "with its platform field, and the owner is not asked")
MANIFEST_MALFORMED_TITLE = ("a malformed manifest answers manifest_malformed, and "
                            "the listing still names every other addon")
MANIFEST_MISSING_TITLE = ("an addon without a manifest answers manifest_missing, "
                          "and the owner is not asked")


def manifest_addons(server):
    return os.path.join(server.root, "data", "ariel", "addons")


def make_addon(server, name, manifest=None):
    """An addon directory in the host test root, with its manifest when given."""
    path = os.path.join(manifest_addons(server), name)
    os.makedirs(path, exist_ok=True)
    if manifest is not None:
        with open(os.path.join(path, "manifest"), "w") as f:
            f.write(manifest)
    return path


def drop_addon(server, name):
    shutil.rmtree(os.path.join(manifest_addons(server), name), ignore_errors=True)


def manifest_text(name, abi="1", platform="host", args="0-2"):
    return "name %s\nargs %s\nabi %s\nplatform %s\n" % (name, args, abi, platform)


def scenario_manifest_accepted(server):
    """A manifest that matches this build is accepted, and the owner is not asked."""
    make_addon(server, "accepted", manifest_text("accepted"))
    try:
        lines = run_command(server, "addon check accepted")
        assert lines == ["addon accepted ok", "exit 0"], (
            "a matching manifest must be accepted, got %r" % lines)
        server.assert_no_line()
    finally:
        drop_addon(server, "accepted")


def scenario_manifest_wrong_abi(server):
    """A manifest naming another ABI is refused by name, before the owner is asked."""
    make_addon(server, "newer", manifest_text("newer", abi="2"))
    try:
        lines = run_command(server, "addon check newer")
        assert lines == ["addon_refused newer abi", "exit 1"], (
            "an addon for another ABI must answer addon_refused, got %r" % lines)
        server.assert_no_line()
    finally:
        drop_addon(server, "newer")


def scenario_manifest_wrong_platform(server):
    """A manifest naming another platform is refused by name, before the owner is asked."""
    make_addon(server, "elsewhere", manifest_text("elsewhere", platform="ps5"))
    try:
        lines = run_command(server, "addon check elsewhere")
        assert lines == ["addon_refused elsewhere platform", "exit 1"], (
            "an addon for another platform must answer addon_refused, got %r"
            % lines)
        server.assert_no_line()
    finally:
        drop_addon(server, "elsewhere")


def scenario_manifest_malformed(server):
    """A malformed manifest names itself, and the listing names the good addon too."""
    make_addon(server, "fine", manifest_text("fine"))
    make_addon(server, "broken", "name broken\nargs 0-2\nabi one\nplatform host\n")
    try:
        lines = run_command(server, "addon check broken")
        assert lines == ["manifest_malformed broken", "exit 92"], (
            "a malformed manifest must answer manifest_malformed, got %r" % lines)
        listing = run_command(server, "addon list")
        assert listing[-1] == "exit 0", (
            "the listing must end exit 0, got %r" % listing)
        assert "addon fine ok" in listing, (
            "the listing must still name the good addon, got %r" % listing)
        assert "manifest_malformed broken" in listing, (
            "the listing must name the malformed addon, got %r" % listing)
        server.assert_no_line()
    finally:
        drop_addon(server, "fine")
        drop_addon(server, "broken")


def scenario_manifest_missing(server):
    """An addon directory without a manifest is named, and the owner is not asked."""
    make_addon(server, "bare")
    try:
        lines = run_command(server, "addon check bare")
        assert lines == ["manifest_missing bare", "exit 91"], (
            "an addon without a manifest must answer manifest_missing, got %r"
            % lines)
        server.assert_no_line()
    finally:
        drop_addon(server, "bare")


MANIFEST_SCENARIOS = [
    (MANIFEST_ACCEPTED_TITLE, scenario_manifest_accepted, HOST_ROOT_REASON),
    (MANIFEST_ABI_TITLE, scenario_manifest_wrong_abi, HOST_ROOT_REASON),
    (MANIFEST_PLATFORM_TITLE, scenario_manifest_wrong_platform, HOST_ROOT_REASON),
    (MANIFEST_MALFORMED_TITLE, scenario_manifest_malformed, HOST_ROOT_REASON),
    (MANIFEST_MISSING_TITLE, scenario_manifest_missing, HOST_ROOT_REASON),
]
HOST_ROOT_SCENARIOS.update(title for title, _, _ in MANIFEST_SCENARIOS)
SCENARIOS.extend(MANIFEST_SCENARIOS)

ADDON_RUN_CLEAN_TITLE = ("an addon run waits for the owner's grant, runs once with its "
                         "arguments and an empty environment, and its output lands "
                         "under /data")
ADDON_RUN_REFUSED_TITLE = ("an addon run whose manifest is refused answers addon_refused "
                           "and the owner is not asked")
ADDON_RUN_TIMEOUT_TITLE = ("an addon run that passes its 10 second timeout answers "
                           "timed_out, keeps no output, and Ariel survives")
ADDON_RUN_TOO_LARGE_TITLE = ("an addon run that writes past the 64 KiB output cap "
                             "answers too_large, keeps no output, and Ariel survives")
ADDON_RUN_KILLED_TITLE = ("an addon run that is killed answers operation_failed, "
                          "keeps no output, and Ariel survives")

ADDON_RUN_TIMEOUT_MS = 10_000

RUNNER_SOURCE = """
#include <stdio.h>

extern char **environ;

int
main(int argc, char **argv) {
  int env = 0;
  int i;

  while(environ[env]) {
    env++;
  }
  printf("argc %d\\n", argc);
  for(i = 1; i < argc; i++) {
    printf("arg %d = %s\\n", i, argv[i]);
  }
  printf("env %d\\n", env);
  return 0;
}
"""

STUCK_SOURCE = """
#include <unistd.h>

int
main(void) {
  (void)write(1, "started\\n", 8);
  for(;;) {
    sleep(60);
  }
}
"""

FLOOD_SOURCE = """
#include <stdio.h>

int
main(void) {
  long i;

  for(i = 0; i < 65537; i++) {
    putchar('x');
  }
  return 0;
}
"""

KILLED_SOURCE = """
#include <signal.h>

int
main(void) {
  raise(SIGKILL);
  return 0;
}
"""


def addon_runner(server, name, source):
    """Install a host addon: its manifest, which this build accepts, and its ELF."""
    manifest = manifest_text(name, args="0-3")
    path = make_addon(server, name, manifest)
    with open(os.path.join(path, "elf"), "wb") as handle:
        handle.write(compile_payload(source, name))
    return hashlib.sha256(manifest.encode("ascii")).hexdigest()


def addon_run_request(server, name, manifest_sha, args, wait_ms=120000):
    """Ask for addon run of name with args and check the challenge names the addon."""
    command = " ".join(["addon", "run", name] + list(args))
    return gated_request(
        server, command,
        ["command=addon", "target=%s" % name, "sha256=%s" % manifest_sha,
         "option.argc=%d" % len(args), "option.args=%s" % args_hash(*args)],
        "addon %s will run" % name, wait_ms=wait_ms)


def addon_results(server, name):
    """The result files that runs of name left under /data."""
    data = os.path.join(server.root, "data")
    return sorted(entry for entry in os.listdir(data)
                  if entry.startswith("addon-%s-" % name))


def cleanup_addon(server, name):
    drop_addon(server, name)
    for entry in addon_results(server, name):
        os.remove(os.path.join(server.root, "data", entry))


def wait_for_addon_output(server, name, text, timeout=5.0):
    """Wait until a run of name has written text to its result file."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for entry in addon_results(server, name):
            with open(os.path.join(server.root, "data", entry), "rb") as handle:
                if handle.read().startswith(text.encode("ascii")):
                    return
        time.sleep(0.02)
    raise AssertionError("an addon run of %s must write %r" % (name, text))


def assert_addon_survives(server):
    lines = run_command(server, "echo still answering")
    assert lines[-1] == "exit 0", (
        "Ariel must answer after an addon run ends badly, got %r" % lines)


def scenario_addon_run_is_granted_and_bare(server):
    manifest_sha = addon_runner(server, "runner", RUNNER_SOURCE)
    try:
        approval, challenge = addon_run_request(server, "runner", manifest_sha,
                                                ["one", "two"])
        sign_and_grant(server, approval, challenge)
        lines = run_command(server, "addon run runner one two")
        match = re.match(r"^result (/data/addon-runner-\d+)$", lines[0]) if lines else None
        assert match and lines[1:] == ["status 0", "exit 0"], (
            "a granted addon run must name its result and exit 0, got %r" % lines)
        with open(os.path.join(server.root, match.group(1).lstrip("/")), "r") as handle:
            output = handle.read()
        assert output == "argc 3\narg 1 = one\narg 2 = two\nenv 0\n", (
            "the addon must get its arguments and an empty environment, got %r"
            % output)
        assert_asks_again(server, "addon run runner one two")
    finally:
        cleanup_addon(server, "runner")


def scenario_addon_run_refused_is_not_asked(server):
    make_addon(server, "newer", manifest_text("newer", abi="2"))
    try:
        lines = run_command(server, "addon run newer one")
        assert lines == ["addon_refused newer abi", "exit 1"], (
            "a refused addon must answer addon_refused without asking, got %r" % lines)
    finally:
        drop_addon(server, "newer")


def scenario_addon_run_timeout_is_cut(server):
    manifest_sha = addon_runner(server, "stuck", STUCK_SOURCE)
    try:
        approval, challenge = addon_run_request(server, "stuck", manifest_sha, [])
        sign_and_grant(server, approval, challenge)
        reply = {}
        worker = threading.Thread(target=lambda: reply.update(
            lines=run_command(server, "addon run stuck", timeout=30.0)))
        worker.start()
        wait_for_addon_output(server, "stuck", "started\n")
        server.advance(ADDON_RUN_TIMEOUT_MS - 1)
        time.sleep(0.2)
        assert worker.is_alive(), "an addon run must not be cut before its timeout"
        server.advance(1)
        worker.join(30.0)
        assert not worker.is_alive() and reply.get("lines") == [
            "timed_out", "exit 1"], (
            "an addon run past its timeout must answer timed_out, got %r"
            % reply.get("lines"))
        assert addon_results(server, "stuck") == [], (
            "a timed out addon run must keep no output")
        assert_addon_survives(server)
    finally:
        cleanup_addon(server, "stuck")


def scenario_addon_run_output_cap_is_too_large(server):
    manifest_sha = addon_runner(server, "flood", FLOOD_SOURCE)
    try:
        approval, challenge = addon_run_request(server, "flood", manifest_sha, [])
        sign_and_grant(server, approval, challenge)
        assert run_command(server, "addon run flood") == ["too_large", "exit 1"], (
            "an addon run past the 64 KiB output cap must answer too_large")
        assert addon_results(server, "flood") == [], (
            "a too large addon run must keep no output")
        assert_addon_survives(server)
    finally:
        cleanup_addon(server, "flood")


def scenario_addon_run_killed_is_operation_failed(server):
    manifest_sha = addon_runner(server, "killed", KILLED_SOURCE)
    try:
        approval, challenge = addon_run_request(server, "killed", manifest_sha, [])
        sign_and_grant(server, approval, challenge)
        assert run_command(server, "addon run killed") == [
            "operation_failed", "exit 1"], (
            "a killed addon run must answer operation_failed")
        assert addon_results(server, "killed") == [], (
            "a killed addon run must keep no output")
        assert_addon_survives(server)
    finally:
        cleanup_addon(server, "killed")


ADDON_RUN_SCENARIOS = [
    (ADDON_RUN_CLEAN_TITLE, scenario_addon_run_is_granted_and_bare, HOST_ROOT_REASON),
    (ADDON_RUN_REFUSED_TITLE, scenario_addon_run_refused_is_not_asked, HOST_ROOT_REASON),
    (ADDON_RUN_TIMEOUT_TITLE, scenario_addon_run_timeout_is_cut, HOST_ROOT_REASON),
    (ADDON_RUN_TOO_LARGE_TITLE, scenario_addon_run_output_cap_is_too_large,
     HOST_ROOT_REASON),
    (ADDON_RUN_KILLED_TITLE, scenario_addon_run_killed_is_operation_failed,
     HOST_ROOT_REASON),
]
HOST_ROOT_SCENARIOS.update(title for title, _, _ in ADDON_RUN_SCENARIOS)
SCENARIOS.extend(ADDON_RUN_SCENARIOS)

ADDON_AUDIT_TITLE = ("an addon run is audited with the gate's words, and a refused "
                     "addon is audited as refused")
ADDON_SIGNATURE_TITLE = ("an addon signature runs its addon once: a replayed signature "
                         "and another addon's signature do not run it")
ADDON_SURFACE_TITLE = ("the agent port has no command that installs, replaces or "
                       "removes an addon, and the addon directory is left as it was")


def addon_events(server, name):
    """The addon.* audit events of name as (kind, subject) pairs, oldest first."""
    return [(event[0], event[1]) for event in audit_events(server)
            if len(event) > 1 and event[0].startswith("addon.") and event[1] == name]


def addon_tree(path):
    """Every file under path, by its relative name, with its bytes."""
    tree = {}
    for root, _dirs, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            with open(full, "rb") as handle:
                tree[os.path.relpath(full, path)] = handle.read()
    return tree


def scenario_addon_run_is_audited(server):
    """Each outcome of an addon run is audited with the gate's words."""
    manifest_sha = addon_runner(server, "audited", RUNNER_SOURCE)
    make_addon(server, "refusedaudit", manifest_text("refusedaudit", abi="2"))
    try:
        assert run_command(server, "addon run refusedaudit one") == [
            "addon_refused refusedaudit abi", "exit 1"], (
            "a refused addon must answer addon_refused")
        assert ("addon.refused", "refusedaudit") in addon_events(
            server, "refusedaudit"), (
            "a refused addon must be audited as addon.refused, got %r"
            % addon_events(server, "refusedaudit"))

        approval, challenge = addon_run_request(server, "audited", manifest_sha, ["one"])
        sign_and_grant(server, approval, challenge)
        assert run_command(server, "addon run audited one")[-1] == "exit 0", (
            "a granted addon run must exit 0")

        approval, challenge = addon_run_request(server, "audited", manifest_sha, ["one"])
        sign_and_grant(server, approval, challenge)
        assert run_command(server, "addon run audited two") == [
            "approval_stale", "exit 78"], (
            "a run with other arguments than were signed must answer approval_stale")

        approval, challenge = addon_run_request(server, "audited", manifest_sha, ["three"])
        server.controller("deny %s" % approval, "denied %s" % approval)
        assert run_command(server, "addon run audited three") == [
            "approval_denied", "exit 77"], (
            "a denied addon run must answer approval_denied")

        kinds = {kind for kind, _ in addon_events(server, "audited")}
        assert {"addon.request", "addon.done", "addon.stale", "addon.denied"} <= kinds, (
            "the addon's audit events must include request, done, stale and denied, "
            "got %r" % sorted(kinds))
    finally:
        cleanup_addon(server, "audited")
        drop_addon(server, "refusedaudit")


# Past the 10 s notification gap, and well inside the 120 s approval expiry.
NOTIFICATION_WAIT_MS = 11_000


def scenario_addon_signature_runs_once(server):
    """A signature runs its addon once; a replayed one, or another addon's, does not."""
    sha_a = addon_runner(server, "once-a", RUNNER_SOURCE)
    sha_b = addon_runner(server, "once-b", RUNNER_SOURCE)
    try:
        approval_a, challenge_a = addon_run_request(server, "once-a", sha_a, [])
        signature_a = sign_challenge(server, challenge_a)
        granted = grant(server, approval_a, signature_a)
        assert granted == ["approval_granted %s" % approval_a, "exit 0"], (
            "the owner's signature must grant the approval, got %r" % granted)
        assert run_command(server, "addon run once-a")[-1] == "exit 0", (
            "a granted addon must run")
        assert len(addon_results(server, "once-a")) == 1, (
            "the granted run must leave its one result")

        replayed = grant(server, approval_a, signature_a)
        assert replayed[-1] != "exit 0", (
            "a replayed signature must not grant again, got %r" % replayed)

        approval_a2, challenge_a2 = addon_run_request(server, "once-a", sha_a, [])
        approval_b, _challenge_b = addon_run_request(
            server, "once-b", sha_b, [], wait_ms=NOTIFICATION_WAIT_MS)
        mismatched = grant(server, approval_b, sign_challenge(server, challenge_a2))
        assert mismatched == ["signature_action_mismatch", "exit 85"], (
            "another addon's signature must answer signature_action_mismatch, got %r"
            % mismatched)
        assert run_command(server, "addon run once-b")[-1] == "exit 75", (
            "an addon whose signature was refused must still wait for the owner")
        assert addon_results(server, "once-b") == [], (
            "an addon whose signature was refused must not run")

        sign_and_grant(server, approval_a2, challenge_a2)
        assert run_command(server, "addon run once-a")[-1] == "exit 0", (
            "the owner's own signature for once-a must still run it")
        assert len(addon_results(server, "once-a")) == 2, (
            "each granted run leaves its own result")
    finally:
        cleanup_addon(server, "once-a")
        cleanup_addon(server, "once-b")


def scenario_addon_surface_has_no_install(server):
    """install, replace and remove of an addon answer unknown_command and change nothing."""
    addon_runner(server, "held", RUNNER_SOURCE)
    directory = os.path.join(manifest_addons(server), "held")
    before_tree = addon_tree(directory)
    before_root = sorted(os.listdir(manifest_addons(server)))
    try:
        for command in ("addon install held", "addon replace held", "addon remove held"):
            server.advance(120000)
            lines = run_command(server, command)
            if lines[-1] == "exit 75":
                approval = APPROVAL_LINE.match(lines[0]).group(1)
                server.next_line()
                sign_and_grant(server, approval, lines[1])
            assert run_command(server, command) == ["unknown_command", "exit 1"], (
                "%r must answer unknown_command once signed" % command)
        assert addon_tree(directory) == before_tree, (
            "no addon command may change an addon's files")
        assert sorted(os.listdir(manifest_addons(server))) == before_root, (
            "no addon command may add or remove an addon")
    finally:
        drop_addon(server, "held")


ADDON_GUARD_TITLE = ("ADR-0010 guard: the agent port has no addon install path, and an "
                     "addon command is gated at 75, audited with the gate's words, and "
                     "answers only words and codes docs/exit-codes.md documents")
ADDON_GUARD_WORDS = ("approval_required", "approval_denied", "approval_stale",
                     "addon_refused", "timed_out", "too_large", "operation_failed",
                     "manifest_missing", "unknown_command", "status", "result")
ADDON_GUARD_CODES = (0, 1, 75, 77, 78, 91, 92)


def scenario_addon_guard(server):
    """ADR-0010's guard: no install path, and an addon command gated and coded like the rest."""
    scenario_addon_surface_has_no_install(server)

    with open(os.path.join(repo_dir(), "docs", "exit-codes.md")) as handle:
        registry = handle.read()
    for word in ADDON_GUARD_WORDS:
        assert "`%s" % word in registry, (
            "docs/exit-codes.md must document %s before an addon reply uses it" % word)
    for code in ADDON_GUARD_CODES:
        assert re.search(r"^\| %d \|" % code, registry, re.M), (
            "docs/exit-codes.md must assign exit %d" % code)

    manifest_sha = addon_runner(server, "guardrun", RUNNER_SOURCE)
    make_addon(server, "guardrefused", manifest_text("guardrefused", abi="2"))
    try:
        approval, _challenge = addon_run_request(server, "guardrun", manifest_sha, ["one"])
        server.controller("deny %s" % approval, "denied %s" % approval)
        assert run_command(server, "addon run guardrun one") == [
            "approval_denied", "exit 77"], "a denied addon run must answer 77"
        assert addon_events(server, "guardrun") == [
            ("addon.request", "guardrun"), ("addon.denied", "guardrun")], (
            "a gated addon run must audit request then denied, got %r"
            % addon_events(server, "guardrun"))

        assert run_command(server, "addon run guardrefused one") == [
            "addon_refused guardrefused abi", "exit 1"], "a refused addon must answer 1"
        assert addon_events(server, "guardrefused") == [
            ("addon.refused", "guardrefused")], (
            "a refused addon must audit addon.refused and no addon.request, got %r"
            % addon_events(server, "guardrefused"))

        for name, source, expected in (
                ("guardflood", FLOOD_SOURCE, ["too_large", "exit 1"]),
                ("guardkill", KILLED_SOURCE, ["operation_failed", "exit 1"])):
            sha = addon_runner(server, name, source)
            approval, challenge = addon_run_request(server, name, sha, [])
            sign_and_grant(server, approval, challenge)
            assert run_command(server, "addon run %s" % name) == expected, (
                "%s must answer %r" % (name, expected))
            assert addon_events(server, name) == [
                ("addon.request", name), ("addon.done", name),
                ("addon.failed", name)], (
                "a failed addon run must audit request, done, failed; got %r"
                % addon_events(server, name))

        sha = addon_runner(server, "guardstuck", STUCK_SOURCE)
        approval, challenge = addon_run_request(server, "guardstuck", sha, [])
        sign_and_grant(server, approval, challenge)
        reply = {}
        worker = threading.Thread(target=lambda: reply.update(
            lines=run_command(server, "addon run guardstuck", timeout=30.0)))
        worker.start()
        wait_for_addon_output(server, "guardstuck", "started\n")
        server.advance(ADDON_RUN_TIMEOUT_MS)
        worker.join(30.0)
        assert reply.get("lines") == ["timed_out", "exit 1"], (
            "a timed out addon run must answer timed_out, got %r" % reply.get("lines"))
        assert addon_events(server, "guardstuck") == [
            ("addon.request", "guardstuck"), ("addon.done", "guardstuck"),
            ("addon.failed", "guardstuck")], (
            "a timed out addon run must audit request, done, failed; got %r"
            % addon_events(server, "guardstuck"))
    finally:
        for name in ("guardrun", "guardflood", "guardkill", "guardstuck"):
            cleanup_addon(server, name)
        drop_addon(server, "guardrefused")


ADDON_GATE_SCENARIOS = [
    (ADDON_AUDIT_TITLE, scenario_addon_run_is_audited, HOST_ROOT_REASON),
    (ADDON_SIGNATURE_TITLE, scenario_addon_signature_runs_once, HOST_ROOT_REASON),
    (ADDON_SURFACE_TITLE, scenario_addon_surface_has_no_install, HOST_ROOT_REASON),
    (ADDON_GUARD_TITLE, scenario_addon_guard, HOST_ROOT_REASON),
]
HOST_ROOT_SCENARIOS.update(title for title, _, _ in ADDON_GATE_SCENARIOS)
SCENARIOS.extend(ADDON_GATE_SCENARIOS)


def main():
    argv = sys.argv[1:]

    # PS5_HOST is the whole switch: with it set the suite runs against the
    # console, and it starts nothing.
    if os.environ.get("PS5_HOST", "").strip():
        import console
        return console.main(SCENARIOS, argv)

    if "--plan" in argv:
        print("--plan lists console mode; set PS5_HOST to reach the console",
              file=sys.stderr)
        return 2

    binary = argv[0] if argv else "./ariel-host"
    global SERVER_BINARY
    SERVER_BINARY = binary
    # The critical fixture is named to Ariel at start, so it must exist first.
    critical = subprocess.Popen(["sleep", "600"])
    server = Server(binary, env={"ARIEL_HOST_CRITICAL_PID": str(critical.pid)})
    server.critical_pid = critical.pid
    try:
        for title, scenario, _clock in SCENARIOS:
            check(title, lambda scenario=scenario: scenario(server))
    finally:
        server.stop()
        critical.kill()
        critical.wait()

    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print("\n%d scenario(s) failed" % len(failed))
        return 1
    print("\nall %d scenarios passed" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
