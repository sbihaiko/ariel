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
import hashlib
import io
import os
import platform
import queue
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

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

    def __init__(self, binary, env=None):
        self.binary = binary
        self.env = env
        self.root = tempfile.mkdtemp(prefix="ariel-host-")
        self.token = None
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
        self.reader = threading.Thread(target=self._pump, daemon=True)
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

    def _pump(self):
        for raw in self.proc.stdout:
            line = raw.decode("ascii", "replace").rstrip("\r\n")
            self.lines.put(line)
        self.lines.put(None)

    def next_line(self, timeout=5.0):
        """Return the next line the server printed, or None on timeout."""
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            return None
        assert line is not None, "the server closed its standard output"
        return line

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


def scenario_run_reports_payload_status(server):
    for code in (3, 75):
        data = compile_payload(
            EXIT_SOURCE.replace("EXIT_CODE", str(code)), "exit%d" % code)
        install_payload(server, "exit%d" % code, data)
        lines = run_payload(server, "exit%d" % code)
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

  if(argc < 3) {
    return 2;
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
    data = b"this is not an executable\n"
    install_payload(server, "notexec", data)
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
    digest = install_payload(server, "bghang", data)
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
    assert payload_logs(server, "bgnever") == ["no_log", "exit 1"], (
        "logs of a payload that never ran must answer no_log")

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
CONSOLE_SENTINEL = "192.0.2.1"
CONSOLE_BANNER = "console mode: %s:2324"
PLAN_RUN = "run  "
# Scenarios that create files or links under the host test root. Console mode
# cannot create them, so it runs its own checks of the same commands instead.
HOST_ROOT_REASON = ("needs files or links in the host test root, which console "
                    "mode cannot create")
PLAN_SKIP = re.compile(r"^skip (\S.*) \((needs [^()]+)\)$")
CLOCK_REASON = "needs the test clock"
FAULT_REASON = "needs the fault injector"
FAULT_ENV = "ARIEL_HOST_FAULT"
HOST_FILE_REASON = "needs the state file on the host"

# The scenarios that crash Ariel at a named commit step, which only a host
# build with the fault injector can do.
FAULT_SCENARIOS = {
    "a crash in prepared leaves the old version in payload list after restart",
    "a crash in committed leaves the new version in payload list after restart",
    "a committed change whose new object is gone is refused at start and "
    "audited, and the state file is left as it was",
    "a recovery killed after its renames, then a clean start, leaves the "
    "listing, state file and audit of one crash",
}

# The scenarios that rewrite or remove the state file on the host's disk,
# which the agent port cannot do on a console.
HOST_FILE_SCENARIOS = {
    "a store written by Stage 1 is migrated on the first start, and a "
    "second start changes nothing",
    "a state file whose payload lines have eight fields starts and lists "
    "previous=-",
}

# Scenarios that act on a process only the host build starts (a victim the
# suite spawns, or Ariel's own pid). A console has no such process to act on.
HOST_FIXTURE_REASON = ("needs a process only the host build starts, which "
                       "console mode cannot name")

# The scenarios whose behavior is defined by moving the host test clock.
# This list comes from the SPEC's time-dependent cases, not from the code.
CLOCK_SCENARIOS = {
    "missing auth after 5 s of test clock closes with exit 70",
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
}

# The scenarios that act on a process only the host build starts, or on
# Ariel's own pid. A console has neither to act on.
HOST_FIXTURE_SCENARIOS = {
    "kill of Ariel's own process answers protected and exit 87",
}

# The read-only scenarios that need the host test root: they write scratch
# files or links there, and the token, approval state and nonces live there.
HOST_ROOT_SCENARIOS = {
    "each read-only command runs with no approval and exits 0 with its output",
    "sha256sum prints the digest openssl dgst -sha256 prints",
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
                      | HOST_FILE_SCENARIOS | HOST_FIXTURE_SCENARIOS)
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


def expected_listing(name, hash_hex, previous_hex=None):
    """The payload list line a push of name committed as hash_hex shows.

    Stage 1 records only a name and a hash. A push has no release, so its
    version identifiers and source say so, and nothing is running: the commit
    approved running the build, it did not start it. previous names the build
    the commit replaced, or "-" for a first build.
    """
    return ("payload %s source=push version=- release=- asset=- "
            "sha256=%s path=/data/ariel/store/objects/%s running=no "
            "previous=%s" % (name, hash_hex, hash_hex, previous_hex or "-"))


def state_path(server):
    return os.path.join(server.root, "data", "ariel", "state")


def read_state(server):
    with open(state_path(server), "rb") as fh:
        return fh.read()


def scenario_list_after_commit(server):
    """After a commit, payload list shows the payload with every field."""
    data = b"listed bytes\n"
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
    data = b"survives a restart\n"
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


def scenario_stage1_store_migrates_once(server):
    """A store Stage 1 wrote is migrated on the first start, and only once.

    Stage 1 kept no state file, only per-name current records. Removing the
    state file and starting again is the Stage 1 store; the first start builds
    the state file from those records, and a second start changes nothing.
    """
    data = b"stage one build\n"
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
        data = b"eight field build\n"
        hash_hex = hashlib.sha256(data).hexdigest()
        install_payload(legacy, "legacy", data)

        legacy.stop()
        with open(state_path(legacy), "r") as fh:
            lines = fh.read().splitlines()
        eight = [line.rsplit(" ", 1)[0] if line.startswith("payload ") else line
                 for line in lines]
        with open(state_path(legacy), "w") as fh:
            fh.write("\n".join(eight) + "\n")
        legacy._start()

        assert listed(payload_list(legacy), "legacy") == expected_listing(
            "legacy", hash_hex), (
            "a state file of eight fields must list its payloads with "
            "previous=-, got %r" % payload_list(legacy))
    finally:
        legacy.stop()


def scenario_commit_installed(server):
    data = b"committed bytes\n"
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
    first = b"first build"
    first_hash = hashlib.sha256(first).hexdigest()
    staging, _ = approve_push(server, "replace", first)
    assert commit(server, staging) == [
        "installed replace %s" % first_hash, "exit 0"], (
        "the first build of a name must be installed"
    )

    second = b"second build"
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
    install_payload(server, "shared-a", b"shared-a second build\n")
    install_payload(server, "shared-a", b"shared-a third build\n")

    assert listed(payload_list(server), "shared-b") == expected_listing(
        "shared-b", shared_hash), (
        "shared-b must still list the build it committed")
    lines = run_payload(server, "shared-b")
    assert lines == [
        "Hello, world from Ariel!", "status 0", "exit 0"], (
        "shared-b must still run the build it committed, got %r" % lines)


FIRST_BUILD = b"journal first build\n"
SECOND_BUILD = b"journal second build\n"
JOURNAL_NAME = "journal"
JOURNAL_FILE = "journal"

COUNT_SOURCE = """
#include <stdio.h>

int
main(int argc, char* argv[]) {
  FILE* log;

  if(argc < 2) {
    return 2;
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


def commit_until_crash(server, staging):
    """Send a commit that the injected fault ends, and wait for Ariel to die."""
    sock = server.connect()
    try:
        sock.sendall(
            ("auth %s\npayload commit %s\n" % (server.token, staging))
            .encode("ascii")
        )
        reply = reply_lines(read_reply(sock))
    except OSError:
        reply = []
    finally:
        sock.close()
    assert server.proc.wait(timeout=5.0) != 0, "the fault must end Ariel"
    return reply


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
        first = install_payload(history, "history", b"history build a\n")
        second = install_payload(history, "history", b"history build b\n")
        assert listed(payload_list(history), "history") == expected_listing(
            "history", second, first), (
            "the replaced build must be listed as previous")

        third = install_payload(history, "history", b"history build c\n")
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
    data = b"one use only"
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
    data = b"status of this approval"
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
    """A line is at most 1 KiB; past that the connection closes."""
    sock = server.connect()
    try:
        sock.sendall(b"auth " + b"0" * 1100 + b"\n")
        assert_closed(sock)
    finally:
        sock.close()

    # Exactly 1 KiB is still a line: an unknown command, not a close.
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n" % server.token).encode("ascii") +
                     b"a" * 1024 + b"\n")
        assert_unknown(read_reply(sock))
    finally:
        sock.close()

    # One byte past the limit closes the connection after auth too.
    sock = server.connect()
    try:
        sock.sendall(("auth %s\n" % server.token).encode("ascii") +
                     b"a" * 1025 + b"\n")
        assert_closed(sock)
    finally:
        sock.close()


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


def run_command(server, command):
    """One command on its own connection; the reply as lines."""
    sock = server.connect()
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
                    "sha256sum notes.txt"):
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
        # mv is a gated command of its own now. Its paths are outside the host
        # test root, so it answers protected before it asks the owner.
        if command.startswith(("rm ", "mkdir ", "touch ", "chmod ", "mv ")):
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


def scenario_inspection_runs_at_once(server):
    """These commands need no approval, so each answers with its own output."""
    assert run_command(server, "echo hello from ariel") == [
        "hello from ariel", "exit 0"]
    assert run_command(server, "sync") == ["exit 0"]
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
    action = challenge_action(challenge)
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
    action = challenge_action(challenge)
    assert action.startswith("ariel-action-v1\ncommand=cp\n"), action
    assert "\ntarget=%s\n" % source in action, action
    assert "\ndestination=%s\n" % destination in action, action
    assert "\nsha256=none\n" in action, action
    assert "\noption.kind=file\n" in action, action
    assert "\noption.dev=" in action and "\noption.ino=" in action, action


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

        # The stalled upload ends only when the clock passes its 60 s stall.
        server.settle(1)
        server.advance(59_999)
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
    r"^challenge (a-[0-9a-f]+) (\S+) ([0-9a-f]{32}) (\d+) (\d+) ([0-9a-f]+)$")


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


def sign_challenge(server, challenge, key=None):
    """Sign a challenge line with the offline signer; return the hex."""
    done = subprocess.run(
        [signer_path(server), "sign", key or test_key(), "--yes"],
        input=challenge + "\n", capture_output=True, text=True)
    assert done.returncode == 0, "the signer failed: %r" % done.stderr
    # The signer shows exactly the action it signs, never a summary.
    assert challenge_action(challenge) in done.stderr, (
        "the signer must print the canonical action as signed, got %r"
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
              ("high byte", action + b"\xc3\xa9")]
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
    data = b"one signature, two tries"
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


def compile_probe(scratch, name, defines):
    root = repo_dir()
    probe = os.path.join(scratch, name)
    done = subprocess.run(
        [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Werror", "-w",
         "-I" + root, "-o", probe,
         os.path.join(tests_dir(), "pin_probe.c"),
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
    r"^(\d+) (\S+) (\S+) (\S+) ([0-9a-f]{64}|none)$")


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


def scenario_audit_tail_order(server):
    """After a push, a grant and a commit, audit tail shows each one in order."""
    data = b"audited bytes\n"
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
    ours = [event for event in events if event.split()[3] in (staging, approval)]
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
            handle.write(b"x" * 300 + b"\n")
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


SERVER_BINARY = "./ariel-host"


SCENARIOS = [
    ("missing auth closes with exit 70", scenario_missing_auth, None),
    ("missing auth after 5 s of test clock closes with exit 70",
     scenario_auth_deadline, CLOCK_REASON),
    ("a line over 1 KiB closes the connection", scenario_line_limit, None),
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
    ("a store written by Stage 1 is migrated on the first start, and a "
     "second start changes nothing", scenario_stage1_store_migrates_once,
     HOST_FILE_REASON),
    ("a state file whose payload lines have eight fields starts and lists "
     "previous=-", scenario_state_without_previous_starts, HOST_FILE_REASON),
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
     "push", scenario_console_quick_start_waits_for_the_gap, None),    ("a crash in prepared leaves the old version in payload list after restart",
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
    ("a payload the record marks running is not started again on restart",
     scenario_running_mark_does_not_restart_payload, None),
]


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
