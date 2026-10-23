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

import hashlib
import os
import queue
import re
import socket
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

    def __init__(self, binary):
        self.binary = binary
        self.root = tempfile.mkdtemp(prefix="ariel-host-")
        self.token = None
        self._start()

    def _start(self):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [self.binary, "--port", str(self.port), "--root", self.root],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._pump, daemon=True)
        self.reader.start()
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
    assert len(lines) == 3, "expected three reply lines, got %r" % lines
    staged = STAGED_LINE.match(lines[0])
    assert staged, "expected 'staged <id>', got %r" % lines[0]
    approval = APPROVAL_LINE.match(lines[1])
    assert approval, "expected 'approval_required <id>', got %r" % lines[1]
    assert lines[2] == "exit 75", "expected exit 75, got %r" % lines[2]

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
    """Push, check the prompt, then answer it on the virtual controller."""
    lines = push(server, name, data, fragments=fragments)
    _, approval = assert_staged(server, lines, name, data)
    answer = "approved" if decision == "approve" else "denied"
    server.controller("%s %s" % (decision, approval),
                      "%s %s" % (answer, approval))
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
        approve=lambda approval_id: server.controller(
            "approve %s" % approval_id, "approved %s" % approval_id),
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
PLAN_SKIP = re.compile(r"^skip (\S.*) \(needs the test clock\)$")

# The scenarios whose behavior is defined by moving the host test clock.
# This list comes from the SPEC's time-dependent cases, not from the code.
CLOCK_SCENARIOS = {
    "missing auth after 5 s of test clock closes with exit 70",
    "a stalled upload does not block another connection",
    "an approval expires after 120 s of test clock",
    "an expired approval does not count among the pending ones",
    "an unanswered staging object disappears after 15 min",
    "a second notification within 10 s answers approval_busy with no prompt",
    "the test clock is host-only and cannot enter the PS5 build",
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

    assert set(skipped) == CLOCK_SCENARIOS, (
        "console mode must skip exactly the scenarios that need the test "
        "clock:\nmissing %r\nunexpected %r"
        % (sorted(CLOCK_SCENARIOS - set(skipped)),
           sorted(set(skipped) - CLOCK_SCENARIOS)))
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


def scripted_session(replies):
    """One console session over a scripted link and a scripted operator."""
    import console

    events = []
    shown = []
    answers = []

    def read(prompt=""):
        events.append(("wait", prompt))
        return answers.pop(0) if answers else ""

    def write(line=""):
        shown.append(line)

    link = ScriptedLink(replies, events)
    operator = console.Operator(read=read, write=write, sleep=lambda s: None)
    return console, link, operator, console.Session(link, operator), events, shown


def scenario_console_approval_prompts(server):
    """An approval step shows the console notification and waits; deny says deny."""
    del server  # the fake link stands in for the agent port

    data = b"deny me"
    digest = hashlib.sha256(data).hexdigest()
    console, link, operator, session, events, shown = scripted_session([
        ["staged s-0123abcd", "approval_required a-4567ef90", "exit 75"],
        ["approval_denied", "exit 77"],
    ])

    lines = session.push("consoledenied", data)
    staging, approval = console.assert_staged(lines, "consoledenied", data)
    session.request(approval, "consoledenied", len(data), digest, deny=True)
    assert session.commit(staging) == ["approval_denied", "exit 77"], (
        "the scripted commit must answer the denial")

    notification = ("prompt %s payload consoledenied (%d bytes, sha256 %s) "
                    "will run" % (approval, len(data), digest))
    assert "Deny consoledenied on the console with the controller." in shown, (
        "a deny step must ask the owner to deny, showed %r" % shown)
    assert "The console notification should read:" in shown, (
        "the owner must be told what the console shows, showed %r" % shown)
    assert "  " + notification in shown, (
        "the step must print the notification the console shows, showed %r"
        % shown)

    sends = [i for i, event in enumerate(events) if event[0] == "send"]
    waits = [i for i, event in enumerate(events) if event[0] == "wait"]
    assert sends and waits, "the step must send and wait, events %r" % events
    assert sends[0] < waits[0] < sends[1], (
        "the prompt must follow the push and the commit must follow the "
        "owner's decision, events %r" % events)
    assert "payload push consoledenied" in events[sends[0]][1], (
        "the first exchange must be the push")
    assert "payload commit" in events[sends[1]][1], (
        "the commit must wait for the decision")

    # An approve step asks the owner to approve, with the same notification.
    console, link, operator, session, events, shown = scripted_session([
        ["staged s-0123abcd", "approval_required a-4567ef90", "exit 75"],
        ["installed consoleapproved %s" % digest, "exit 0"],
    ])
    lines = session.push("consoleapproved", data)
    staging, approval = console.assert_staged(lines, "consoleapproved", data)
    session.request(approval, "consoleapproved", len(data), digest)
    assert session.commit(staging) == [
        "installed consoleapproved %s" % digest, "exit 0"], (
        "the scripted commit must answer the installation")
    assert "Approve consoleapproved on the console with the controller." in shown, (
        "an approval step must ask the owner to approve, showed %r" % shown)
    assert "  prompt %s payload consoleapproved" % approval in " ".join(shown), (
        "the approval step must print the console notification, showed %r"
        % shown)


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


def approve_push(server, name, data):
    """Push, check the prompt, approve it and return the staging ID."""
    lines = push(server, name, data)
    staging, approval = assert_staged(server, lines, name, data)
    server.controller("approve %s" % approval, "approved %s" % approval)
    return staging, approval


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
    # object, and the object it replaces is gone.
    with open(os.path.join(store_dir(server), "current", "replace")) as fh:
        current = fh.read().strip()
    assert current == second_hash, (
        "the current record must point at the new build, got %r" % current
    )
    objects = os.listdir(os.path.join(store_dir(server), "objects"))
    assert second_hash in objects, (
        "the new build must be in the store, it holds %r" % objects
    )
    assert first_hash not in objects, (
        "the replaced object must be deleted, store holds %r" % objects
    )


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
    assert commit(server, staging) == ["approval_expired", "exit 77"], (
        "a commit after its approval expired must answer approval_expired "
        "and exit 77")
    assert not os.path.exists(staging_path(server, staging)), (
        "an expired approval's staging object must be deleted")
    assert commit(server, staging) == ["approval_stale", "exit 78"], (
        "once its object is gone, an expired approval is only stale")


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


def scenario_unknown_command(server):
    for command in (
        "payload run helloworld",
        "payload status",
        "nonsense",
    ):
        sock = server.connect()
        try:
            sock.sendall(
                ("auth %s\n%s\n" % (server.token, command)).encode("ascii")
            )
            assert_unknown(read_reply(sock))
        finally:
            sock.close()


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
            assert_unknown(read_reply(second))
        finally:
            second.close()
        first.sendall(b"anything\n")
        first.settimeout(2.0)
        assert_unknown(read_reply(first))
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
            assert_unknown(read_reply(sock))
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
SCENARIOS = [
    ("missing auth closes with exit 70", scenario_missing_auth, False),
    ("missing auth after 5 s of test clock closes with exit 70",
     scenario_auth_deadline, True),
    ("a line over 1 KiB closes the connection", scenario_line_limit, False),
    ("wrong token closes with exit 70", scenario_wrong_token, False),
    ("right token and a Stage 1 command outside the set answers "
     "unknown_command", scenario_unknown_command, False),
    ("two connections are served at the same time",
     scenario_two_connections, False),
    ("a fifth concurrent connection answers busy and exit 82",
     scenario_connection_limit, False),
    ("a ninth connection answers busy and exit 82 with every refusal slot "
     "taken", scenario_refusal_slots_exhausted, False),
    ("a stalled upload does not block another connection",
     scenario_stalled_upload_does_not_block, True),
    ("a truncated upload answers upload_mismatch and exit 81",
     scenario_truncated_upload, False),
    ("bytes past the declared size answer upload_mismatch and exit 81",
     scenario_extra_bytes, False),
    ("a hash mismatch answers upload_mismatch and exit 81",
     scenario_hash_mismatch, False),
    ("a name outside the grammar answers bad_name", scenario_bad_name, False),
    ("a matching push is staged, asks for approval and exits 75",
     scenario_matching_push, False),
    ("an upload in many small fragments arrives intact",
     scenario_fragmented_upload, False),
    ("an ELF containing 0xff bytes arrives intact",
     scenario_elf_with_ff, False),
    ("a denied push is answered on the virtual controller",
     scenario_denied_push, False),
    ("a commit before the decision answers approval_required and exit 75",
     scenario_commit_before_decision, False),
    ("an approved commit answers installed <name> <hash> and exit 0",
     scenario_commit_installed, False),
    ("a second commit of the same name replaces the first build",
     scenario_commit_replaces, False),
    ("an approval does not survive a restart of Ariel",
     scenario_commit_after_restart, False),
    ("a staging object changed after approval answers approval_stale and "
     "exit 78", scenario_commit_stale, False),
    ("an approval is single-use when two commits race",
     scenario_commit_single_use, False),
    ("a denied commit answers approval_denied and exit 77 and deletes the "
     "staging object", scenario_commit_denied, False),
    ("a run streams the payload's output, then status 0 and exit 0",
     scenario_run_streams_output, False),
    ("a payload exiting 3 answers status 3, and one exiting 75 answers "
     "status 75, never an approval request",
     scenario_run_reports_payload_status, False),
    ("an unknown payload name is an error", scenario_run_unknown_name, False),
    ("an object changed behind Ariel's back answers approval_stale and "
     "exit 78 and does not run", scenario_run_stale_object, False),
    ("a FIFO in place of a committed object answers approval_stale and "
     "exit 78 without blocking other clients",
     scenario_run_fifo_object, False),
    ("a run of a committed build needs no new approval, and a push of a "
     "different build asks again", scenario_run_needs_no_new_approval, False),
    ("a stored object that cannot be executed answers spawn_failed and "
     "exit 1", scenario_run_exec_failure, False),
    ("a finished connection reaches end of stream while a payload runs",
     scenario_run_does_not_leak_connections, False),
    ("the quick start's 'After Stage 1' section passes headless",
     scenario_quick_start, False),
    ("a change to the 'After Stage 1' section without a change to Ariel "
     "makes the fixture fail", scenario_quick_start_doc_drift, False),
    ("a broken setup command or a wrong exported token makes the fixture "
     "fail", scenario_quick_start_broken_setup, False),
    ("a failing '$' command in a block of any label makes the fixture fail",
     scenario_quick_start_unlabeled_block, False),
    ("an approval expires after 120 s of test clock",
     scenario_approval_expired, True),
    ("an expired approval does not count among the pending ones",
     scenario_expired_not_pending, True),
    ("an upload over 64 MiB answers staging_full and exit 80",
     scenario_upload_too_large, False),
    ("staging past 64 MiB in total answers staging_full",
     scenario_staging_total, False),
    ("an unanswered staging object disappears after 15 min",
     scenario_staging_ttl, True),
    ("a fourth pending approval answers approval_busy and exit 76 with no "
     "prompt", scenario_pending_limit, False),
    ("a second notification within 10 s answers approval_busy with no "
     "prompt", scenario_notification_rate, True),
    ("the test clock is host-only and cannot enter the PS5 build",
     scenario_test_clock_host_only, True),
    ("console mode with PS5_HOST set names the console scenarios and every "
     "scenario that needs the test clock", scenario_console_mode_plan, False),
    ("console mode prints what the owner should see on the console and "
     "waits for the controller decision",
     scenario_console_approval_prompts, False),
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
    server = Server(binary)
    try:
        for title, scenario, _clock in SCENARIOS:
            check(title, lambda scenario=scenario: scenario(server))
    finally:
        server.stop()

    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print("\n%d scenario(s) failed" % len(failed))
        return 1
    print("\nall %d scenarios passed" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
