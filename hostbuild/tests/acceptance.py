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
         fragments=None):
    """Send one payload push and return the lines the server answered."""
    size = len(data) if declared_size is None else declared_size
    if declared_hash is None:
        declared_hash = hashlib.sha256(data).hexdigest()
    sock = server.connect()
    try:
        header = "auth %s\npayload push %s %d %s\n" % (
            server.token, name, size, declared_hash)
        sock.sendall(header.encode("ascii"))
        if fragments is None:
            sock.sendall(data)
        else:
            offset = 0
            for step in fragments:
                sock.sendall(data[offset:offset + step])
                offset += step
                time.sleep(0.002)
            sock.sendall(data[offset:])
        sock.shutdown(socket.SHUT_WR)
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
        "the 'After Stage 1' section must show the payload's output"
    )
    mutated = text.replace(section, drifted, 1)

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".md", delete=False)
    try:
        handle.write(mutated)
        handle.close()
        fresh = Server(server.binary)
        try:
            try:
                run_quick_start(fresh, handle.name)
            except quickstart.FixtureError:
                pass
            else:
                raise AssertionError(
                    "a quick start changed without Ariel must fail the fixture"
                )
        finally:
            fresh.stop()
    finally:
        os.unlink(handle.name)


def staging_path(server, staging_id):
    return os.path.join(server.root, "data", "ariel", "staging", staging_id)


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


def scenario_missing_auth(server):
    sock = server.connect()
    try:
        sock.shutdown(socket.SHUT_WR)
        assert_exit_only(read_reply(sock), 70)
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
        time.sleep(0.1)
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


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./ariel-host"
    server = Server(binary)
    try:
        check("missing auth closes with exit 70",
              lambda: scenario_missing_auth(server))
        check("wrong token closes with exit 70",
              lambda: scenario_wrong_token(server))
        check("right token and a Stage 1 command outside the set answers "
              "unknown_command", lambda: scenario_unknown_command(server))
        check("two connections are served at the same time",
              lambda: scenario_two_connections(server))
        check("a truncated upload answers upload_mismatch and exit 81",
              lambda: scenario_truncated_upload(server))
        check("bytes past the declared size answer upload_mismatch and "
              "exit 81", lambda: scenario_extra_bytes(server))
        check("a hash mismatch answers upload_mismatch and exit 81",
              lambda: scenario_hash_mismatch(server))
        check("a name outside the grammar answers bad_name",
              lambda: scenario_bad_name(server))
        check("a matching push is staged, asks for approval and exits 75",
              lambda: scenario_matching_push(server))
        check("an upload in many small fragments arrives intact",
              lambda: scenario_fragmented_upload(server))
        check("an ELF containing 0xff bytes arrives intact",
              lambda: scenario_elf_with_ff(server))
        check("a denied push is answered on the virtual controller",
              lambda: scenario_denied_push(server))
        check("a commit before the decision answers approval_required and "
              "exit 75", lambda: scenario_commit_before_decision(server))
        check("an approved commit answers installed <name> <hash> and "
              "exit 0", lambda: scenario_commit_installed(server))
        check("a second commit of the same name replaces the first build",
              lambda: scenario_commit_replaces(server))
        check("an approval does not survive a restart of Ariel",
              lambda: scenario_commit_after_restart(server))
        check("a staging object changed after approval answers "
              "approval_stale and exit 78",
              lambda: scenario_commit_stale(server))
        check("an approval is single-use when two commits race",
              lambda: scenario_commit_single_use(server))
        check("a denied commit answers approval_denied and exit 77 and "
              "deletes the staging object",
              lambda: scenario_commit_denied(server))
        check("a run streams the payload's output, then status 0 and exit 0",
              lambda: scenario_run_streams_output(server))
        check("a payload exiting 3 answers status 3, and one exiting 75 "
              "answers status 75, never an approval request",
              lambda: scenario_run_reports_payload_status(server))
        check("an unknown payload name is an error",
              lambda: scenario_run_unknown_name(server))
        check("an object changed behind Ariel's back answers approval_stale "
              "and exit 78 and does not run",
              lambda: scenario_run_stale_object(server))
        check("a run of a committed build needs no new approval, and a push "
              "of a different build asks again",
              lambda: scenario_run_needs_no_new_approval(server))
        check("the quick start's 'After Stage 1' section passes headless",
              lambda: scenario_quick_start(server))
        check("a change to the 'After Stage 1' section without a change to "
              "Ariel makes the fixture fail",
              lambda: scenario_quick_start_doc_drift(server))
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
