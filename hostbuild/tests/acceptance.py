#!/usr/bin/env python3
"""Headless acceptance harness for the Ariel agent port.

Starts the host build of Ariel in a temporary root, reads the access token
from its standard output and drives the server only through the agent port.
Requests for approval reach the virtual controller on the server's standard
input, and its prompt and acknowledgements arrive on standard output.
Nothing here reaches into the server's files, except to create the
temporary root it runs under.
"""

import hashlib
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
        self.root = tempfile.mkdtemp(prefix="ariel-host-")
        self.port = free_port()
        self.proc = subprocess.Popen(
            [binary, "--port", str(self.port), "--root", self.root],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._pump, daemon=True)
        self.reader.start()
        try:
            self.token = self._read_token()
        except Exception:
            self.stop()
            raise

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
        "payload commit s-1",
        "payload run --wait helloworld",
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
