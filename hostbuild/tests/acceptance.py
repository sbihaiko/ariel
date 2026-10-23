#!/usr/bin/env python3
"""Headless acceptance harness for the Ariel agent port tracer.

Starts the host build of Ariel in a temporary root, reads the access token
from its standard output and drives the server only through the agent port.
Nothing here reaches into the server's files or functions.
"""

import os
import re
import select
import socket
import subprocess
import sys
import tempfile
import time

HOST = "127.0.0.1"
TOKEN_LINE = re.compile(r"^token ([0-9a-f]{32})$")

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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.token = self._read_token()
        except Exception:
            self.stop()
            raise

    def _read_token(self):
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.proc.stdout], [], [], 0.2)
            if not ready:
                continue
            line = self.proc.stdout.readline()
            if not line:
                break
            text = line.decode("ascii", "replace").rstrip("\r\n")
            match = TOKEN_LINE.match(text)
            if not match:
                raise AssertionError("unexpected startup line %r" % text)
            ready, _, _ = select.select([self.proc.stdout], [], [], 0.3)
            if ready:
                extra = self.proc.stdout.readline()
                raise AssertionError(
                    "server printed more than one startup line: %r"
                    % extra.decode("ascii", "replace").rstrip("\r\n")
                )
            return match.group(1)
        raise AssertionError("server printed no token line")

    def connect(self, timeout=5.0):
        sock = socket.create_connection((HOST, self.port), timeout=timeout)
        sock.settimeout(timeout)
        return sock

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
        "payload push helloworld 5 %s" % ("0" * 64),
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


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./ariel-host"
    server = Server(binary)
    try:
        check("missing auth closes with exit 70",
              lambda: scenario_missing_auth(server))
        check("wrong token closes with exit 70",
              lambda: scenario_wrong_token(server))
        check("right token and any command answers unknown_command",
              lambda: scenario_unknown_command(server))
        check("two connections are served at the same time",
              lambda: scenario_two_connections(server))
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
