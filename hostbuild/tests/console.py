#!/usr/bin/env python3
"""Console mode of the acceptance suite.

With PS5_HOST set, the harness runs against a real console instead of starting
the host build of Ariel: Ariel already runs there, so nothing is started. The
harness reads the access token from the owner, builds `helloworld.elf` with
`prospero-clang`, and at every approval step prints the notification the
console shows and waits for the owner to decide on the controller.

The console has no test clock, so every scenario that moves time is skipped
and named. Console mode is a manual run: it is not part of CI and not part of
the Stage 1 gate, and the headless suite takes this path only when PS5_HOST is
set.

`--plan` lists the selection without reading the token, building anything or
opening a connection, which is what the headless suite uses to prove it.
"""

import hashlib
import os
import re
import socket
import sys
import tempfile
import time

import quickstart

PORT = 2324
BANNER = "console mode: %s:%d"
CLOCK_REASON = "needs the test clock"
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
STAGED_LINE = re.compile(r"^staged (s-[0-9a-f]+)$")
APPROVAL_LINE = re.compile(r"^approval_required (a-[0-9a-f]+)$")

# One notification every 10 s and approvals that expire after 120 s are the
# console's own limits; console mode waits in real time, since it can move
# no clock.
NOTIFICATION_SPACING = 10.0
BUSY_RETRIES = 6
DECISION_SPACING = 1.0
DECISION_RETRIES = 180


class ConsoleError(AssertionError):
    """The console and the harness disagree, or the owner cannot continue."""


def document_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "..", "..", "docs", "quick-start.md")


def prospero_clang():
    """The SDK compiler console mode builds helloworld.elf with."""
    sdk = os.environ.get("PS5_PAYLOAD_SDK", "").strip()
    if not sdk:
        raise ConsoleError(
            "console mode needs PS5_PAYLOAD_SDK to build helloworld.elf "
            "with prospero-clang")
    compiler = os.path.join(sdk, "bin", "prospero-clang")
    if not os.path.exists(compiler):
        raise ConsoleError("no prospero-clang at %s" % compiler)
    return [compiler]


class Operator:
    """The owner at the console, over a pair of text streams.

    Input and output are injectable, so the headless suite can prove what an
    approval step shows and that it waits, without a console and without a
    human.
    """

    def __init__(self, read=None, write=None, sleep=None):
        self._read = read if read is not None else input
        self._write = write if write is not None else print
        self._sleep = sleep if sleep is not None else time.sleep
        self.shown = []

    def say(self, text=""):
        self.shown.append(text)
        self._write(text)

    def pause(self, seconds):
        self._sleep(seconds)

    def token(self, host):
        """Read Ariel's access token from the owner."""
        self.say("Read Ariel's access token on the console: Ariel shows it "
                 "when it starts.")
        for _ in range(3):
            answer = (self._read("Ariel's token for %s: " % host) or "").strip()
            if TOKEN.match(answer):
                return answer
            self.say("That is not a token: 32 lowercase hex digits.")
        raise ConsoleError("no valid token was read from the owner")

    def approve(self, name, notification):
        self._decide("Approve", name, notification)

    def deny(self, name, notification):
        self._decide("Deny", name, notification)

    def _decide(self, verb, name, notification):
        """Show the console's notification, then wait for the decision."""
        self.say("")
        self.say("%s %s on the console with the controller." % (verb, name))
        self.say("The console notification should read:")
        self.say("  " + notification)
        self._read("Press Enter when the console has recorded your decision: ")


def read_reply(sock):
    """Read a reply until the server closes the connection."""
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except ConnectionResetError:
        pass
    return data.decode("ascii", "replace")


def reply_lines(reply):
    return [line for line in reply.replace("\r\n", "\n").split("\n")
            if line != ""]


class Link:
    """One connection to a console's agent port."""

    def __init__(self, host, port, token, connect=None, timeout=10.0):
        self.host = host
        self.port = port
        self.token = token
        self._connect = connect if connect is not None else socket.create_connection
        self.timeout = timeout

    def open(self, timeout=None):
        return self._connect((self.host, self.port),
                             timeout=timeout or self.timeout)

    def exchange(self, command, body=None, token=None):
        """Send one command after auth and return the lines the console replied."""
        sock = self.open()
        try:
            sock.sendall(("auth %s\n%s\n" % (token or self.token, command))
                         .encode("ascii"))
            if body is not None:
                sock.sendall(body)
            sock.shutdown(socket.SHUT_WR)
            return reply_lines(read_reply(sock))
        finally:
            sock.close()

    def raw(self, payload):
        """Send bytes with no auth line and return whatever came back."""
        sock = self.open()
        try:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            return read_reply(sock)
        finally:
            sock.close()


class Session:
    """The console checks, over one link to the agent port."""

    def __init__(self, link, operator, sleep=None):
        self.link = link
        self.operator = operator
        self._sleep = sleep if sleep is not None else time.sleep

    def push(self, name, data, declared_size=None, declared_hash=None):
        size = len(data) if declared_size is None else declared_size
        digest = (hashlib.sha256(data).hexdigest()
                  if declared_hash is None else declared_hash)
        command = "payload push %s %d %s" % (name, size, digest)
        for attempt in range(BUSY_RETRIES + 1):
            lines = self.link.exchange(command, data)
            if lines != ["approval_busy", "exit 76"] or attempt == BUSY_RETRIES:
                return lines
            # The console shows one notification every 10 s.
            self.operator.say(
                "The console allows one notification every 10 s; waiting.")
            self._sleep(NOTIFICATION_SPACING)
        return lines

    def commit(self, staging_id):
        return self.link.exchange("payload commit %s" % staging_id)

    def commit_after_decision(self, staging_id):
        """Retry a commit while the console still has no decision.

        The owner is asked to press Enter only once the controller has
        recorded the decision, so the first commit usually succeeds; a
        commit before the decision answers `approval_required` and is simply
        retried, as an agent does until `approval status` exists.
        """
        lines = self.commit(staging_id)
        for attempt in range(DECISION_RETRIES):
            if lines[-1:] != ["exit 75"]:
                return lines
            if attempt == 0:
                self.operator.say(
                    "The console has not recorded the decision yet; retrying.")
            self._sleep(DECISION_SPACING)
            lines = self.commit(staging_id)
        return lines

    def request(self, approval_id, name, size, digest, deny=False):
        """Show the notification the console displays and wait for the decision."""
        notification = ("prompt %s payload %s (%d bytes, sha256 %s) will run"
                        % (approval_id, name, size, digest))
        if deny:
            self.operator.deny(name, notification)
        else:
            self.operator.approve(name, notification)
        return notification


def assert_staged(lines, name, data):
    """Check a matching push's reply and return its staging and approval IDs."""
    assert len(lines) == 3, "expected three reply lines, got %r" % lines
    staged = STAGED_LINE.match(lines[0])
    assert staged, "expected 'staged <id>', got %r" % lines[0]
    approval = APPROVAL_LINE.match(lines[1])
    assert approval, "expected 'approval_required <id>', got %r" % lines[1]
    assert lines[2] == "exit 75", "expected exit 75, got %r" % lines[2]
    return staged.group(1), approval.group(1)


def assert_mismatch(lines):
    assert lines == ["upload_mismatch", "exit 81"], (
        "expected upload_mismatch and exit 81, got %r" % lines)


def check_missing_auth(session, context):
    del context
    assert reply_lines(session.link.raw(b"")) == ["exit 70"], (
        "a connection without auth must close with exit 70")


def check_line_limit(session, context):
    del context
    reply = session.link.raw(b"auth " + b"0" * 1100 + b"\n")
    assert reply == "", (
        "a line over 1 KiB must close the connection with no reply, got %r"
        % reply)


def check_wrong_token(session, context):
    del context
    token = session.link.token
    wrong = "0" * 32 if token != "0" * 32 else "1" * 32
    assert session.link.exchange("nonsense", token=wrong) == ["exit 70"], (
        "a wrong token must close with exit 70")


def check_unknown_command(session, context):
    del context
    for command in ("payload status", "nonsense"):
        lines = session.link.exchange(command)
        exits = [line for line in lines if line.startswith("exit ")]
        assert len(exits) == 1, (
            "expected exactly one exit line, got %r" % lines)
        assert lines[:-1] == ["unknown_command"], (
            "expected unknown_command before the exit line, got %r" % lines)
        assert lines[-1] == exits[0], "the exit line must come last: %r" % lines
        assert int(exits[0].split()[1]) != 0, (
            "unknown_command must exit nonzero, got %r" % exits[0])


def check_truncated_upload(session, context):
    del context
    assert_mismatch(session.push("consoleshort", b"hello", declared_size=6))


def check_hash_mismatch(session, context):
    del context
    assert_mismatch(session.push("consolehash", b"hello", declared_hash="0" * 64))


def check_bad_name(session, context):
    del context
    assert session.push("../x", b"") == ["bad_name", "exit 1"], (
        "a name outside the grammar must answer bad_name and exit 1")


def check_approval_then_install(session, context):
    del context
    data = b"console approval\n"
    digest = hashlib.sha256(data).hexdigest()
    lines = session.push("consoleapprove", data)
    staging, approval = assert_staged(lines, "consoleapprove", data)

    lines = session.commit(staging)
    assert lines == ["approval_required %s" % approval, "exit 75"], (
        "a commit before the decision must ask again with the same approval "
        "ID, got %r" % lines)

    session.request(approval, "consoleapprove", len(data), digest)
    lines = session.commit_after_decision(staging)
    assert lines == ["installed consoleapprove %s" % digest, "exit 0"], (
        "an approved commit must install the build, got %r" % lines)


def check_denied_commit(session, context):
    del context
    data = b"console denial\n"
    digest = hashlib.sha256(data).hexdigest()
    lines = session.push("consoledenied", data)
    staging, approval = assert_staged(lines, "consoledenied", data)

    session.request(approval, "consoledenied", len(data), digest, deny=True)
    lines = session.commit_after_decision(staging)
    assert lines == ["approval_denied", "exit 77"], (
        "a denied commit must answer approval_denied and exit 77, got %r"
        % lines)


def check_quick_start(session, context):
    quickstart.run_quick_start(
        doc_path=context.document,
        workdir=context.workdir,
        host=context.host,
        port=context.port,
        token=context.token,
        next_line=None,
        approve=None,
        notify=lambda approval_id, name, size, digest: session.request(
            approval_id, name, size, digest),
        cc=context.cc,
    )


class Context:
    """What the console checks share: where to build and how to reach Ariel."""

    def __init__(self, host, port, token, workdir, cc, document):
        self.host = host
        self.port = port
        self.token = token
        self.workdir = workdir
        self.cc = cc
        self.document = document


# Every check console mode runs. Each is a scenario that needs no test clock.
CHECKS = [
    ("missing auth closes with exit 70", check_missing_auth),
    ("a line over 1 KiB closes the connection", check_line_limit),
    ("a wrong token closes with exit 70", check_wrong_token),
    ("an unknown command answers unknown_command and exits nonzero",
     check_unknown_command),
    ("a truncated upload answers upload_mismatch and exit 81",
     check_truncated_upload),
    ("a hash mismatch answers upload_mismatch and exit 81",
     check_hash_mismatch),
    ("a name outside the grammar answers bad_name", check_bad_name),
    ("a commit before the decision answers approval_required and exit 75, the "
     "owner approves on the console, and the commit installs the build",
     check_approval_then_install),
    ("a deny step asks the owner to deny on the controller, and the commit "
     "answers approval_denied and exit 77", check_denied_commit),
    ("the quick start's 'After Stage 1' section passes against the console",
     check_quick_start),
]


def plan_lines(host, scenarios):
    """The selection console mode makes, without touching the console."""
    lines = [BANNER % (host, PORT)]
    lines += ["run  " + title for title, _check in CHECKS]
    lines += ["skip %s (%s)" % (title, CLOCK_REASON)
              for title, _check, clock in scenarios if clock]
    lines.append("console mode is not part of CI or of the Stage 1 gate.")
    return lines


def run(host, scenarios, operator=None):
    """Run every console check and return its results."""
    operator = operator or Operator()
    token = operator.token(host)
    cc = prospero_clang()
    workdir = tempfile.mkdtemp(prefix="ariel-console-")
    link = Link(host, PORT, token)
    session = Session(link, operator)
    context = Context(host=host, port=PORT, token=token, workdir=workdir,
                      cc=cc, document=document_path())

    results = []
    for title, check in CHECKS:
        print("\nRUN  %s" % title)
        try:
            check(session, context)
        except Exception as err:  # noqa: BLE001 - a failed check is a report
            results.append((title, False, "%s: %s" % (type(err).__name__, err)))
            print("FAIL %s: %s: %s" % (title, type(err).__name__, err))
        else:
            results.append((title, True, ""))
            print("PASS %s" % title)

    skipped = [title for title, _check, clock in scenarios if clock]
    print("\nskipped %d scenario(s) that %s:" % (len(skipped), CLOCK_REASON))
    for title in skipped:
        print("  %s" % title)
    return results


def main(scenarios, argv):
    """Console mode's entry point: list the plan, or run against the console."""
    host = os.environ.get("PS5_HOST", "").strip()
    if not host:
        print("console mode needs PS5_HOST", file=sys.stderr)
        return 2

    for line in plan_lines(host, scenarios):
        print(line)
    if "--plan" in argv:
        return 0

    try:
        results = run(host, scenarios)
    except ConsoleError as err:
        print("\nconsole mode stopped: %s" % err, file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nconsole mode stopped by the owner", file=sys.stderr)
        return 130

    failed = [result for result in results if not result[1]]
    if failed:
        print("\n%d console check(s) failed" % len(failed))
        return 1
    print("\nall %d console checks passed" % len(results))
    return 0
