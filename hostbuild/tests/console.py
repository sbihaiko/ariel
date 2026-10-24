#!/usr/bin/env python3
"""Console mode of the acceptance suite.

With PS5_HOST set, the harness runs against a real console instead of starting
the host build of Ariel: Ariel already runs there, so nothing is started. The
harness reads the access token from the owner, builds `helloworld.elf` with
`prospero-clang`, and at every approval step prints the notification the
console shows and waits for the owner to sign the challenge.

The console has no test clock, so every scenario that moves time is skipped
and named. An approval the owner leaves unsigned expires on the console's own
clock and answers `approval_expired` with `exit 88`, which means push again;
the console has no refusal, so `exit 77` (`approval_denied`) never comes from
it. Console mode is a manual run: it is not part of CI and not part of the
Stage 1 gate, and the headless suite takes this path only when PS5_HOST is
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
import uuid

import quickstart

PORT = 2324
BANNER = "console mode: %s:%d"
CLOCK_REASON = "needs the test clock"
CONSOLE_STATE_DIR = "/data/ariel"
SECRET_FILES = ("token", "approvals", "nonces")
SECRET_READS = (
    "cat {p}",
    "stat {p}",
    "file {p}",
    "grep . {p}",
    "hexdump {p}",
    "sha256sum {p}",
    "cmp {p} {p}",
)
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
STAGED_LINE = re.compile(r"^staged (s-[0-9a-f]+)$")
APPROVAL_LINE = re.compile(r"^approval_required (a-[0-9a-f]+)$")

# One notification every 10 s and approvals that expire after 120 s are the
# console's own limits; console mode waits in real time, since it can move
# no clock.
NOTIFICATION_SPACING = 10.0
BUSY_RETRIES = 6


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

    def sign(self, name, notification, challenge):
        """Show the console's notification and the challenge, read the signature."""
        self.say("")
        self.say("Sign %s offline with your key: ariel-sign sign <keyfile>" % name)
        self.say("The console notification should read:")
        self.say("  " + notification)
        self.say("The challenge to sign:")
        self.say("  " + challenge)
        return (self._read("Signature (128 hex digits): ") or "").strip()


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
        return self.until_not_busy(lambda: self.link.exchange(command, data))

    def until_not_busy(self, send):
        """Send again while the console is busy, one notification every 10 s."""
        for attempt in range(BUSY_RETRIES + 1):
            lines = send()
            if lines != ["approval_busy", "exit 76"] or attempt == BUSY_RETRIES:
                return lines
            self.operator.say(
                "The console allows one notification every 10 s; waiting.")
            self._sleep(NOTIFICATION_SPACING)
        return lines

    def rollback(self, name):
        return self.until_not_busy(
            lambda: self.link.exchange("payload rollback %s" % name))

    def commit(self, staging_id):
        return self.link.exchange("payload commit %s" % staging_id)

    def grant(self, approval_id, signature):
        return self.link.exchange("approval grant %s %s"
                                  % (approval_id, signature))

    def status(self, approval_id):
        return self.link.exchange("approval status %s" % approval_id)

    def decide(self, approval_id, challenge, name, notification):
        """Show what the console displays, read the owner's signature, grant it."""
        signature = self.operator.sign(name, notification, challenge)
        lines = self.grant(approval_id, signature)
        assert lines == ["approval_granted %s" % approval_id, "exit 0"], (
            "the owner's signature must decide the approval, got %r" % lines)

    def request(self, approval_id, challenge, name, size, digest):
        notification = ("prompt %s payload %s (%d bytes, sha256 %s) will run"
                        % (approval_id, name, size, digest))
        self.decide(approval_id, challenge, name, notification)
        return notification


def assert_staged(lines, name, data):
    """Check a matching push's reply and return its staging and approval IDs."""
    assert len(lines) == 4, "expected four reply lines, got %r" % lines
    staged = STAGED_LINE.match(lines[0])
    assert staged, "expected 'staged <id>', got %r" % lines[0]
    approval = APPROVAL_LINE.match(lines[1])
    assert approval, "expected 'approval_required <id>', got %r" % lines[1]
    assert lines[2].startswith("challenge %s " % approval.group(1)), (
        "expected the challenge for the approval, got %r" % lines[2])
    assert lines[3] == "exit 75", "expected exit 75, got %r" % lines[3]
    return staged.group(1), approval.group(1), lines[2]


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
    """A command outside the set asks the owner first, never unknown_command."""
    del context
    for command in ("payload status", "nonsense"):
        lines = session.link.exchange(command)
        if lines == ["approval_busy", "exit 76"]:
            continue
        assert len(lines) == 3 and lines[2] == "exit 75", (
            "%s must answer approval_required and exit 75, got %r"
            % (command, lines))
        assert APPROVAL_LINE.match(lines[0]), (
            "expected approval_required, got %r" % lines[0])


def check_protected_without_asking(session, context):
    del context
    for command in ("touch /etc/ariel-gate",
                    "rm %s/token" % CONSOLE_STATE_DIR,
                    "rm %s/approvals" % CONSOLE_STATE_DIR):
        assert session.link.exchange(command) == ["protected", "exit 87"], (
            "%s must answer protected and exit 87 without asking" % command)


def check_run_refusals(session, context):
    del context
    assert session.link.exchange("/data/ariel-no-such-elf") == [
        "no_such_file", "exit 1"], "a run of a missing path must answer no_such_file"
    assert session.link.exchange("%s/token" % CONSOLE_STATE_DIR) == [
        "protected", "exit 87"], "a run of Ariel's token must answer protected"


def check_tar_refusals_without_asking(session, context):
    del context
    for command, answer in (
            ("tar -t", ["bad_argument", "exit 1"]),
            ("tar -t relative.tar", ["relative_path", "exit 1"]),
            ("tar -t /system/ariel-tar-tar", ["protected", "exit 87"]),
            ("tar -x /system/ariel-tar-tar /data/ariel-tar-out",
             ["protected", "exit 87"]),
            ("tar -t /data/ariel-no-such-tar", ["no_such_file", "exit 1"])):
        assert session.link.exchange(command) == answer, (
            "%s must answer %s without asking" % (command, answer[0]))


def run_gated_file_command(session, command):
    """Ask for command, show the owner the challenge, grant it; return the approval ID."""
    lines = session.until_not_busy(lambda: session.link.exchange(command))
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "%s must answer approval_required and exit 75, got %r" % (command, lines))
    approval = APPROVAL_LINE.match(lines[0])
    assert approval, "expected approval_required, got %r" % lines[0]
    shown = "prompt %s %s will run" % (approval.group(1), command)
    signature = session.operator.sign(command.split()[0], shown, lines[1])
    assert session.grant(approval.group(1), signature) == [
        "approval_granted %s" % approval.group(1), "exit 0"], (
        "the owner's signature must grant %s" % command)
    return approval.group(1)


def check_file_command_runs_after_approval(session, context):
    """mkdir and rmdir run once each, after the owner signs, on the console."""
    del context
    folder = "/data/gate-%s" % os.urandom(4).hex()
    run_gated_file_command(session, "mkdir " + folder)
    assert session.link.exchange("mkdir " + folder) == ["exit 0"], (
        "a signed mkdir must run")
    assert session.link.exchange("stat " + folder)[-1] == "exit 0", (
        "mkdir must create the directory")
    run_gated_file_command(session, "rmdir " + folder)
    assert session.link.exchange("rmdir " + folder) == ["exit 0"], (
        "a signed rmdir must run")
    assert session.link.exchange("stat " + folder)[-1] == "exit 1", (
        "rmdir must remove the directory")


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


def check_install_bad_name_is_audited(session, context):
    del context
    assert session.link.exchange("payload install ../x owner/app app.elf") == [
        "bad_name", "exit 1"], "an install with a bad name must answer bad_name"
    events = [line.split() for line in session.link.exchange("audit tail")
              if line != "exit 0"]
    assert any(event[1:4] == ["payload.install.refused", "-", "bad_name"]
               for event in events), (
        "a refused install must reach audit tail, got %r" % events)


def check_commit_stale_is_audited(session, context):
    del context
    staging = "s-0123456789abcdef"
    assert session.link.exchange("payload commit %s" % staging) == [
        "approval_stale", "exit 78"], (
        "a commit of an unknown staging ID must answer approval_stale and exit 78")
    events = [line.split() for line in session.link.exchange("audit tail")
              if line != "exit 0"]
    assert any(event[1:4] == ["payload.commit.stale", "-", staging]
               for event in events), (
        "a stale commit must reach audit tail, got %r" % events)


def check_approval_then_install(session, context):
    del context
    data = b"console approval\n"
    digest = hashlib.sha256(data).hexdigest()
    lines = session.push("consoleapprove", data)
    staging, approval, challenge = assert_staged(lines, "consoleapprove", data)

    lines = session.commit(staging)
    assert lines == ["approval_required %s" % approval, "exit 75"], (
        "a commit before the decision must ask again with the same approval "
        "ID, got %r" % lines)

    session.request(approval, challenge, "consoleapprove", len(data), digest)
    lines = session.commit(staging)
    assert lines == ["installed consoleapprove %s" % digest, "exit 0"], (
        "an approved commit must install the build, got %r" % lines)
    lines = session.link.exchange(
        "sha256sum %s/store/objects/%s" % (CONSOLE_STATE_DIR, digest))
    assert lines[-1] == "exit 0" and lines[0].split()[0] == digest, (
        "the installed object must hash to its digest, got %r" % lines)


def check_unsigned_commit(session, context):
    del context
    data = b"console unsigned\n"
    lines = session.push("consoleunsigned", data)
    staging, approval, _challenge = assert_staged(lines, "consoleunsigned", data)

    lines = session.grant(approval, "0" * 128)
    assert lines == ["signature_invalid", "exit 79"], (
        "a signature that is not the owner's must answer signature_invalid "
        "and exit 79, got %r" % lines)
    lines = session.commit(staging)
    assert lines == ["approval_required %s" % approval, "exit 75"], (
        "a commit without the owner's signature must stay refused, got %r"
        % lines)


def check_approval_status(session, context):
    """Status is a question: it needs no signature, and it survives the action."""
    del context
    data = b"console status\n"
    digest = hashlib.sha256(data).hexdigest()
    lines = session.push("consolestatus", data)
    staging, approval, challenge = assert_staged(lines, "consolestatus", data)

    assert session.status(approval) == [
        "approval_status %s pending" % approval, "exit 0"], (
        "a fresh approval must answer pending")

    session.request(approval, challenge, "consolestatus", len(data), digest)
    assert session.status(approval) == [
        "approval_status %s granted" % approval, "exit 0"], (
        "a granted approval must answer granted")

    lines = session.commit(staging)
    assert lines == ["installed consolestatus %s" % digest, "exit 0"], (
        "the granted approval must still commit the build, got %r" % lines)
    assert session.status(approval) == [
        "approval_status %s consumed" % approval, "exit 0"], (
        "a consumed approval must answer consumed")

    unknown = session.status("a-0")
    assert unknown == ["unknown_approval", "exit 1"], (
        "an id Ariel never issued must be an error, got %r" % unknown)


def check_read_only_relative(session, context):
    del context
    for command in ("cat notes.txt", "sha256sum notes.txt", "ls relative"):
        assert session.link.exchange(command) == ["relative_path", "exit 1"], (
            "%r must refuse a relative path" % command)


def check_read_only_on_console(session, context):
    del context
    for command in ("ls /", "stat /", "file /", "df /",
                    "ls %s" % CONSOLE_STATE_DIR,
                    "find %s" % CONSOLE_STATE_DIR):
        lines = session.link.exchange(command)
        assert lines and lines[-1] == "exit 0", (
            "%s must exit 0, got %r" % (command, lines))


def check_secrets_read_directly(session, context):
    del context
    for name in SECRET_FILES:
        path = "%s/%s" % (CONSOLE_STATE_DIR, name)
        for template in SECRET_READS:
            lines = session.link.exchange(template.format(p=path))
            assert lines == ["protected", "exit 87"], (
                "%s must answer protected and exit 87, got %r"
                % (template.format(p=path), lines))


def check_quick_start(session, context):
    # The check before this one pushed, and the console shows one
    # notification every 10 s. The fixture pushes at once and takes
    # approval_busy for a failure, so the gap is waited out here.
    session.operator.say(
        "The console allows one notification every 10 s; waiting.")
    session._sleep(NOTIFICATION_SPACING)
    quickstart.run_quick_start(
        doc_path=context.document,
        workdir=context.workdir,
        host=context.host,
        port=context.port,
        token=context.token,
        next_line=None,
        approve=None,
        notify=lambda approval_id, challenge, name, size, digest: (
            session.request(approval_id, challenge, name, size, digest)),
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


def check_audit_tail(session, context):
    """A push, a grant and a commit each land in the audit log, in that order."""
    del context
    data = b"console audit\n"
    digest = hashlib.sha256(data).hexdigest()
    lines = session.push("consoleaudit", data)
    staging, approval, challenge = assert_staged(lines, "consoleaudit", data)
    session.request(approval, challenge, "consoleaudit", len(data), digest)
    lines = session.commit(staging)
    assert lines == ["installed consoleaudit %s" % digest, "exit 0"], (
        "an approved commit must install the build, got %r" % lines)

    lines = session.link.exchange("audit tail")
    events = [line for line in lines if line != "exit 0"]
    assert lines and lines[-1] == "exit 0", (
        "audit tail must end with exit 0, got %r" % lines)
    for event in events:
        assert len(event.split()) == 5, (
            "expected '<ms> <kind> <name> <id> <sha256>', got %r" % event)

    # The console's log keeps earlier events: only this build's count.
    ours = [event for event in events if event.split()[3] in (staging, approval)]
    kinds = [event.split()[1] for event in ours]
    assert kinds == ["push", "grant", "commit"], (
        "audit tail must show the push, then the grant, then the commit, "
        "got %r" % ours)
    for event in ours:
        parts = event.split()
        assert parts[2] == "consoleaudit" and parts[4] == digest, (
            "the event must name the payload and its hash, got %r" % event)

    # Reading the log changes nothing, and no agent-port command clears it.
    assert session.link.exchange("audit tail") == lines, (
        "audit tail must not change the log it reads")
    for command in ("audit clear", "rm /data/ariel/audit.log"):
        refused = session.link.exchange(command)
        assert refused and refused[-1] != "exit 0", (
            "%r must not succeed, got %r" % (command, refused))
    assert session.link.exchange("audit tail") == lines, (
        "no agent-port command may change the audit log")


def check_kill_refusals(session, context):
    del context
    link = session.link
    assert link.exchange("kill 99999999 NOPE") == ["bad_signal", "exit 1"]
    assert link.exchange("kill 99999999 TERM") == ["no_such_process", "exit 1"]
    assert link.exchange("kill x TERM") == ["unknown_command", "exit 1"]
    lines = link.exchange("ps")
    shells = [line.split() for line in lines[1:-1]
              if line.split() and line.split()[-1] == "SceShellCore"]
    assert shells, "the console must list SceShellCore, got %r" % lines
    pid = shells[0][0]
    assert link.exchange("kill %s TERM" % pid) == ["protected", "exit 87"], (
        "SceShellCore must be refused with exit 87")


def check_http2_get_refusal(session, context):
    del context
    link = session.link
    lines = link.exchange("http2_get http://localhost:1/file")
    assert lines == ["not_allowlisted", "exit 1"], (
        "a host the console allowlist does not name must be refused, got %r"
        % lines)


def check_env_export_exec_refusals(session, context):
    del context
    link = session.link
    assert link.exchange("env A=B") == ["bad_name", "exit 1"]
    assert link.exchange("export 9X=1") == ["bad_name", "exit 1"]
    assert link.exchange("exec relative/prog") == ["relative_path", "exit 1"]
    assert link.exchange("exec /data/gate-missing") == [
        "no_such_file", "exit 1"]
    assert link.exchange("exec %s/token" % CONSOLE_STATE_DIR) == [
        "protected", "exit 87"], "the console's token must be refused with exit 87"
    kinds = {line.split()[1] for line in link.exchange("audit tail")
             if len(line.split()) == 5}
    for kind in ("env.refused", "export.refused", "exec.refused",
                 "exec.protected"):
        assert kind in kinds, "audit tail must show %s, got %r" % (
            kind, sorted(kinds))


def check_inspection_commands(session, context):
    del context
    link = session.link
    assert link.exchange("echo hello from ariel") == ["hello from ariel", "exit 0"]
    assert link.exchange("sync") == ["exit 0"]
    assert link.exchange("sleep 0") == ["exit 0"]
    assert link.exchange("sleep") == ["missing_operand", "exit 1"]
    assert link.exchange("sleep 61") == ["bad_duration", "exit 1"]
    lines = link.exchange("id")
    assert lines[-1] == "exit 0" and lines[0].startswith("uid="), (
        "id must print the user and group, got %r" % lines)
    lines = link.exchange("ps")
    assert lines[-1] == "exit 0" and lines[0].split()[0] == "PID", (
        "ps must print a header and exit 0, got %r" % lines)
    rows = [line.split() for line in lines[1:-1]]
    assert rows, "ps must list the console's processes"
    lines = link.exchange("procstat %s" % rows[0][0])
    assert lines[-1] == "exit 0", "procstat must exit 0, got %r" % lines
    assert link.exchange("procstat") == ["missing_operand", "exit 1"]
    lines = link.exchange("sysctl kern.ostype")
    assert lines[-1] == "exit 0" and lines[0].startswith("00000000"), (
        "sysctl must print a hexdump and exit 0, got %r" % lines)
    assert link.exchange("sum relative") == ["relative_path", "exit 1"]
    assert link.exchange("sfoinfo relative") == ["relative_path", "exit 1"]
    lines = link.exchange("authid")
    assert lines[-1] == "exit 0" and lines[0].startswith("0x"), (
        "authid must print the console's authid and exit 0, got %r" % lines)
    lines = link.exchange("sysctl kern.ostype=Other")
    assert lines[:-1] == ["unknown_command"] and lines[-1] != "exit 0", (
        "a sysctl write must be refused, got %r" % lines)


def check_background_refusals(session, context):
    del context
    for command, expected in (
        ("payload run bgnosuch", ["unknown_payload", "exit 1"]),
        ("payload logs bgnosuch", ["unknown_payload", "exit 1"]),
        ("payload run ../escape", ["bad_name", "exit 1"]),
    ):
        lines = session.link.exchange(command)
        assert lines == expected, (
            "%r must answer %r, got %r" % (command, expected, lines))


# Every check console mode runs. Each is a scenario that needs no test clock.
def autoload_listing(session):
    return session.link.exchange("autoload show")


def autoload_ask(session, op, name):
    """Ask for an autoload edit and return its approval ID and challenge."""
    session.operator.pause(NOTIFICATION_SPACING)
    lines = session.link.exchange("autoload edit %s %s" % (op, name))
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "an autoload edit without a grant must answer 75, got %r" % lines)
    approval = APPROVAL_LINE.match(lines[0])
    assert approval, "expected 'approval_required <id>', got %r" % lines[0]
    assert lines[1].startswith("challenge %s " % approval.group(1)), (
        "expected the challenge for the approval, got %r" % lines[1])
    return approval.group(1), lines[1]


def autoload_notification(approval, op, name, listing):
    """The notification the console shows for an edit asked of this listing."""
    names = [line[len("autoload "):] for line in listing
             if line.startswith("autoload ")]
    text = "".join(entry + "\n" for entry in names)
    digest = hashlib.sha256(text.encode("ascii")).hexdigest()
    return ("prompt %s autoload.%s %s (list sha256 %s) will change autoload"
            % (approval, op, name, digest))


def autoload_approve(session, op, name):
    """The owner's step for an autoload edit: ask, sign, grant; return the ID."""
    listing = autoload_listing(session)
    approval, challenge = autoload_ask(session, op, name)
    notification = autoload_notification(approval, op, name, listing)
    signature = session.operator.sign(name, notification, challenge)
    lines = session.grant(approval, signature)
    assert lines == ["approval_granted %s" % approval, "exit 0"], (
        "the owner's signature must decide the autoload edit, got %r" % lines)
    return approval


def autoload_apply(session, op, name, approval):
    return session.link.exchange("autoload edit %s %s %s" % (op, name, approval))


def autoload_remove(session, name):
    """Take an entry this check added back out of the console's list."""
    approval = autoload_approve(session, "remove", name)
    assert autoload_apply(session, "remove", name, approval) == [
        "autoload remove %s" % name, "exit 0"], (
        "the cleanup of %s must remove it" % name)


def install_build(session, name, data):
    """Push, approve and commit one build, and return its digest."""
    digest = hashlib.sha256(data).hexdigest()
    lines = session.push(name, data)
    staging, approval, challenge = assert_staged(lines, name, data)
    session.request(approval, challenge, name, len(data), digest)
    lines = session.commit(staging)
    assert lines == ["installed %s %s" % (name, digest), "exit 0"], (
        "an approved commit must install the build, got %r" % lines)
    return digest


def check_rollback_restores_previous(session, context):
    """A rollback waits for the owner, then restores the previous build and is audited."""
    del context
    name = "rollb" + uuid.uuid4().hex[:8]
    previous = install_build(session, name, b"console rollback first\n")
    current = install_build(session, name, b"console rollback second\n")

    lines = session.rollback(name)
    assert len(lines) == 3 and lines[2] == "exit 75", (
        "a rollback without a grant must answer approval_required and exit 75, "
        "got %r" % lines)
    approval = APPROVAL_LINE.match(lines[0])
    assert approval, "expected 'approval_required <id>', got %r" % lines[0]
    notification = ("prompt %s payload %s rolls back to %s, replacing %s"
                    % (approval.group(1), name, previous, current))
    session.decide(approval.group(1), lines[1], name, notification)

    lines = session.rollback(name)
    assert lines == ["rolled_back %s %s" % (name, previous), "exit 0"], (
        "a granted rollback must restore the previous build, got %r" % lines)

    listing = [line for line in session.link.exchange("payload list")
               if line.startswith("payload %s " % name)]
    assert len(listing) == 1 and ("sha256=%s" % previous) in listing[0] and (
        "previous=%s" % current) in listing[0], (
        "the previous build must be listed as current, got %r" % listing)

    events = [line.split() for line in session.link.exchange("audit tail")
              if line != "exit 0"]
    assert ["rollback_done", name, approval.group(1)] in [
        event[1:4] for event in events], (
        "the completed rollback must be audited as rollback_done, got %r"
        % events)


def check_rollback_refusals(session, context):
    """A payload with no previous build and an unknown name answer their words."""
    del context
    name = "rollfirst" + uuid.uuid4().hex[:8]
    install_build(session, name, b"console rollback only build\n")

    lines = session.rollback(name)
    assert lines == ["no_previous_version", "exit 1"], (
        "a payload with no previous version must answer no_previous_version, "
        "got %r" % lines)
    lines = session.rollback("rollnone" + uuid.uuid4().hex[:8])
    assert lines == ["unknown_payload", "exit 1"], (
        "a rollback of an unknown payload must answer unknown_payload, got %r"
        % lines)


def install_autoload_payload(session, name, data):
    install_build(session, name, data)


def check_autoload_show(session, context):
    """autoload show lists the console's entries, Ariel first, and writes nothing."""
    del context
    before = session.link.exchange("audit tail")
    lines = autoload_listing(session)
    assert lines and lines[0] == "autoload ariel" and lines[-1] == "exit 0", (
        "autoload show must list ariel first and end with exit 0, got %r"
        % lines)
    assert session.link.exchange("audit tail") == before, (
        "autoload show is read-only and must not audit anything")


def check_autoload_edit_asks_before_it_applies(session, context):
    """An autoload edit without a grant answers 75 and the list does not change."""
    del context
    name = "consoleasks"
    before = autoload_listing(session)
    autoload_ask(session, "add", name)
    assert autoload_listing(session) == before, (
        "an edit that was asked for must not be applied before its grant")


def check_reboot_asks_the_owner(session, context):
    """reboot without a grant answers 75 and asks the owner, and restarts nothing."""
    del context
    lines = session.link.exchange("reboot")
    assert lines and lines[-1] == "exit 75" and APPROVAL_LINE.match(lines[0]), (
        "reboot without a grant must answer approval_required and exit 75, "
        "got %r" % lines)
    assert not any(line.startswith("rebooting") for line in lines), (
        "a reboot without a grant must not restart the console")


def check_autoload_edit_applies_after_grant(session, context):
    """A granted autoload add is applied, shown by autoload show and audited."""
    del context
    name = "consoleboot"
    install_autoload_payload(session, name, b"console boot\n")
    approval = autoload_approve(session, "add", name)
    try:
        assert autoload_apply(session, "add", name, approval) == [
            "autoload add %s" % name, "exit 0"], "a granted autoload add must apply"
        assert "autoload %s" % name in autoload_listing(session), (
            "autoload show must list the added entry")

        kinds = [line.split()[1] for line in session.link.exchange("audit tail")
                 if line.split()[3:4] == [approval]]
        assert kinds == ["grant", "autoload_add"], (
            "the grant and the applied edit must both be audited, got %r"
            % kinds)

        assert session.link.exchange("autoload edit add %s" % name) == [
            "already_in_autoload", "exit 1"], (
            "adding a name that is already listed must be refused")
    finally:
        autoload_remove(session, name)


def check_autoload_pins_ariel(session, context):
    """Ariel cannot be removed from the list: the edit is refused and audited."""
    del context
    assert session.link.exchange("autoload edit remove ariel") == [
        "ariel_pinned", "exit 1"], "removing ariel must be refused"
    assert "autoload ariel" in autoload_listing(session), (
        "a refused removal must leave ariel in the list")
    refused = [line.split() for line in session.link.exchange("audit tail")
               if line.split()[1:4] == ["refuse", "ariel", "ariel_pinned"]]
    assert refused, "the refused removal must be audited"


def check_autoload_refusals_answer_their_words(session, context):
    """Unknown and absent names are refused with their own words, unsigned."""
    del context
    assert session.link.exchange("autoload edit add consoleghost") == [
        "unknown_payload", "exit 1"], "adding a payload that is not installed"
    assert session.link.exchange("autoload edit remove consolemissing") == [
        "not_in_autoload", "exit 1"], "removing a name that is not listed"


def check_autoload_stale_grant_answers_78(session, context):
    """A grant for a list that has since changed answers approval_stale, 78."""
    del context
    first, second = "consolestale", "consoleother"
    install_autoload_payload(session, second, b"console other\n")
    listing = autoload_listing(session)
    stale, challenge = autoload_ask(session, "add", first)
    try:
        other = autoload_approve(session, "add", second)
        assert autoload_apply(session, "add", second, other) == [
            "autoload add %s" % second, "exit 0"], "the other edit must apply"

        notification = autoload_notification(stale, "add", first, listing)
        signature = session.operator.sign(first, notification, challenge)
        lines = session.grant(stale, signature)
        assert lines == ["approval_granted %s" % stale, "exit 0"], (
            "the owner's signature must decide the stale edit, got %r" % lines)
        assert autoload_apply(session, "add", first, stale) == [
            "approval_stale", "exit 78"], "a grant for an older list is stale"
        assert "autoload %s" % first not in autoload_listing(session), (
            "a stale grant must not change the list")
    finally:
        autoload_remove(session, second)


CHECKS = [
    ("missing auth closes with exit 70", check_missing_auth),
    ("a line over 1 KiB closes the connection", check_line_limit),
    ("a wrong token closes with exit 70", check_wrong_token),
    ("a command outside the set asks the owner first and never answers "
     "unknown_command", check_unknown_command),
    ("on the console, writes outside /data, /user and /mnt/usb* answer "
     "protected and exit 87 without asking", check_protected_without_asking),
    ("tar refuses a relative, protected or missing archive on the console "
     "without asking", check_tar_refusals_without_asking),
    ("mkdir and rmdir run only after the owner signs, once each, on the console",
     check_file_command_runs_after_approval),
    ("a truncated upload answers upload_mismatch and exit 81",
     check_truncated_upload),
    ("a hash mismatch answers upload_mismatch and exit 81",
     check_hash_mismatch),
    ("a name outside the grammar answers bad_name", check_bad_name),
    ("an install with a name outside the grammar answers bad_name and is "
     "audited", check_install_bad_name_is_audited),
    ("a commit of an unknown staging ID answers approval_stale, exit 78, and "
     "is audited", check_commit_stale_is_audited),
    ("a commit before the decision answers approval_required and exit 75, the "
     "owner signs the challenge, and the commit installs the build",
     check_approval_then_install),
    ("a grant that is not the owner's signature answers signature_invalid "
     "and the commit stays refused", check_unsigned_commit),
    ("after a push, a grant and a commit, audit tail shows each one in order "
     "and no agent-port command can clear the log", check_audit_tail),
    ("a payload rollback answers 75, the owner signs it, and the previous build "
     "is listed as current and audited as rollback_done",
     check_rollback_restores_previous),
    ("a payload rollback with no previous version answers no_previous_version "
     "and an unknown name unknown_payload, both with exit 1",
     check_rollback_refusals),
    ("approval status answers pending, granted and consumed without an "
     "approval of its own, and an unknown id is an error",
     check_approval_status),
    ("autoload show lists the entries, Ariel first, and writes nothing",
     check_autoload_show),
    ("an autoload edit without a grant answers 75 and leaves the list as it "
     "was", check_autoload_edit_asks_before_it_applies),
    ("a granted autoload add is applied, shown by autoload show and audited",
     check_autoload_edit_applies_after_grant),
    ("autoload edit remove ariel is refused with ariel_pinned and audited",
     check_autoload_pins_ariel),
    ("autoload refuses an unknown payload and an absent entry with their words",
     check_autoload_refusals_answer_their_words),
    ("a stale autoload grant answers approval_stale, 78, and leaves the list "
     "as it was", check_autoload_stale_grant_answers_78),
    ("a read-only command with a relative path answers relative_path and "
     "exit 1", check_read_only_relative),
    ("kill with a bad signal, a bad pid or no such process answers an "
     "error and exit 1, and SceShellCore is refused with exit 87",
     check_kill_refusals),
    ("http2_get off the console allowlist is refused with not_allowlisted "
     "and exit 1, without asking",
     check_http2_get_refusal),
    ("env, export and exec refuse a bad name, a relative or missing path and "
     "the token without asking, and audit each refusal",
     check_env_export_exec_refusals),
    ("reboot answers 75 with a challenge and restarts nothing without a grant",
     check_reboot_asks_the_owner),
    ("the read-only commands on the console's root and data directory exit 0",
     check_read_only_on_console),
    ("the token, approval state and nonces answer protected and exit 87 when "
     "read directly on the console", check_secrets_read_directly),
    ("a run of a missing path answers no_such_file and exit 1, and a run of "
     "Ariel's token answers protected and exit 87, both without asking",
     check_run_refusals),
    ("a background run or logs of an unknown payload, and a run of a bad "
     "name, answer their word and exit 1", check_background_refusals),
    ("the quick start's 'After Stage 1' section passes against the console",
     check_quick_start),
    ("the inspection commands run with no approval and answer their output",
     check_inspection_commands),
]


def skip_reason(clock):
    """A scenario's clock flag is True for the test clock, or a reason string."""
    return clock if isinstance(clock, str) else CLOCK_REASON


def plan_lines(host, scenarios):
    """The selection console mode makes, without touching the console."""
    lines = [BANNER % (host, PORT)]
    lines += ["run  " + title for title, _check in CHECKS]
    lines += ["skip %s (%s)" % (title, skip_reason(clock))
              for title, _check, clock in scenarios if clock]
    lines.append("console mode is not part of CI or of the Stage 1 gate.")
    return lines


def run(host, scenarios, operator=None, connect=None):
    """Run every console check and return its results."""
    operator = operator or Operator()
    token = operator.token(host)
    cc = prospero_clang()
    workdir = tempfile.mkdtemp(prefix="ariel-console-")
    link = Link(host, PORT, token, connect=connect)
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

    skipped = [(title, clock) for title, _check, clock in scenarios if clock]
    print("\nskipped %d scenario(s):" % len(skipped))
    for title, clock in skipped:
        print("  %s (%s)" % (title, skip_reason(clock)))
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
