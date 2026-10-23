#!/usr/bin/env python3
"""Run the 'After Stage 1' section of docs/quick-start.md as an acceptance fixture.

The fixture reads the section, not a copy of it: every `$` block is sent as
written after substituting the access token, the host, the port and the
staging ID captured from an earlier reply. Each 'Approve it on the console'
step becomes an approval on the virtual controller. Expected output is
matched line by line, with `s-...`/`a-...` IDs and hashes as placeholders.

The blocks share one shell, so the documented `export ARIEL_TOKEN` is what
every later block uses: a token preloaded into the environment or a setup
command that failed would hide a broken tutorial. Every command must also
exit 0.

The fixture is driven only through the agent port. It builds helloworld.elf
from the C source in the same document with the host compiler.
"""

import hashlib
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid

STAGING_ID = re.compile(r"(?<![0-9a-z])s-[0-9a-f]+(?![0-9a-z])")
APPROVAL_ID = re.compile(r"(?<![0-9a-z])a-[0-9a-f]+(?![0-9a-z])")
ANY_ID = re.compile(r"(?<![0-9a-z])[sa]-[0-9a-f]+(?![0-9a-z])")
HASH = re.compile(r"(?<![0-9a-f])[0-9a-f]{6,}(?:\.\.\.)?(?![0-9a-f])")
APPROVAL_REPLY = re.compile(r"^approval_required (a-[0-9a-f]+)$")
PROMPT = re.compile(
    r"^prompt (a-[0-9a-f]+) payload (\S+) \((\d+) bytes, sha256 ([0-9a-f]{64})\)"
    r" will run$"
)
ERROR = re.compile(r"(invalid|illegal|unknown) option", re.I)

SECTION = "## After Stage 1"
DOCUMENTED_PORT = 2324
APPROVE_STEP = "Approve it on the console"
TOKEN_PLACEHOLDER = "<token shown on the console>"
TAIL = [
    "Hello, world from Ariel!",
    "argv[1] = one",
    "argv[2] = two",
    "status 0",
    "exit 0",
]


class FixtureError(AssertionError):
    """The quick start and the server disagree, or the section is malformed."""


def after_stage1(text):
    """Return the text of the 'After Stage 1' section, without its heading."""
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if line.strip() == SECTION:
            break
    else:
        raise FixtureError("docs/quick-start.md has no '%s' section" % SECTION)

    body = []
    for line in lines[index + 1:]:
        if line.startswith("## "):
            break
        body.append(line)
    return "\n".join(body)


def parse_items(section):
    """Split a section into prose and console blocks, in document order."""
    items = []
    prose = []
    lines = section.split("\n")
    index = 0

    while index < len(lines):
        line = lines[index]
        if line.startswith("```"):
            if prose:
                items.append(("prose", "\n".join(prose).strip()))
                prose = []
            tag = line[3:].strip()
            body = []
            index += 1
            while index < len(lines) and not lines[index].startswith("```"):
                body.append(lines[index])
                index += 1
            index += 1
            # Every block that holds a `$` command runs, whatever its label.
            if tag == "console" or any(l.startswith("$ ") for l in body):
                items.append(("console", body))
            continue
        prose.append(line)
        index += 1

    if prose:
        items.append(("prose", "\n".join(prose).strip()))
    return items


def parse_command(block):
    """Split one console block into its command and its expected output."""
    command = None
    expected = []
    index = 0

    while index < len(block):
        line = block[index]
        if line.startswith("$ "):
            if command is not None:
                raise FixtureError("a console block holds more than one command")
            parts = [line[2:]]
            while parts[-1].rstrip().endswith("\\") and index + 1 < len(block):
                index += 1
                parts.append(block[index])
            command = "\n".join(parts)
        else:
            expected.append(line)
        index += 1

    if command is None:
        raise FixtureError("a console block holds no '$' command")
    return command, expected


def normalize(line):
    """Replace IDs and hashes with placeholders so only behavior is compared."""
    line = ANY_ID.sub("<id>", line)
    return HASH.sub("<hash>", line)


def trim(lines):
    lines = [line.rstrip("\r") for line in lines]
    while lines and lines[-1] == "":
        lines.pop()
    while lines and lines[0] == "":
        lines.pop(0)
    return lines


def compare(expected, actual):
    expected = trim(expected)
    actual = trim(actual)

    if len(expected) != len(actual):
        raise FixtureError(
            "expected %d output lines, got %d:\nexpected %r\nactual   %r"
            % (len(expected), len(actual), expected, actual)
        )

    for number, (want, got) in enumerate(zip(expected, actual), start=1):
        if normalize(want) != normalize(got):
            raise FixtureError(
                "line %d: expected %r, got %r" % (number, want, got))


def placeholders(expected, actual):
    """Map the document's ID placeholders to the IDs the server answered."""
    mapping = {}

    for want, got in zip(trim(expected), trim(actual)):
        wanted = ANY_ID.findall(want)
        answered = ANY_ID.findall(got)
        if len(wanted) == len(answered):
            for before, after in zip(wanted, answered):
                mapping.setdefault(before, after)
    return mapping


def substitute(command, token, host, port, ids):
    command = command.replace(TOKEN_PLACEHOLDER, token)
    command = command.replace("${PS5_HOST}", host)
    command = command.replace("$PS5_HOST", host)
    # The section names the agent port's documented default; the fixture
    # talks to the port the server actually listens on.
    command = re.sub(r"(?<![0-9])%d(?![0-9])" % DOCUMENTED_PORT,
                     str(port), command)
    for before, after in ids.items():
        command = re.sub(
            r"(?<![0-9a-z])%s(?![0-9a-z])" % re.escape(before), after, command)
    return command


class Shell:
    """One shell whose state survives every documented block.

    A fresh `bash -c` per block would lose the documented `export`, and a
    token injected into the environment would hide a broken export. Each
    block's output goes to a temporary file; a marker line on the shell's
    own standard output carries the block's exit status, so a setup command
    that failed is never taken for success.
    """

    def __init__(self, cwd, env):
        self.proc = subprocess.Popen(
            ["bash", "--noprofile", "--norc"],
            cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.marker = "ariel-quickstart-" + uuid.uuid4().hex
        self.count = 0
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._pump, daemon=True)
        self.reader.start()

    def _pump(self):
        for raw in self.proc.stdout:
            self.lines.put(raw)
        self.lines.put(None)

    def run(self, command, timeout=30.0):
        """Run one block and return its exit status, output and errors."""
        self.count += 1
        marker = "%s-%d" % (self.marker, self.count)
        handle, out_path = tempfile.mkstemp(prefix="ariel-block-")
        os.close(handle)
        err_path = out_path + ".err"
        script = ("{\n%s\n} > %s 2> %s\nprintf '%%s %%d\\n' %s \"$?\"\n"
                  % (command, shlex.quote(out_path), shlex.quote(err_path),
                     shlex.quote(marker)))

        try:
            self.proc.stdin.write(script.encode("utf-8"))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise FixtureError(
                "the shell ended before the block could run: %s"
                % command.split("\n")[0])

        status = None
        while status is None:
            try:
                raw = self.lines.get(timeout=timeout)
            except queue.Empty:
                raise FixtureError(
                    "the command did not finish: %s" % command.split("\n")[0])
            if raw is None:
                raise FixtureError(
                    "the shell ended while the command ran: %s"
                    % command.split("\n")[0])
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith(marker + " "):
                status = int(line[len(marker) + 1:])

        with open(out_path, "rb") as output:
            lines = output.read().decode("utf-8", "replace").split("\n")
        with open(err_path, "rb") as errors:
            stderr = errors.read().decode("utf-8", "replace").strip()
        os.unlink(out_path)
        os.unlink(err_path)
        return status, lines, stderr

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def hello_source(text):
    match = re.search(r"```c\n(.*?)```", text, re.S)
    if not match:
        raise FixtureError("docs/quick-start.md has no C source for helloworld")
    return match.group(1)


def build_hello(text, workdir, cc=None):
    """Build helloworld.elf from the document with the given compiler."""
    with open(os.path.join(workdir, "hello.c"), "w") as handle:
        handle.write(hello_source(text))

    compiler = list(cc) if cc else [os.environ.get("CC", "cc")]
    result = subprocess.run(
        compiler + ["-Wall", "-Werror", "-o", "helloworld.elf", "hello.c"],
        cwd=workdir, capture_output=True,
    )
    if result.returncode:
        raise FixtureError(
            "cannot build helloworld.elf: %s"
            % result.stderr.decode("utf-8", "replace").strip()
        )


def nc_flags(real):
    """Close the sending side at end of input, as the section tells readers.

    macOS nc does that by default. Linux nc needs -N, as the section says.
    """
    if sys.platform == "darwin":
        return []

    probe = subprocess.run([real, "-N", "-h"], capture_output=True)
    text = (probe.stdout + probe.stderr).decode("utf-8", "replace")
    return [] if ERROR.search(text) else ["-N"]


def nc_path(env):
    """Put an `nc` wrapper first on PATH; the section calls plain `nc`."""
    real = shutil.which("nc")
    if not real:
        raise FixtureError("the quick start needs nc on PATH")

    bindir = tempfile.mkdtemp(prefix="ariel-nc-")
    wrapper = os.path.join(bindir, "nc")
    flags = " ".join(nc_flags(real))
    with open(wrapper, "w") as handle:
        handle.write("#!/bin/sh\nexec %s%s \"$@\"\n"
                     % (shlex.quote(real), (" " + flags) if flags else ""))
    os.chmod(wrapper, 0o755)
    env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    return wrapper


def run_quick_start(doc_path, workdir, host, port, token, next_line, approve,
                    notify=None, cc=None):
    """Drive the section against one server. Raises FixtureError on a mismatch.

    With `notify`, the owner approves on a real console instead: the callback
    receives the approval ID, the payload name, its size and its hash, shows
    the notification the console displays, and waits for the owner's decision.
    The prompt is then not read from a server's standard output.
    """
    with open(doc_path) as handle:
        text = handle.read()

    section = after_stage1(text)
    build_hello(text, workdir, cc)

    with open(os.path.join(workdir, "helloworld.elf"), "rb") as handle:
        elf = handle.read()
    elf_hash = hashlib.sha256(elf).hexdigest()

    env = os.environ.copy()
    env["PS5_HOST"] = host
    # The token must come from the section's own export, never from the
    # harness: a wrong documented token has to break the fixture.
    env.pop("ARIEL_TOKEN", None)
    nc_path(env)

    shell = Shell(workdir, env)
    ids = {}
    pending = None
    push_name = None
    run_output = None
    approvals = 0
    runs = 0

    try:
        for kind, body in parse_items(section):
            if kind == "prose":
                if APPROVE_STEP not in body:
                    continue

                if pending is None:
                    raise FixtureError(
                        "the section approves on the console with nothing "
                        "pending")

                if notify is not None:
                    if push_name is None:
                        raise FixtureError(
                            "the section approves on the console before a push")
                    notify(pending, push_name, len(elf), elf_hash)
                else:
                    line = next_line()
                    match = PROMPT.match(line or "")
                    if not match:
                        raise FixtureError(
                            "expected the approval prompt, got %r" % line)
                    if match.group(1) != pending:
                        raise FixtureError(
                            "the prompt names %s but the push staged %s"
                            % (match.group(1), pending))
                    if push_name is not None and match.group(2) != push_name:
                        raise FixtureError(
                            "the prompt names %r, not %r"
                            % (match.group(2), push_name))
                    if int(match.group(3)) != len(elf):
                        raise FixtureError(
                            "the prompt says %s bytes, not %d"
                            % (match.group(3), len(elf)))
                    if match.group(4) != elf_hash:
                        raise FixtureError("the prompt shows the wrong hash")

                    approve(pending)
                approvals += 1
                pending = None
                continue

            command, expected = parse_command(body)
            command = substitute(command, token, host, port, ids)

            pushed = re.search(r"payload push (\S+)", command)
            if pushed:
                push_name = pushed.group(1)

            status, actual, stderr = shell.run(command)
            if status != 0:
                raise FixtureError(
                    "the command exited %d: %s%s"
                    % (status, command.split("\n")[0],
                       ("\n" + stderr) if stderr else ""))
            compare(expected, actual)
            ids.update(placeholders(expected, actual))

            for line in trim(actual):
                match = APPROVAL_REPLY.match(line)
                if match:
                    pending = match.group(1)

            if "payload run --wait" in command:
                runs += 1
                run_output = trim(actual)
    finally:
        shell.close()

    if approvals != 1:
        raise FixtureError(
            "the section must approve exactly once, it approves %d times"
            % approvals)
    if runs != 1:
        raise FixtureError(
            "the section must run the payload exactly once, it runs %d times"
            % runs)
    if run_output[-len(TAIL):] != TAIL:
        raise FixtureError(
            "the fixture must end with %r, got %r" % (TAIL, run_output))
