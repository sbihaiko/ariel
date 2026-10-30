#!/usr/bin/env python3
"""Headless acceptance for ariel-mcp, driven over stdio as a client does.

Starts the host build of Ariel on a loopback port and the host-built server as
child processes. The server talks to that Ariel over the agent port; every
answer is what a binary wrote to the wire. No stub stands in for the protocol
or for the console.

Usage: mcp_acceptance.py [./ariel-mcp [./ariel-host]]
"""

import base64
import hashlib
import json
import os
import queue
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

import acceptance

PROTOCOL_REVISION = "2026-07-28"
DEFAULT_PORT = 2324
# Every setting the server reads from the environment; a scenario starts from
# none of them, so a developer's shell cannot change what is measured.
CONFIG_VARS = ("PS5_HOST", "ARIEL_TOKEN", "ARIEL_PORT", "ARIEL_TIMEOUT",
               "ARIEL_ENV_FILE")
INIT_PARAMS = {
    "protocolVersion": PROTOCOL_REVISION,
    "capabilities": {},
    "clientInfo": {"name": "acceptance", "version": "0"},
}
results = []


class ServerExited(AssertionError):
    """The server ended before it answered; the message carries its own words."""


def check(name, fn):
    try:
        fn()
    except Exception as err:  # noqa: BLE001 - a failed scenario is a report
        results.append((name, False))
        print("FAIL %s: %s: %s" % (name, type(err).__name__, err))
    else:
        results.append((name, True))
        print("PASS %s" % name)


def environment(extra=None):
    env = {key: value for key, value in os.environ.items()
           if key not in CONFIG_VARS}
    env.update(extra or {})
    return env


def run(binary, args, env=None, timeout=30):
    return subprocess.run(
        [binary] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment() if env is None else env, timeout=timeout)


def console_args(console, token=None):
    return ["--host", "127.0.0.1", "--port", str(console.port),
            "--token", console.token if token is None else token]


def wrong_token(token):
    return ("0" if token[0] != "0" else "1") + token[1:]


def closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def write_env_file(directory, text):
    path = os.path.join(directory, "ariel.env")
    with open(path, "w") as handle:
        handle.write(text)
    return path


def one_line(text):
    lines = text.strip().splitlines()
    assert len(lines) == 1, "expected one line, got %r" % text
    return lines[0]


class McpClient:
    """A client that writes one JSON-RPC object per line and reads one per line."""

    def __init__(self, binary, args):
        self.proc = subprocess.Popen(
            [binary] + list(args), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment())
        self.lines = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for raw in self.proc.stdout:
            self.lines.put(raw.decode("utf-8", "replace").rstrip("\r\n"))
        self.lines.put(None)

    def _write(self, message):
        try:
            self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except BrokenPipeError:
            raise self.exited()

    def notify(self, method):
        self._write({"jsonrpc": "2.0", "method": method})

    def request(self, id_, method, params=None, timeout=15.0):
        message = {"jsonrpc": "2.0", "id": id_, "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError("the server gave no reply within %d s" % timeout)
        if line is None:
            raise self.exited()
        reply = json.loads(line)
        assert reply.get("id") == id_, reply
        return reply

    def exited(self):
        code = self.proc.wait(timeout=10)
        err = self.proc.stderr.read().decode("utf-8", "replace").strip()
        word = err.splitlines()[-1] if err else "no word on its standard error"
        return ServerExited("the server exited %d: %s" % (code, word))

    def close(self):
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def session(binary, console, lines):
    """Run the server with lines on stdin and return its parsed replies.

    A str item is sent verbatim, so a test can send text that is not JSON.
    """
    payload = "".join(
        (line if isinstance(line, str) else json.dumps(line)) + "\n"
        for line in lines)
    proc = subprocess.run(
        [binary] + console_args(console), input=payload.encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment(),
        timeout=30)
    out = proc.stdout.decode()
    replies = [json.loads(text) for text in out.splitlines() if text.strip()]
    return replies, proc


def request(id_, method, params=None):
    message = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        message["params"] = params
    return message


INITIALIZE = request(1, "initialize", INIT_PARAMS)


def scenario_initialize_names_the_revision_and_server(binary, console):
    replies, _ = session(binary, console, [INITIALIZE])
    assert len(replies) == 1, replies
    result = replies[0]["result"]
    assert result["protocolVersion"] == PROTOCOL_REVISION, result
    assert result["serverInfo"]["name"] == "ariel", result
    assert result["serverInfo"]["version"], result
    assert "tools" in result["capabilities"], result


def scenario_second_initialize_is_refused(binary, console):
    replies, _ = session(binary, console, [INITIALIZE, request(2, "initialize", INIT_PARAMS)])
    assert len(replies) == 2, replies
    assert replies[1].get("id") == 2, replies[1]
    assert "error" in replies[1], replies[1]


def scenario_notification_is_silent_and_ping_answers(binary, console):
    replies, _ = session(binary, console, [
        INITIALIZE,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request(3, "ping"),
    ])
    assert len(replies) == 2, replies
    assert replies[1] == {"jsonrpc": "2.0", "id": 3, "result": {}}, replies[1]


def scenario_unknown_method_answers_32601(binary, console):
    replies, _ = session(binary, console, [INITIALIZE, request(5, "resources/list")])
    error = replies[1]["error"]
    assert error["code"] == -32601, replies[1]
    assert replies[1]["id"] == 5, replies[1]


def scenario_malformed_arguments_answer_32602(binary, console):
    replies, _ = session(binary, console, [
        INITIALIZE, request(6, "tools/call", {"arguments": {}})])
    error = replies[1]["error"]
    assert error["code"] == -32602, replies[1]
    assert replies[1]["id"] == 6, replies[1]


# Issue #143: one table defines the surface. The read rows are named here from
# the SPEC, not read back from the server, with the argument keys each takes.
READ_ROWS = [
    ("ariel_ls", ["path"]),
    ("ariel_cat", ["path"]),
    ("ariel_stat", ["path"]),
    ("ariel_df", ["path"]),
    ("ariel_find", ["path"]),
    ("ariel_file", ["path"]),
    ("ariel_head", ["path"]),
    ("ariel_tail", ["path"]),
    ("ariel_wc", ["path"]),
    ("ariel_du", ["path"]),
    ("ariel_pwd", []),
    ("ariel_sysinfo", []),
    ("ariel_sysctl", ["name"]),
    ("ariel_ps", []),
    ("ariel_procstat", ["pid"]),
    ("ariel_dmesg", []),
    ("ariel_ifconfig", []),
    ("ariel_ping", ["address"]),
    ("ariel_read", ["path", "offset", "limit", "local_path"]),
    ("ariel_autoload_show", []),
]
# Paths are absolute on the host, so fixtures live under the harness's root and
# the arguments name them by "{root}".
READ_CALLS = {
    "ariel_ls": {"path": "{root}/mcp-read"},
    "ariel_cat": {"path": "{root}/mcp-read/hello.txt"},
    "ariel_stat": {"path": "{root}/mcp-read/hello.txt"},
    "ariel_df": {"path": "{root}/mcp-read"},
    "ariel_find": {"path": "{root}/mcp-read"},
    "ariel_file": {"path": "{root}/mcp-read/hello.txt"},
    "ariel_head": {"path": "{root}/mcp-read/hello.txt"},
    "ariel_tail": {"path": "{root}/mcp-read/hello.txt"},
    "ariel_wc": {"path": "{root}/mcp-read/hello.txt"},
    "ariel_du": {"path": "{root}/mcp-read"},
    "ariel_pwd": {},
    "ariel_sysinfo": {},
    "ariel_sysctl": {"name": "kern.ostype"},
    "ariel_ps": {},
    "ariel_procstat": {"pid": 1},
    "ariel_dmesg": {},
    "ariel_ifconfig": {},
    "ariel_ping": {"address": "127.0.0.1", "count": 1, "wait": 200},
    "ariel_read": {"path": "{root}/mcp-read/hello.txt",
                   "local_path": "{root}/mcp-read/hello.copy"},
    "ariel_autoload_show": {},
}


def listed_tools(binary, console):
    replies, _ = session(binary, console, [INITIALIZE, request(4, "tools/list")])
    assert replies[1]["id"] == 4, replies[1]
    return replies[1]["result"]["tools"]


def call_read(binary, console, name, arguments=None):
    params = {"name": name, "arguments": arguments or {}}
    replies, _ = session(binary, console, [INITIALIZE, request(2, "tools/call", params)])
    assert len(replies) == 2, replies
    assert replies[1]["id"] == 2, replies[1]
    assert "error" not in replies[1], replies[1]
    return replies[1]["result"]


def write_fixture(console, relative, data):
    path = os.path.join(console.root, relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def arguments_under(console, arguments):
    return {key: value.replace("{root}", console.root) if isinstance(value, str) else value
            for key, value in arguments.items()}


def agent_answer(console, line):
    """One command on the agent port, as an agent sends it: the whole reply."""
    sock = console.connect()
    try:
        sock.sendall(("auth %s\n%s\n" % (console.token, line)).encode())
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    return b"".join(chunks).decode("utf-8", "replace")


def scenario_tools_list_names_every_read_row(binary, console):
    tools = listed_tools(binary, console)
    by_name = {tool["name"]: tool for tool in tools}
    read_names = [tool["name"] for tool in tools
                  if tool["annotations"]["readOnlyHint"] is True]
    assert read_names == [name for name, _ in READ_ROWS], read_names
    for name, keys in READ_ROWS:
        tool = by_name[name]
        assert tool["description"].strip(), tool
        schema = tool["inputSchema"]
        assert schema["type"] == "object", tool
        for key in keys + ["session"]:
            assert key in schema["properties"], (name, key, schema)
        assert tool["annotations"]["destructiveHint"] is False, tool


def scenario_read_tool_answers_without_approval(binary, console, name):
    write_fixture(console, "mcp-read/hello.txt", b"hello from the console\n")
    result = call_read(binary, console, name, arguments_under(console, READ_CALLS[name]))
    text = result["content"][0]["text"]
    assert "approval_required" not in text, result
    assert result["structuredContent"]["exit"] != 75, result
    assert result["structuredContent"].get("word") != "approval_required", result


def scenario_read_answers_text_and_exit_status(binary, console):
    write_fixture(console, "mcp-read/hello.txt", b"hello from the console\n")
    path = os.path.join(console.root, "mcp-read/hello.txt")
    result = call_read(binary, console, "ariel_cat", {"path": path})
    assert result["isError"] is False, result
    assert result["content"][0]["text"] == "hello from the console\n", result
    assert result["structuredContent"] == {"exit": 0, "truncated": False}, result


def scenario_read_over_64_kib_reports_truncated(binary, console):
    write_fixture(console, "mcp-read/big.txt", b"a line of the console's text\n" * 2400)
    path = os.path.join(console.root, "mcp-read/big.txt")
    result = call_read(binary, console, "ariel_cat", {"path": path})
    assert result["isError"] is False, result
    assert result["structuredContent"]["exit"] == 0, result
    assert result["structuredContent"]["truncated"] is True, result


def scenario_session_argument_reaches_the_console_as_the_prefix(binary, console):
    write_fixture(console, "mcp-read/work/.keep", b"")
    reply = agent_answer(console, "session new")
    match = re.match(r"session ([0-9a-f]{32}) ", reply)
    assert match, reply
    sid = match.group(1)
    work = os.path.join(console.root, "mcp-read/work")
    moved = agent_answer(console, "@%s cd %s" % (sid, work))
    assert moved.endswith("exit 0\n"), moved
    inside = call_read(binary, console, "ariel_pwd", {"session": sid})
    assert inside["content"][0]["text"] == work + "\n", inside
    assert inside["structuredContent"]["exit"] == 0, inside
    outside = call_read(binary, console, "ariel_pwd")
    assert outside["content"][0]["text"] == "/\n", outside
    stale = call_read(binary, console, "ariel_pwd", {"session": "0" * 32})
    assert stale["isError"] is True, stale
    assert stale["structuredContent"]["word"] == "session_expired", stale


def scenario_suspend_is_not_advertised_as_a_read_tool(binary, console):
    by_name = {tool["name"]: tool for tool in listed_tools(binary, console)}
    suspend = by_name.get("ariel_suspend")
    assert suspend is None or suspend["annotations"]["readOnlyHint"] is False, suspend


def scenario_refused_read_answers_the_console_word(binary, console):
    write_fixture(console, "mcp-read/hello.txt", b"hello from the console\n")
    result = call_read(binary, console, "ariel_cat", {"path": "mcp-read/hello.txt"})
    assert result["isError"] is True, result
    assert result["structuredContent"]["exit"] == 1, result
    assert result["structuredContent"]["word"] == "relative_path", result


def scenario_list_tools_matches_tools_list(binary, console):
    replies, _ = session(binary, console, [INITIALIZE, request(7, "tools/list")])
    proc = run(binary, ["--list-tools"])
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.decode()) == replies[1]["result"], proc.stdout
    assert PROTOCOL_REVISION.encode() in proc.stderr, proc.stderr


def scenario_malformed_ids_answer_parse_error(binary, console):
    for bad in ['--', '01', '1.', '+1', '1e']:
        text = '{"jsonrpc":"2.0","id":%s,"method":"ping"}' % bad
        replies, _ = session(binary, console, [INITIALIZE, text])
        error = replies[1]["error"]
        assert error["code"] == -32700, (bad, replies[1])
        assert replies[1]["id"] is None, (bad, replies[1])


def scenario_numeric_ids_are_echoed(binary, console):
    replies, _ = session(binary, console, [
        INITIALIZE,
        '{"jsonrpc":"2.0","id":-1.5e+2,"method":"ping"}',
        '{"jsonrpc":"2.0","id":0,"method":"ping"}',
    ])
    assert replies[1]["id"] == -150, replies[1]
    assert replies[2]["id"] == 0, replies[2]


def repository_version():
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    tags = subprocess.run(
        ["git", "tag", "--list", "v[0-9]*", "--sort=-v:refname"], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    names = tags.stdout.decode().split()
    return names[0][1:] if names else None


def scenario_server_version_is_the_repository_version(binary, console):
    replies, _ = session(binary, console, [INITIALIZE])
    version = replies[0]["result"]["serverInfo"]["version"]
    expected = repository_version()
    if expected is None:
        assert version, replies[0]
    else:
        assert version == expected, (version, expected)


def scenario_key_path_refuses_to_start(binary, console):
    proc = run(binary, ["--key", "/nonexistent/owner.key"])
    assert proc.returncode != 0, proc
    assert proc.stdout == b"", proc.stdout


# Issue #140: the suite drives the server over stdio, against a real Ariel.

def scenario_initialize_and_tools_list_over_the_wire(binary, console):
    client = McpClient(binary, console_args(console))
    try:
        result = client.request(1, "initialize", INIT_PARAMS)["result"]
        assert result["protocolVersion"] == PROTOCOL_REVISION, result
        assert result["serverInfo"]["name"] == "ariel", result
        client.notify("notifications/initialized")
        listed = client.request(2, "tools/list")["result"]
    finally:
        client.close()
    expected = json.loads(run(binary, ["--list-tools"]).stdout.decode())
    assert listed == expected, (listed, expected)


def scenario_second_initialize_over_the_wire_is_refused(binary, console):
    client = McpClient(binary, console_args(console))
    try:
        client.request(1, "initialize", INIT_PARAMS)
        reply = client.request(2, "initialize", INIT_PARAMS)
    finally:
        client.close()
    assert reply["id"] == 2 and "error" in reply, reply


def scenario_refused_token_fails_with_the_console_word(binary, console):
    client = McpClient(binary, console_args(console, wrong_token(console.token)))
    try:
        client.request(1, "initialize", INIT_PARAMS)
    except ServerExited as err:
        message = str(err)
        assert "exit 70" in message, message
        assert "refused" in message, message
        return
    finally:
        client.close()
    raise AssertionError("the server answered initialize with a refused token")


def scenario_closed_console_fails_with_the_connection_error(binary, console):
    port = closed_port()
    client = McpClient(binary, ["--host", "127.0.0.1", "--port", str(port),
                                "--token", console.token])
    try:
        client.request(1, "initialize", INIT_PARAMS)
    except ServerExited as err:
        message = str(err)
        assert "connect 127.0.0.1:%d" % port in message, message
        assert "refused" in message.lower(), message
        return
    finally:
        client.close()
    raise AssertionError("the server answered initialize with no console")


# Issue #141: the configuration resolves in a fixed order, and --check proves it.

def scenario_check_against_listening_agent_exits_zero_and_names_console(binary, console):
    proc = run(binary, ["--check"] + console_args(console))
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.decode()
    assert "127.0.0.1:%d" % console.port in out, out
    assert console.token not in out, out


def scenario_check_against_closed_port_exits_nonzero_with_one_line(binary, console):
    port = closed_port()
    proc = run(binary, ["--check", "--host", "127.0.0.1", "--port", str(port),
                        "--token", console.token])
    assert proc.returncode != 0, proc
    assert proc.stdout == b"", proc.stdout
    line = one_line(proc.stderr.decode())
    assert "127.0.0.1:%d" % port in line and "refused" in line.lower(), line


def scenario_check_refused_token_names_the_console_word(binary, console):
    proc = run(binary, ["--check"] + console_args(console, wrong_token(console.token)))
    assert proc.returncode != 0, proc
    line = one_line(proc.stderr.decode())
    assert "exit 70" in line and "refused" in line, line


def scenario_env_file_supplies_host_and_token(binary, console):
    with tempfile.TemporaryDirectory() as directory:
        path = write_env_file(directory, "PS5_HOST=127.0.0.1\nARIEL_TOKEN=%s\n"
                              % console.token)
        proc = run(binary, ["--check", "--port", str(console.port), "--env-file", path])
    assert proc.returncode == 0, proc.stderr
    assert "127.0.0.1:%d" % console.port in proc.stdout.decode(), proc.stdout


def scenario_env_file_beats_the_environment(binary, console):
    with tempfile.TemporaryDirectory() as directory:
        path = write_env_file(directory, "PS5_HOST=127.0.0.1\nARIEL_TOKEN=%s\n"
                              % console.token)
        env = environment({"PS5_HOST": "no-such-host.invalid",
                           "ARIEL_TOKEN": wrong_token(console.token)})
        proc = run(binary, ["--check", "--port", str(console.port),
                            "--env-file", path], env=env)
    assert proc.returncode == 0, proc.stderr


def scenario_flag_beats_env_file(binary, console):
    with tempfile.TemporaryDirectory() as directory:
        path = write_env_file(directory, "PS5_HOST=no-such-host.invalid\n"
                              "ARIEL_TOKEN=%s\n" % wrong_token(console.token))
        refused = run(binary, ["--check", "--port", str(console.port),
                               "--env-file", path])
        assert refused.returncode != 0, "the file's wrong token must refuse"
        proc = run(binary, ["--check", "--host", "127.0.0.1", "--port",
                            str(console.port), "--token", console.token,
                            "--env-file", path])
    assert proc.returncode == 0, proc.stderr


def scenario_environment_variables_supply_host_and_token(binary, console):
    env = environment({"PS5_HOST": "127.0.0.1", "ARIEL_TOKEN": console.token,
                       "ARIEL_PORT": str(console.port)})
    proc = run(binary, ["--check"], env=env)
    assert proc.returncode == 0, proc.stderr


def scenario_missing_token_is_refused_naming_it(binary, console):
    proc = run(binary, ["--check", "--host", "127.0.0.1", "--port", str(console.port)])
    assert proc.returncode != 0, proc
    assert proc.stdout == b"", proc.stdout
    line = one_line(proc.stderr.decode())
    assert "token" in line.lower() and "ARIEL_TOKEN" in line, line


def scenario_missing_host_is_refused_naming_it(binary, console):
    proc = run(binary, ["--check", "--token", console.token])
    assert proc.returncode != 0, proc
    line = one_line(proc.stderr.decode())
    assert "host" in line.lower() and "PS5_HOST" in line, line


def scenario_unreadable_env_file_names_the_file(binary, console):
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "absent.env")
        proc = run(binary, ["--check", "--env-file", path])
    assert proc.returncode != 0, proc
    assert path in one_line(proc.stderr.decode()), proc.stderr


def scenario_malformed_token_names_the_file_not_the_value(binary, console):
    almost = console.token[:-1]
    with tempfile.TemporaryDirectory() as directory:
        path = write_env_file(directory, "PS5_HOST=127.0.0.1\nARIEL_TOKEN=%s\n" % almost)
        proc = run(binary, ["--check", "--port", str(console.port), "--env-file", path])
    assert proc.returncode != 0, proc
    line = one_line(proc.stderr.decode())
    assert path in line, line
    assert almost not in line and almost not in proc.stdout.decode(), line


def scenario_token_never_reaches_stdout_stderr_or_list_tools(binary, console):
    token = console.token
    runs = [
        run(binary, ["--check"] + console_args(console)),
        run(binary, ["--check"] + console_args(console, wrong_token(token))),
        run(binary, ["--check", "--host", "127.0.0.1", "--port",
                     str(closed_port()), "--token", token]),
        run(binary, ["--list-tools"] + console_args(console)),
    ]
    for proc in runs:
        text = proc.stdout.decode() + proc.stderr.decode()
        assert token not in text, text
    listed = runs[3].stdout.decode()
    assert json.loads(listed), listed


def scenario_key_path_refuses_with_the_console_settings(binary, console):
    proc = run(binary, ["--check", "--key", "/nonexistent/owner.key"]
               + console_args(console))
    assert proc.returncode != 0, proc
    assert proc.stdout == b"", proc.stdout
    assert console.token.encode() not in proc.stderr, proc.stderr


def scenario_silent_console_is_cut_by_the_timeout(binary, console):
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        started = time.monotonic()
        proc = run(binary, ["--check", "--host", "127.0.0.1", "--port", str(port),
                            "--token", console.token, "--timeout", "1"], timeout=20)
        elapsed = time.monotonic() - started
    finally:
        listener.close()
    assert proc.returncode != 0, proc
    line = one_line(proc.stderr.decode())
    assert "1 s" in line and "did not answer" in line, line
    assert elapsed < 15, elapsed


def scenario_numeric_flags_refuse_bad_values(binary, console):
    for flag, bad in (("--timeout", "0"), ("--timeout", "soon"),
                      ("--port", "0"), ("--port", "65536")):
        proc = run(binary, ["--check", "--host", "127.0.0.1", "--token", console.token,
                            flag, bad])
        assert proc.returncode != 0, (flag, bad, proc)
        assert flag in one_line(proc.stderr.decode()), (flag, bad, proc.stderr)


# Issue #144: a change tool returns the challenge, and the same call with the
# signature returns the console's answer.

WRITE_TOOL = "ariel_mkdir"
APPROVAL_ID = re.compile(r"a-[0-9a-f]+")
APPROVAL_EXPIRY_MS = 120_000
UNKNOWN_APPROVAL_ID = "a-0123456789abcdef"


def call_tool(binary, console, name, arguments):
    params = {"name": name, "arguments": arguments}
    replies, _ = session(binary, console, [INITIALIZE, request(2, "tools/call", params)])
    assert len(replies) == 2, replies
    assert replies[1]["id"] == 2, replies[1]
    assert "error" not in replies[1], replies[1]
    return replies[1]["result"]


def open_approval(binary, console, leaf):
    """Ask for the gated write on a fresh table and drain the owner's prompt."""
    console.fresh()
    path = os.path.join(console.root, "data", "mcp-" + leaf)
    result = call_tool(binary, console, WRITE_TOOL, {"path": path})
    prompt = console.next_line(timeout=5.0)
    assert prompt and prompt.startswith("prompt "), prompt
    return result


def scenario_write_tool_answers_the_challenge(binary, console):
    result = open_approval(binary, console, "challenge")
    assert result["isError"] is True, result
    shown = result["structuredContent"]
    assert shown["exit"] == 75 and shown["word"] == "approval_required", shown
    assert APPROVAL_ID.fullmatch(shown["approval_id"]), shown
    challenge = shown["challenge"].split(" ")
    assert shown["challenge"].startswith("challenge %s " % shown["approval_id"]), shown
    assert shown["console"] == challenge[2], shown
    assert shown["action"] == challenge[6], shown
    assert "ariel-sign sign <owner.key>" in shown["next"], shown


def scenario_signed_grant_returns_the_granted_answer(binary, console):
    shown = open_approval(binary, console, "grant")["structuredContent"]
    envelope = acceptance.sign_challenge(console, shown["challenge"])
    granted = call_tool(binary, console, WRITE_TOOL, {
        "approval_id": shown["approval_id"], "signature": envelope})
    assert granted["isError"] is False, granted
    assert granted["content"][0]["text"] == "approval_granted %s\n" % shown["approval_id"], granted
    assert granted["structuredContent"] == {"exit": 0, "truncated": False}, granted


def scenario_second_call_while_pending_answers_no_challenge(binary, console):
    first = open_approval(binary, console, "pending")["structuredContent"]
    again = call_tool(binary, console, WRITE_TOOL,
                      {"path": os.path.join(console.root, "data", "mcp-pending")})
    assert again["isError"] is True, again
    assert again["structuredContent"]["approval_id"] == first["approval_id"], again
    assert "challenge" not in again["structuredContent"], again
    assert again["content"][0]["text"] == "approval_required %s\n" % first["approval_id"], again
    assert again["structuredContent"]["exit"] == 75, again


def scenario_tampered_signature_answers_the_refusal_word(binary, console):
    shown = open_approval(binary, console, "tampered")["structuredContent"]
    envelope = acceptance.sign_challenge(console, shown["challenge"]).split(" ")
    envelope[0] = wrong_token(envelope[0])
    refused = call_tool(binary, console, WRITE_TOOL, {
        "approval_id": shown["approval_id"], "signature": " ".join(envelope)})
    assert refused["isError"] is True, refused
    assert refused["structuredContent"] == {
        "exit": 79, "truncated": False, "word": "signature_invalid"}, refused


def agent_outcome(console, line):
    """The word and exit status the agent answers to one line, sent as an agent sends it."""
    lines = agent_answer(console, line).splitlines()
    assert lines and lines[-1].startswith("exit "), lines
    status = int(lines[-1].split()[1])
    return (lines[0] if status else None), status


def assert_grant_matches_agent(binary, console, approval_id, signature, why):
    word, status = agent_outcome(console, "approval grant %s %s" % (approval_id, signature))
    result = call_tool(binary, console, WRITE_TOOL,
                       {"approval_id": approval_id, "signature": signature})
    shown = result["structuredContent"]
    assert shown["exit"] == status and shown.get("word") == word, (
        why, shown, "the agent answered", word, status)


def scenario_grant_refusals_match_the_agents_word(binary, console):
    assert_grant_matches_agent(binary, console, "a/b", "0" * 128, "an id the agent never issued")
    assert_grant_matches_agent(binary, console, UNKNOWN_APPROVAL_ID, "zz",
                               "a signature that is not hex")
    assert_grant_matches_agent(binary, console, UNKNOWN_APPROVAL_ID, "0" * 300,
                               "a signature over the agent's length")


def scenario_grant_at_the_full_envelope_length_reaches_the_agent(binary, console):
    envelope = " ".join(["0" * 128, "c" * 64, "0" * 64])
    assert_grant_matches_agent(binary, console, UNKNOWN_APPROVAL_ID, envelope,
                               "a signed envelope with a 64-byte console name")


def scenario_repeat_after_expiry_opens_a_new_approval(binary, console):
    first = open_approval(binary, console, "expiry")["structuredContent"]
    console.advance(APPROVAL_EXPIRY_MS + 1000)
    again = call_tool(binary, console, WRITE_TOOL, {
        "path": os.path.join(console.root, "data", "mcp-expiry")})
    shown = again["structuredContent"]
    assert again["isError"] is True and shown["exit"] == 75, again
    assert shown["approval_id"] != first["approval_id"], (first, shown)
    assert shown["challenge"].startswith("challenge %s " % shown["approval_id"]), shown
    prompt = console.next_line(timeout=5.0)
    assert prompt and prompt.startswith("prompt "), prompt


def scenario_write_tool_is_listed_as_a_change(binary, console):
    by_name = {tool["name"]: tool for tool in listed_tools(binary, console)}
    tool = by_name[WRITE_TOOL]
    assert tool["annotations"] == {"readOnlyHint": False, "destructiveHint": True}, tool
    for key in ("path", "approval_id", "signature", "session"):
        assert key in tool["inputSchema"]["properties"], tool


# Issue #145: bytes move by local path in both directions, never through the context.
BLOB = bytes(range(256)) * 4


def local_path(console, relative):
    path = os.path.join(console.root, "local", relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def local_file(console, relative, data):
    path = local_path(console, relative)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def scenario_push_from_a_local_file_moves_the_bytes(binary, console):
    console.fresh()
    local = local_file(console, "firmware.bin", BLOB)
    result = call_tool(binary, console, "ariel_payload_push",
                       {"name": "mcppush", "local_path": local})
    shown = result["structuredContent"]
    assert result["isError"] is True and shown["exit"] == 75, result
    assert APPROVAL_ID.fullmatch(shown["approval_id"]) and shown["challenge"], shown
    prompt = console.next_line(timeout=5.0)
    match = acceptance.PROMPT_LINE.match(prompt or "")
    assert match, "expected the owner's prompt, got %r" % prompt
    assert match.group(1) == shown["approval_id"], (match.group(1), shown)
    assert match.group(2) == "mcppush", prompt
    assert int(match.group(3)) == len(BLOB), prompt
    assert match.group(4) == hashlib.sha256(BLOB).hexdigest(), (
        "the console stored a different hash from the local file's")


def scenario_push_cut_by_the_console_returns_its_word(binary, console):
    console.fresh()
    path = local_path(console, "too-big.bin")
    with open(path, "wb") as handle:
        handle.truncate(64 * 1024 * 1024 + 1)
    result = call_tool(binary, console, "ariel_payload_push",
                       {"name": "toobig", "local_path": path})
    assert result["isError"] is True, result
    assert result["content"][0]["text"] == "staging_full\n", result
    assert result["structuredContent"] == {
        "exit": 80, "truncated": False, "word": "staging_full"}, result


def scenario_binary_range_is_written_to_the_local_path(binary, console):
    write_fixture(console, "mcp-read/blob.bin", BLOB)
    destination = local_path(console, "range.bin")
    result = call_tool(binary, console, "ariel_read", {
        "path": os.path.join(console.root, "mcp-read", "blob.bin"),
        "offset": 16, "limit": 64, "local_path": destination})
    assert result["isError"] is False, result
    expected = BLOB[16:80]
    with open(destination, "rb") as handle:
        assert handle.read() == expected, "the local file must hold the range"
    shown = result["structuredContent"]
    assert shown["exit"] == 0 and shown["truncated"] is False, shown
    assert shown["path"] == destination and shown["size"] == 64, shown
    assert shown["sha256"] == hashlib.sha256(expected).hexdigest(), shown
    assert shown["file_sha256"] == hashlib.sha256(BLOB).hexdigest(), shown
    text = result["content"][0]["text"]
    assert destination in text, text
    assert base64.b64encode(expected).decode() not in text, text


def scenario_write_from_a_local_file_answers_the_challenge(binary, console):
    console.fresh()
    data = b"hello written from a local file\n"
    local = local_file(console, "note.txt", data)
    destination = os.path.join(console.root, "data", "mcp-written.txt")
    result = call_tool(binary, console, "ariel_write",
                       {"path": destination, "local_path": local})
    shown = result["structuredContent"]
    assert result["isError"] is True and shown["exit"] == 75, result
    assert APPROVAL_ID.fullmatch(shown["approval_id"]), shown
    assert shown["challenge"].startswith("challenge %s " % shown["approval_id"]), shown
    prompt = console.next_line(timeout=5.0)
    assert prompt and prompt.startswith("prompt "), prompt
    assert hashlib.sha256(data).hexdigest() in prompt, prompt


def scenario_byte_tools_say_what_the_server_touches(binary, console):
    by_name = {tool["name"]: tool for tool in listed_tools(binary, console)}
    push = by_name["ariel_payload_push"]
    assert "local_path" in push["description"] and "reads" in push["description"], push
    assert "59 seconds" in push["description"], push
    assert "stops moving" in push["description"], push
    assert "upload_mismatch" in push["description"], push
    assert push["annotations"] == {"readOnlyHint": False, "destructiveHint": True}, push
    write = by_name["ariel_write"]["description"]
    assert "local_path" in write and "reads" in write, write
    read = by_name["ariel_read"]["description"]
    assert "local_path" in read and "writes" in read, read


def scenario_relative_local_path_is_refused_before_the_console(binary, console):
    replies, _ = session(binary, console, [INITIALIZE, request(2, "tools/call", {
        "name": "ariel_payload_push",
        "arguments": {"name": "relative", "local_path": "firmware.bin"}})])
    error = replies[1]["error"]
    assert replies[1]["id"] == 2 and error["code"] == -32602, replies[1]
    assert "absolute" in error["message"], replies[1]


def scenario_missing_local_file_is_a_tool_failure(binary, console):
    missing = local_path(console, "absent.bin")
    result = call_tool(binary, console, "ariel_payload_push",
                       {"name": "absent", "local_path": missing})
    assert result["isError"] is True, result
    assert missing in result["content"][0]["text"], result


# Issue #146: the change tools. Each one's first call opens the owner's
# approval and the same call with the signed challenge completes it. No tool is
# named reboot: a restart from a payload was measured not to exist (SPEC #136).
# The rows are named here from the SPEC, not read back from the server.
CHANGE_ROWS = [
    ("ariel_payload_run", ["name"]),
    ("ariel_payload_install", ["name", "repo", "asset", "tag"]),
    ("ariel_payload_rollback", ["name"]),
    ("ariel_payload_config", ["name", "timeout"]),
    ("ariel_autoload_safe_boot", []),
    ("ariel_shutdown", []),
    ("ariel_suspend", []),
    # Issue #148: the commands that change the file system.
    ("ariel_mkdir", ["path"]),
    ("ariel_rmdir", ["path"]),
    ("ariel_rm", ["path"]),
    ("ariel_touch", ["path"]),
    ("ariel_cp", ["source", "path"]),
    ("ariel_mv", ["source", "path"]),
    ("ariel_chmod", ["mode", "path"]),
    ("ariel_chown", ["owner", "path"]),
    ("ariel_chgrp", ["group", "path"]),
    ("ariel_ln", ["target", "path", "symbolic"]),
]

# The ariel-host binary the suite was given, for a scenario that needs a console
# of its own: a granted shutdown ends the console's process.
CONSOLE_BINARY = "./ariel-host"


def scenario_change_rows_are_listed_as_changes(binary, console):
    by_name = {tool["name"]: tool for tool in listed_tools(binary, console)}
    for name, keys in CHANGE_ROWS:
        tool = by_name[name]
        assert tool["description"].strip(), tool
        assert tool["annotations"] == {
            "readOnlyHint": False, "destructiveHint": True}, tool
        schema = tool["inputSchema"]
        assert schema["type"] == "object", tool
        for key in keys + ["session", "approval_id", "signature"]:
            assert key in schema["properties"], (name, key, schema)


def scenario_no_tool_is_named_reboot(binary, console):
    """tools/list carries no restart: only the console's shutdown and suspend."""
    names = [tool["name"] for tool in listed_tools(binary, console)]
    assert [name for name in names if "reboot" in name.lower()] == [], names


def scenario_shutdown_says_the_console_stays_off(binary, console):
    by_name = {tool["name"]: tool for tool in listed_tools(binary, console)}
    description = by_name["ariel_shutdown"]["description"]
    assert "stays off" in description, description
    assert "button" in description, description


def scenario_suspend_says_it_suspends_and_not_restarts(binary, console):
    by_name = {tool["name"]: tool for tool in listed_tools(binary, console)}
    description = by_name["ariel_suspend"]["description"]
    assert "suspend" in description.lower(), description
    assert "does not restart" in description, description


def open_change(binary, console, name, arguments):
    """Ask a change tool on a clean table, and drain the owner's prompt."""
    console.fresh()
    result = call_tool(binary, console, name, arguments)
    prompt = console.next_line(timeout=10.0)
    assert prompt and prompt.startswith("prompt "), prompt
    shown = result["structuredContent"]
    assert result["isError"] is True and shown["exit"] == 75, result
    assert APPROVAL_ID.fullmatch(shown.get("approval_id") or ""), result
    # An install answers the staging it made before it asks, so the console's
    # approval line is what this checks, not the first word of the answer.
    assert ("approval_required %s\n" % shown["approval_id"]
            in result["content"][0]["text"]), result
    assert shown["challenge"].startswith(
        "challenge %s " % shown["approval_id"]), result
    assert "ariel-sign sign <owner.key>" in shown["next"], result
    return shown


def grant_change(binary, console, name, shown):
    """Sign the challenge and pass it back: the console answers the grant."""
    envelope = acceptance.sign_challenge(console, shown["challenge"])
    result = call_tool(binary, console, name, {
        "approval_id": shown["approval_id"], "signature": envelope})
    assert result["isError"] is False, result
    assert result["content"][0]["text"] == (
        "approval_granted %s\n" % shown["approval_id"]), result
    assert result["structuredContent"] == {"exit": 0, "truncated": False}, result


def scenario_suspend_asks_then_answers_the_platform_word(binary, console):
    """A granted suspend runs the built-in and the host names its own refusal."""
    shown = open_change(binary, console, "ariel_suspend", {})
    grant_change(binary, console, "ariel_suspend", shown)
    again = call_tool(binary, console, "ariel_suspend", {})
    assert again["isError"] is True, again
    assert again["content"][0]["text"] == "not available on this platform\n", again
    assert again["structuredContent"]["exit"] == 1, again


def scenario_autoload_safe_boot_asks_then_answers_the_console(binary, console):
    """A granted safe-boot sets the boot list aside; a second one must wait."""
    shown = open_change(binary, console, "ariel_autoload_safe_boot", {})
    grant_change(binary, console, "ariel_autoload_safe_boot", shown)
    again = call_tool(binary, console, "ariel_autoload_safe_boot", {})
    assert again["isError"] is False, again
    assert again["content"][0]["text"] == "autoload safe-boot\n", again
    assert again["structuredContent"] == {"exit": 0, "truncated": False}, again
    pending = call_tool(binary, console, "ariel_autoload_safe_boot", {})
    assert pending["isError"] is True, pending
    assert pending["content"][0]["text"] == "safe_boot_pending\n", pending
    assert pending["structuredContent"]["word"] == "safe_boot_pending", pending


def scenario_payload_config_asks_then_answers_the_console(binary, console):
    """A granted config names the payload, the one-shot kind and the timeout."""
    acceptance.install_payload(
        console, "cfg", acceptance.healthy_build("cfg"))
    shown = open_change(binary, console, "ariel_payload_config",
                        {"name": "cfg", "timeout": 30})
    grant_change(binary, console, "ariel_payload_config", shown)
    again = call_tool(binary, console, "ariel_payload_config",
                      {"name": "cfg", "timeout": 30})
    assert again["isError"] is False, again
    assert again["content"][0]["text"] == (
        "configured cfg kind=one-shot timeout=30\n"), again


def scenario_payload_rollback_asks_then_answers_the_console(binary, console):
    """A granted rollback restores the build the newer one replaced."""
    previous = acceptance.install_payload(
        console, "roll", acceptance.healthy_build("roll-a"))
    acceptance.install_payload(console, "roll", acceptance.healthy_build("roll-b"))
    shown = open_change(binary, console, "ariel_payload_rollback",
                        {"name": "roll"})
    grant_change(binary, console, "ariel_payload_rollback", shown)
    again = call_tool(binary, console, "ariel_payload_rollback",
                      {"name": "roll"})
    assert again["isError"] is False, again
    assert again["content"][0]["text"] == "rolled_back roll %s\n" % previous, again


def scenario_payload_install_asks_then_answers_the_console(binary, console):
    """A granted install answers the grant; the console staged the release."""
    fixture = acceptance.InstallFixture(
        acceptance.healthy_build(acceptance.INSTALL_NAME))
    try:
        server = fixture.server
        shown = open_change(binary, server, "ariel_payload_install", {
            "name": acceptance.INSTALL_NAME, "repo": acceptance.INSTALL_REPO,
            "asset": acceptance.INSTALL_ASSET})
        grant_change(binary, server, "ariel_payload_install", shown)
        assert fixture.fake.requests, (
            "an install must fetch the release the allowlist names")
    finally:
        fixture.close()


def scenario_payload_run_runs_the_installed_build(binary, console):
    """A run executes the committed build; the commit was the approval.

    The console gates a build when it is committed, and approving a build also
    approves running it (Stage 1). A run of an installed build therefore asks
    nobody: this tool is a change, but its prompt happened at the commit.
    """
    acceptance.install_payload(
        console, "runs", acceptance.healthy_build("runs"))
    result = call_tool(binary, console, "ariel_payload_run", {"name": "runs"})
    assert result["isError"] is False, result
    text = result["content"][0]["text"]
    assert "Hello from runs!" in text, text
    assert text.endswith("status 0\n"), text


def scenario_shutdown_asks_then_the_console_goes_off(binary, console):
    """A granted shutdown answers, and the console's process ends: it stays off."""
    dedicated = acceptance.Server(CONSOLE_BINARY)
    try:
        shown = open_change(binary, dedicated, "ariel_shutdown", {})
        grant_change(binary, dedicated, "ariel_shutdown", shown)
        result = call_tool(binary, dedicated, "ariel_shutdown", {})
        assert result["isError"] is False, result
        assert result["content"][0]["text"] == "shutting_down\n", result
        assert result["structuredContent"] == {"exit": 0, "truncated": False}, result
        assert dedicated.proc.wait(timeout=10) == 0, (
            "a shutdown must end the console's process")
    finally:
        dedicated.stop()


# Issue #148: the commands that change the file system. Each row is a write
# gated through the same handshake, and the console's protection rule holds
# through every one: a path under Ariel's state directory answers protected
# (87) even with an approval.

def change_path(console, leaf):
    """An absent entry under the console's data directory."""
    path = os.path.join(console.root, "data", leaf)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.lexists(path):
        os.unlink(path)
    return path


def run_change(binary, console, name, arguments):
    """Open the approval, grant it, and resubmit: the console's own answer."""
    shown = open_change(binary, console, name, arguments)
    grant_change(binary, console, name, shown)
    return call_tool(binary, console, name, arguments)


def scenario_rmdir_removes_an_empty_directory(binary, console):
    path = change_path(console, "mcp-rmdir")
    os.makedirs(path)
    again = run_change(binary, console, "ariel_rmdir", {"path": path})
    assert again["isError"] is False, again
    assert not os.path.exists(path), "the directory must be gone"


def scenario_touch_creates_the_file(binary, console):
    path = change_path(console, "mcp-touch")
    again = run_change(binary, console, "ariel_touch", {"path": path})
    assert again["isError"] is False, again
    assert os.path.isfile(path), "touch must create the file"


def scenario_rm_removes_a_symbolic_link_and_leaves_its_target(binary, console):
    target = change_path(console, "mcp-rm-target")
    write_fixture(console, "data/mcp-rm-target", b"kept\n")
    link = change_path(console, "mcp-rm-link")
    os.symlink(target, link)
    again = run_change(binary, console, "ariel_rm", {"path": link})
    assert again["isError"] is False, again
    assert not os.path.lexists(link), "the link must be gone"
    with open(target, "rb") as handle:
        assert handle.read() == b"kept\n", "the object the link named must stay"


def scenario_cp_copies_the_source(binary, console):
    source = change_path(console, "mcp-cp-source")
    destination = change_path(console, "mcp-cp-copy")
    write_fixture(console, "data/mcp-cp-source", b"copy me\n")
    again = run_change(binary, console, "ariel_cp",
                       {"source": source, "path": destination})
    assert again["isError"] is False, again
    with open(destination, "rb") as handle:
        assert handle.read() == b"copy me\n", "the copy must hold the source's bytes"
    with open(source, "rb") as handle:
        assert handle.read() == b"copy me\n", "a copy leaves the source in place"


def scenario_mv_renames_the_name(binary, console):
    source = change_path(console, "mcp-mv-source")
    destination = change_path(console, "mcp-mv-moved")
    write_fixture(console, "data/mcp-mv-source", b"move me\n")
    again = run_change(binary, console, "ariel_mv",
                       {"source": source, "path": destination})
    assert again["isError"] is False, again
    assert not os.path.lexists(source), "mv must move the name"
    with open(destination, "rb") as handle:
        assert handle.read() == b"move me\n", "the moved name must hold the bytes"


def scenario_chmod_sets_the_mode(binary, console):
    path = change_path(console, "mcp-chmod")
    write_fixture(console, "data/mcp-chmod", b"mode\n")
    os.chmod(path, 0o644)
    again = run_change(binary, console, "ariel_chmod",
                       {"mode": "0600", "path": path})
    assert again["isError"] is False, again
    assert os.stat(path).st_mode & 0o777 == 0o600, oct(os.stat(path).st_mode)


def scenario_ln_creates_a_symbolic_link(binary, console):
    target = change_path(console, "mcp-ln-target")
    link = change_path(console, "mcp-ln-link")
    write_fixture(console, "data/mcp-ln-target", b"link me\n")
    again = run_change(binary, console, "ariel_ln",
                       {"target": target, "path": link, "symbolic": True})
    assert again["isError"] is False, again
    assert os.path.islink(link), "symbolic true must create a symbolic link"
    assert os.readlink(link) == target, os.readlink(link)


def scenario_ln_takes_a_boolean_and_refuses_anything_else(binary, console):
    by_name = {tool["name"]: tool for tool in listed_tools(binary, console)}
    schema = by_name["ariel_ln"]["inputSchema"]
    assert schema["properties"]["symbolic"] == {"type": "boolean"}, schema
    replies, _ = session(binary, console, [INITIALIZE, request(2, "tools/call", {
        "name": "ariel_ln",
        "arguments": {"target": "/data/a", "path": "/data/b", "symbolic": 1}})])
    error = replies[1]["error"]
    assert replies[1]["id"] == 2 and error["code"] == -32602, replies[1]
    assert "symbolic" in error["message"], replies[1]


def scenario_chown_and_chgrp_ask_the_owner_first(binary, console):
    """The ids are the caller's; the host may refuse the change, not the ask."""
    path = change_path(console, "mcp-owner")
    write_fixture(console, "data/mcp-owner", b"owner\n")
    for name, arguments in (
            ("ariel_chown", {"owner": str(os.getuid()), "path": path}),
            ("ariel_chgrp", {"group": str(os.getgid()), "path": path})):
        shown = open_change(binary, console, name, arguments)
        grant_change(binary, console, name, shown)


def scenario_state_directory_is_protected_through_every_change_tool(binary, console):
    protected = os.path.join(console.root, "data", "ariel")
    inside = os.path.join(protected, "staging")
    destination = change_path(console, "mcp-protected-destination")
    cases = [
        ("ariel_rmdir", {"path": inside}),
        ("ariel_rm", {"path": os.path.join(protected, "token")}),
        ("ariel_touch", {"path": os.path.join(protected, "token")}),
        ("ariel_cp", {"source": os.path.join(protected, "token"),
                      "path": destination}),
        ("ariel_mv", {"source": os.path.join(protected, "token"),
                      "path": destination}),
        ("ariel_chmod", {"mode": "0644", "path": os.path.join(protected, "token")}),
        ("ariel_chown", {"owner": "0", "path": os.path.join(protected, "token")}),
        ("ariel_chgrp", {"group": "0", "path": os.path.join(protected, "token")}),
        ("ariel_ln", {"target": os.path.join(protected, "token"),
                      "path": destination, "symbolic": True}),
    ]
    for name, arguments in cases:
        console.fresh()
        result = call_tool(binary, console, name, arguments)
        assert result["isError"] is True, (name, result)
        shown = result["structuredContent"]
        assert shown["exit"] == 87 and shown["word"] == "protected", (name, shown)
        console.assert_no_line(timeout=0.4)


SCENARIOS = [
    ("initialize answers the ADR-0017 revision and serverInfo ariel",
     scenario_initialize_names_the_revision_and_server),
    ("a second initialize is refused",
     scenario_second_initialize_is_refused),
    ("notifications/initialized is silent and ping answers",
     scenario_notification_is_silent_and_ping_answers),
    ("an unknown method answers -32601",
     scenario_unknown_method_answers_32601),
    ("malformed arguments answer -32602",
     scenario_malformed_arguments_answer_32602),
    ("--list-tools prints what tools/list answers and names the revision",
     scenario_list_tools_matches_tools_list),
    ("a malformed id answers -32700 with a null id",
     scenario_malformed_ids_answer_parse_error),
    ("numeric ids are echoed as numbers",
     scenario_numeric_ids_are_echoed),
    ("serverInfo.version is the repository's newest v tag",
     scenario_server_version_is_the_repository_version),
    ("a key path refuses to start and prints nothing",
     scenario_key_path_refuses_to_start),
    ("the suite completes initialize and tools/list over the wire",
     scenario_initialize_and_tools_list_over_the_wire),
    ("a second initialize over the wire is refused",
     scenario_second_initialize_over_the_wire_is_refused),
    ("a refused token fails the scenario with the console's word",
     scenario_refused_token_fails_with_the_console_word),
    ("a closed console fails the scenario with the connection error",
     scenario_closed_console_fails_with_the_connection_error),
    ("--check against a listening agent exits 0 and names the console",
     scenario_check_against_listening_agent_exits_zero_and_names_console),
    ("--check against a closed port exits non-zero with one line",
     scenario_check_against_closed_port_exits_nonzero_with_one_line),
    ("--check with a refused token names the console's word",
     scenario_check_refused_token_names_the_console_word),
    ("--env-file supplies PS5_HOST and ARIEL_TOKEN",
     scenario_env_file_supplies_host_and_token),
    ("the env file beats the environment",
     scenario_env_file_beats_the_environment),
    ("a flag beats the env file",
     scenario_flag_beats_env_file),
    ("the environment supplies host, token and port",
     scenario_environment_variables_supply_host_and_token),
    ("a missing token is refused, naming ARIEL_TOKEN",
     scenario_missing_token_is_refused_naming_it),
    ("a missing host is refused, naming PS5_HOST",
     scenario_missing_host_is_refused_naming_it),
    ("an unreadable env file is refused, naming the file",
     scenario_unreadable_env_file_names_the_file),
    ("a malformed token is refused, naming the file and not the value",
     scenario_malformed_token_names_the_file_not_the_value),
    ("the token never reaches stdout, stderr or --list-tools",
     scenario_token_never_reaches_stdout_stderr_or_list_tools),
    ("a key path refuses with the console settings present",
     scenario_key_path_refuses_with_the_console_settings),
    ("--timeout cuts a silent console with one line",
     scenario_silent_console_is_cut_by_the_timeout),
    ("--port and --timeout refuse values that are not numbers in range",
     scenario_numeric_flags_refuse_bad_values),
    ("tools/list names every read row with a description, a schema and a class",
     scenario_tools_list_names_every_read_row),
    ("a read answers its text and exit status with isError false",
     scenario_read_answers_text_and_exit_status),
    ("an answer over 64 KiB reports truncated true",
     scenario_read_over_64_kib_reports_truncated),
    ("a session argument reaches the console as @<sid>, and pwd answers its directory",
     scenario_session_argument_reaches_the_console_as_the_prefix),
    ("ariel_suspend is not advertised as a read tool",
     scenario_suspend_is_not_advertised_as_a_read_tool),
    ("a refused read answers isError true with the console's word",
     scenario_refused_read_answers_the_console_word),
    ("a write tool on a fresh agent answers isError true with approval_id, the challenge and the action",
     scenario_write_tool_answers_the_challenge),
    ("the suite signs with the test key, passes approval_id and signature back, and gets the granted answer",
     scenario_signed_grant_returns_the_granted_answer),
    ("a second call while the approval is pending answers approval_id and no challenge line",
     scenario_second_call_while_pending_answers_no_challenge),
    ("a tampered signature answers the agent's refusal word, not a server error",
     scenario_tampered_signature_answers_the_refusal_word),
    ("a grant refused locally answers the agent's own word and exit",
     scenario_grant_refusals_match_the_agents_word),
    ("a signed envelope with a 64-byte console name reaches the agent",
     scenario_grant_at_the_full_envelope_length_reaches_the_agent),
    ("a repeat after the approval expires opens a new approval with its challenge",
     scenario_repeat_after_expiry_opens_a_new_approval),
    ("the write tool is listed as a change with approval_id and signature arguments",
     scenario_write_tool_is_listed_as_a_change),
    ("a push from a local file moves the bytes and the console stores the file's hash",
     scenario_push_from_a_local_file_moves_the_bytes),
    ("a push the console cuts answers the console's word, not a server wording",
     scenario_push_cut_by_the_console_returns_its_word),
    ("a binary range is written to the named local path with no base64 in the answer",
     scenario_binary_range_is_written_to_the_local_path),
    ("a write from a local file answers the challenge for the file's hash",
     scenario_write_from_a_local_file_answers_the_challenge),
    ("the byte tools' descriptions say the server reads and writes local_path, and the push names the stall",
     scenario_byte_tools_say_what_the_server_touches),
    ("a relative local_path is refused as invalid params before the console",
     scenario_relative_local_path_is_refused_before_the_console),
    ("a missing local file is a tool failure that names the file",
     scenario_missing_local_file_is_a_tool_failure),
    ("every change row is listed with a destructive class, its keys and the approval arguments",
     scenario_change_rows_are_listed_as_changes),
    ("tools/list carries no tool named reboot",
     scenario_no_tool_is_named_reboot),
    ("ariel_shutdown's description says the console stays off until a button is pressed",
     scenario_shutdown_says_the_console_stays_off),
    ("ariel_suspend's description says it suspends and does not restart",
     scenario_suspend_says_it_suspends_and_not_restarts),
    ("ariel_suspend asks the owner, then the host answers not available on this platform",
     scenario_suspend_asks_then_answers_the_platform_word),
    ("ariel_autoload_safe_boot asks the owner, then sets the boot list aside",
     scenario_autoload_safe_boot_asks_then_answers_the_console),
    ("ariel_payload_config asks the owner, then applies the one-shot timeout",
     scenario_payload_config_asks_then_answers_the_console),
    ("ariel_payload_rollback asks the owner, then restores the previous build",
     scenario_payload_rollback_asks_then_answers_the_console),
    ("ariel_payload_install asks the owner after fetching the release",
     scenario_payload_install_asks_then_answers_the_console),
    ("ariel_payload_run runs the committed build without a new prompt",
     scenario_payload_run_runs_the_installed_build),
    ("ariel_shutdown asks the owner, then the console answers and stays off",
     scenario_shutdown_asks_then_the_console_goes_off),
    ("ariel_rmdir asks the owner, then removes the empty directory",
     scenario_rmdir_removes_an_empty_directory),
    ("ariel_touch asks the owner, then creates the file",
     scenario_touch_creates_the_file),
    ("ariel_rm on a symbolic link removes the link and leaves its target",
     scenario_rm_removes_a_symbolic_link_and_leaves_its_target),
    ("ariel_cp asks the owner, then copies the source",
     scenario_cp_copies_the_source),
    ("ariel_mv asks the owner, then renames the name",
     scenario_mv_renames_the_name),
    ("ariel_chmod asks the owner, then sets the mode",
     scenario_chmod_sets_the_mode),
    ("ariel_ln with symbolic true creates a symbolic link",
     scenario_ln_creates_a_symbolic_link),
    ("ariel_ln's symbolic is a boolean and anything else is invalid params",
     scenario_ln_takes_a_boolean_and_refuses_anything_else),
    ("ariel_chown and ariel_chgrp ask the owner first",
     scenario_chown_and_chgrp_ask_the_owner_first),
    ("a path under the state directory answers protected 87 through every file change tool",
     scenario_state_directory_is_protected_through_every_change_tool),
]
for _name, _keys in READ_ROWS:
    SCENARIOS.append((
        "%s answers without approval_required" % _name,
        lambda binary, console, name=_name: scenario_read_tool_answers_without_approval(
            binary, console, name)))


def main():
    global CONSOLE_BINARY

    args = sys.argv[1:]
    binary = args[0] if args else "./ariel-mcp"
    host_binary = args[1] if len(args) > 1 else "./ariel-host"
    CONSOLE_BINARY = host_binary
    console = acceptance.Server(host_binary)
    try:
        for title, scenario in SCENARIOS:
            check(title, lambda scenario=scenario: scenario(binary, console))
    finally:
        console.stop()
    failed = [name for name, ok in results if not ok]
    if failed:
        print("\n%d mcp scenario(s) failed" % len(failed))
        return 1
    print("\nall %d mcp scenarios passed" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
