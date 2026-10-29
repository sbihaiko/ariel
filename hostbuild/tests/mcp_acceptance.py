#!/usr/bin/env python3
"""Headless acceptance for ariel-mcp, driven over stdio as a client does.

Starts the host build of Ariel on a loopback port and the host-built server as
child processes. The server talks to that Ariel over the agent port; every
answer is what a binary wrote to the wire. No stub stands in for the protocol
or for the console.

Usage: mcp_acceptance.py [./ariel-mcp [./ariel-host]]
"""

import json
import os
import queue
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


def scenario_tools_list_is_a_valid_empty_list(binary, console):
    replies, _ = session(binary, console, [INITIALIZE, request(4, "tools/list")])
    assert replies[1]["id"] == 4, replies[1]
    assert replies[1]["result"] == {"tools": []}, replies[1]


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


SCENARIOS = [
    ("initialize answers the ADR-0017 revision and serverInfo ariel",
     scenario_initialize_names_the_revision_and_server),
    ("a second initialize is refused",
     scenario_second_initialize_is_refused),
    ("notifications/initialized is silent and ping answers",
     scenario_notification_is_silent_and_ping_answers),
    ("tools/list answers a valid empty list",
     scenario_tools_list_is_a_valid_empty_list),
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
]


def main():
    args = sys.argv[1:]
    binary = args[0] if args else "./ariel-mcp"
    host_binary = args[1] if len(args) > 1 else "./ariel-host"
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
