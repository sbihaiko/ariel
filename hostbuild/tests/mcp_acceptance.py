#!/usr/bin/env python3
"""Headless acceptance for ariel-mcp, driven over stdio as a client does.

Spawns the host-built server and writes one JSON-RPC 2.0 object per line to its
standard input, reading one per line from its standard output. No stub stands
in for the protocol: every answer is what the binary wrote to the wire.

The stdio scenarios start ariel-host on a loopback port, the host build of the
console, and the --check scenarios reach it over the agent port. A console that
refuses the token answers its own word, exit 70, and the scenario names it.
"""

import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

HOST = "127.0.0.1"
TOKEN = "0123456789abcdef0123456789abcdef"
WRONG_TOKEN = "f" * 32
PROTOCOL_REVISION = "2026-07-28"
START_TIMEOUT = 60.0
REPLY_TIMEOUT = 30.0
ARIEL_HOST = "./ariel-host"
results = []


def check(name, fn):
    try:
        fn()
    except Exception as err:  # noqa: BLE001 - a failed scenario is a report
        results.append((name, False))
        print("FAIL %s: %s: %s" % (name, type(err).__name__, err))
    else:
        results.append((name, True))
        print("PASS %s" % name)


class ServerExited(AssertionError):
    """ariel-mcp ended before it answered; its status and stderr are the report."""

    def __init__(self, status, stderr):
        self.status = status
        self.stderr = stderr
        first = stderr.strip().splitlines()[:1]
        detail = " (%s)" % first[0] if first else ""
        super().__init__("ariel-mcp exited with status %d before it answered%s"
                         % (status, detail))


class ConsoleRefused(AssertionError):
    """The console answered a refusal; the message carries its own word."""


def clean_env(**extra):
    """The environment with no console address or token, plus extra."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("PS5_HOST", "ARIEL_TOKEN")}
    env.update(extra)
    return env


def run(binary, args, env=None):
    proc = subprocess.run(
        [binary] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env if env is not None else clean_env(), timeout=60)
    return proc.returncode, proc.stdout.decode(), proc.stderr.decode()


def write_env_file(directory, **values):
    path = os.path.join(directory, "ariel.env")
    with open(path, "w") as f:
        for key, value in values.items():
            f.write("%s=%s\n" % (key, value))
    return path


def closed_port():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


class Lines:
    """Lines read from a stream by a thread, so a wait for one can time out."""

    def __init__(self, stream):
        self.queue = queue.Queue()
        threading.Thread(target=self._pump, args=(stream,), daemon=True).start()

    def _pump(self, stream):
        for raw in iter(stream.readline, b""):
            self.queue.put(raw)
        self.queue.put(None)

    def get(self, timeout):
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError("no line in %d s" % timeout)


class Host:
    """ariel-host on a loopback port in a root of its own: the console."""

    def __init__(self, binary):
        self.root = tempfile.mkdtemp(prefix="ariel-mcp-",
                                     dir=os.path.realpath("/tmp"))
        self.proc = subprocess.Popen(
            [binary, "--port", "0", "--root", self.root],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.lines = Lines(self.proc.stdout)
        self.port = int(self._expect("port "))
        self.token = self._expect("token ")

    def _expect(self, prefix):
        raw = self.lines.get(START_TIMEOUT)
        if raw is None:
            raise AssertionError("ariel-host ended before its %s line"
                                 % prefix.strip())
        line = raw.decode().strip()
        if not line.startswith(prefix):
            raise AssertionError("ariel-host did not print its %s line"
                                 % prefix.strip())
        return line[len(prefix):]

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=START_TIMEOUT)
        shutil.rmtree(self.root, ignore_errors=True)


def console_answers(port, token, command="sysinfo"):
    """The reply lines of one command after auth, as the agent port answers."""
    with socket.create_connection((HOST, port), timeout=REPLY_TIMEOUT) as sock:
        sock.sendall(("auth %s\n%s\n" % (token, command)).encode())
        sock.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    lines = data.decode().splitlines()
    if lines == ["exit 70"]:
        raise ConsoleRefused("the console refused the token: exit 70")
    return lines


class Stdio:
    """ariel-mcp as a child process, spoken to one line at a time."""

    def __init__(self, binary, args=(), env=None):
        self.proc = subprocess.Popen(
            [binary] + list(args), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env if env is not None else clean_env())
        self.lines = Lines(self.proc.stdout)

    def send(self, message):
        try:
            self.proc.stdin.write((json.dumps(message) + "\n").encode())
            self.proc.stdin.flush()
        except BrokenPipeError:
            pass  # the server has ended; receive reports how

    def receive(self):
        raw = self.lines.get(REPLY_TIMEOUT)
        if raw is None:
            self.proc.wait(timeout=REPLY_TIMEOUT)
            raise ServerExited(self.proc.returncode,
                               self.proc.stderr.read().decode())
        return json.loads(raw)

    def request(self, id_, method, params=None):
        self.send(request(id_, method, params))
        return self.receive()

    def close(self):
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        self.proc.wait(timeout=REPLY_TIMEOUT)
        return self.proc.returncode


def session(binary, lines):
    """Run the server with lines on stdin and return its parsed replies.

    A str item is sent verbatim, so a test can send text that is not JSON.
    """
    payload = "".join(
        (line if isinstance(line, str) else json.dumps(line)) + "\n"
        for line in lines)
    proc = subprocess.run(
        [binary], input=payload.encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30)
    out = proc.stdout.decode()
    replies = [json.loads(text) for text in out.splitlines() if text.strip()]
    return replies, proc


def request(id_, method, params=None):
    message = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        message["params"] = params
    return message


INITIALIZE_PARAMS = {
    "protocolVersion": PROTOCOL_REVISION,
    "capabilities": {},
    "clientInfo": {"name": "acceptance", "version": "0"},
}
INITIALIZE = request(1, "initialize", INITIALIZE_PARAMS)


def scenario_initialize_names_the_revision_and_server(binary):
    replies, _ = session(binary, [INITIALIZE])
    assert len(replies) == 1, replies
    result = replies[0]["result"]
    assert result["protocolVersion"] == PROTOCOL_REVISION, result
    assert result["serverInfo"]["name"] == "ariel", result
    assert result["serverInfo"]["version"], result
    assert "tools" in result["capabilities"], result


def scenario_second_initialize_is_refused(binary):
    replies, _ = session(binary, [INITIALIZE, request(2, "initialize", {
        "protocolVersion": PROTOCOL_REVISION, "capabilities": {},
        "clientInfo": {"name": "acceptance", "version": "0"}})])
    assert len(replies) == 2, replies
    assert replies[1].get("id") == 2, replies[1]
    assert "error" in replies[1], replies[1]


def scenario_notification_is_silent_and_ping_answers(binary):
    replies, _ = session(binary, [
        INITIALIZE,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request(3, "ping"),
    ])
    assert len(replies) == 2, replies
    assert replies[1] == {"jsonrpc": "2.0", "id": 3, "result": {}}, replies[1]


def scenario_tools_list_is_a_valid_empty_list(binary):
    replies, _ = session(binary, [INITIALIZE, request(4, "tools/list")])
    assert replies[1]["id"] == 4, replies[1]
    assert replies[1]["result"] == {"tools": []}, replies[1]


def scenario_unknown_method_answers_32601(binary):
    replies, _ = session(binary, [INITIALIZE, request(5, "resources/list")])
    error = replies[1]["error"]
    assert error["code"] == -32601, replies[1]
    assert replies[1]["id"] == 5, replies[1]


def scenario_malformed_arguments_answer_32602(binary):
    replies, _ = session(binary, [
        INITIALIZE, request(6, "tools/call", {"arguments": {}})])
    error = replies[1]["error"]
    assert error["code"] == -32602, replies[1]
    assert replies[1]["id"] == 6, replies[1]


def scenario_list_tools_matches_tools_list(binary):
    replies, _ = session(binary, [INITIALIZE, request(7, "tools/list")])
    proc = subprocess.run([binary, "--list-tools"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.decode()) == replies[1]["result"], proc.stdout
    assert PROTOCOL_REVISION.encode() in proc.stderr, proc.stderr


def scenario_malformed_ids_answer_parse_error(binary):
    for bad in ['--', '01', '1.', '+1', '1e']:
        text = '{"jsonrpc":"2.0","id":%s,"method":"ping"}' % bad
        replies, _ = session(binary, [INITIALIZE, text])
        error = replies[1]["error"]
        assert error["code"] == -32700, (bad, replies[1])
        assert replies[1]["id"] is None, (bad, replies[1])


def scenario_numeric_ids_are_echoed(binary):
    replies, _ = session(binary, [
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


def scenario_server_version_is_the_repository_version(binary):
    replies, _ = session(binary, [INITIALIZE])
    version = replies[0]["result"]["serverInfo"]["version"]
    expected = repository_version()
    if expected is None:
        assert version, replies[0]
    else:
        assert version == expected, (version, expected)


def scenario_key_path_refuses_to_start(binary):
    proc = subprocess.run([binary, "--key", "/nonexistent/owner.key"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30)
    assert proc.returncode != 0, proc
    assert proc.stdout == b"", proc.stdout


def scenario_stdio_client_drives_ariel_mcp_against_a_real_host(binary):
    host = Host(ARIEL_HOST)
    try:
        server = Stdio(binary, ["--host", HOST, "--port", str(host.port),
                                "--token", host.token])
        try:
            init = server.request(1, "initialize", INITIALIZE_PARAMS)
            assert init["result"]["protocolVersion"] == PROTOCOL_REVISION, init
            assert init["result"]["serverInfo"]["name"] == "ariel", init
            server.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            listed = server.request(2, "tools/list")
            assert listed["id"] == 2, listed
            assert isinstance(listed["result"]["tools"], list), listed
        finally:
            status = server.close()
        assert status == 0, "ariel-mcp exited %d at end of input" % status
    finally:
        host.stop()


def scenario_a_server_that_exits_fails_with_its_status(binary):
    server = Stdio(binary, ["--no-such-flag"])
    try:
        server.request(1, "initialize", INITIALIZE_PARAMS)
    except ServerExited as err:
        assert err.status == 2, err
        assert "--no-such-flag" in err.stderr, err.stderr
    else:
        raise AssertionError("a server that exited answered")
    finally:
        server.close()


def scenario_a_console_that_refuses_the_token_fails_with_its_word(binary):
    host = Host(ARIEL_HOST)
    try:
        assert console_answers(host.port, host.token)[-1] == "exit 0"
        try:
            console_answers(host.port, WRONG_TOKEN)
        except ConsoleRefused as err:
            assert "exit 70" in str(err), err
        else:
            raise AssertionError("a refused token was answered")
    finally:
        host.stop()


def scenario_check_against_a_listening_agent_exits_0_and_names_the_console(binary):
    host = Host(ARIEL_HOST)
    try:
        rc, out, err = run(binary, ["--host", HOST, "--port", str(host.port),
                                    "--token", host.token, "--check"])
        assert rc == 0, (rc, out, err)
        assert "%s:%d" % (HOST, host.port) in out, out
        assert os.uname().sysname in out, out
        assert err == "", err
    finally:
        host.stop()


def scenario_check_against_a_closed_port_exits_nonzero_with_one_line(binary):
    port = closed_port()
    rc, out, err = run(binary, ["--host", HOST, "--port", str(port),
                                "--token", TOKEN, "--check"])
    assert rc != 0, rc
    assert out == "", out
    assert len(err.splitlines()) == 1 and str(port) in err, err


def scenario_env_file_beats_the_environment(binary):
    host = Host(ARIEL_HOST)
    try:
        with tempfile.TemporaryDirectory() as scratch:
            env_file = write_env_file(scratch, PS5_HOST=HOST,
                                      ARIEL_TOKEN=host.token)
            rc, out, err = run(
                binary, ["--port", str(host.port), "--env-file", env_file,
                         "--timeout", "2", "--check"],
                clean_env(PS5_HOST="192.0.2.1", ARIEL_TOKEN=WRONG_TOKEN))
        assert rc == 0, (rc, out, err)
        assert "%s:%d" % (HOST, host.port) in out, out
    finally:
        host.stop()


def scenario_a_flag_beats_the_env_file(binary):
    host = Host(ARIEL_HOST)
    try:
        with tempfile.TemporaryDirectory() as scratch:
            env_file = write_env_file(scratch, PS5_HOST="192.0.2.1",
                                      ARIEL_TOKEN=WRONG_TOKEN)
            rc, out, err = run(
                binary, ["--host", HOST, "--port", str(host.port),
                         "--token", host.token, "--env-file", env_file,
                         "--timeout", "2", "--check"])
        assert rc == 0, (rc, out, err)
        assert "%s:%d" % (HOST, host.port) in out, out
    finally:
        host.stop()


def scenario_the_token_is_never_printed(binary):
    host = Host(ARIEL_HOST)
    try:
        rc, out, err = run(binary, ["--host", HOST, "--port", str(host.port),
                                    "--token", host.token, "--check"])
        assert rc == 0 and host.token not in out + err, (rc, out, err)
        rc, out, err = run(binary, ["--host", HOST, "--port", str(host.port),
                                    "--token", WRONG_TOKEN, "--check"])
        assert rc != 0 and WRONG_TOKEN not in out + err, (rc, out, err)
        with tempfile.TemporaryDirectory() as scratch:
            missing = os.path.join(scratch, "absent.env")
            rc, out, err = run(binary, ["--token", host.token,
                                        "--env-file", missing, "--check"])
            assert rc != 0 and missing in err, (rc, out, err)
            assert host.token not in out + err, (out, err)
    finally:
        host.stop()
    rc, out, err = run(binary, ["--list-tools"],
                       clean_env(ARIEL_TOKEN=TOKEN, PS5_HOST=HOST))
    assert rc == 0 and TOKEN not in out + err, (rc, err)


def scenario_a_missing_value_is_refused_by_name(binary):
    rc, out, err = run(binary, ["--host", HOST, "--port", "2324", "--check"])
    assert rc != 0 and out == "" and "no access token" in err, (rc, err)
    rc, out, err = run(binary, ["--token", TOKEN, "--check"])
    assert rc != 0 and out == "" and "no console address" in err, (rc, err)


def scenario_a_refused_token_names_the_consoles_word(binary):
    host = Host(ARIEL_HOST)
    try:
        rc, out, err = run(binary, ["--host", HOST, "--port", str(host.port),
                                    "--token", WRONG_TOKEN, "--check"])
        assert rc != 0 and out == "", (rc, out)
        assert "exit 70" in err and len(err.splitlines()) == 1, err
    finally:
        host.stop()


def scenario_key_paths_are_refused_with_check_too(binary):
    for flag in ("--key", "--owner-key"):
        rc, out, err = run(binary, [flag, "/nonexistent/owner.key", "--check"])
        assert rc != 0 and out == "", (flag, rc, out)
        assert flag in err, (flag, err)


def scenario_a_bad_timeout_is_refused_by_name(binary):
    rc, out, err = run(binary, ["--host", HOST, "--port", "2324",
                                "--token", TOKEN, "--timeout", "0", "--check"])
    assert rc != 0 and out == "" and "--timeout" in err, (rc, err)


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
    ("a stdio client drives ariel-mcp against a real ariel-host",
     scenario_stdio_client_drives_ariel_mcp_against_a_real_host),
    ("a server that exits fails with its status and stderr",
     scenario_a_server_that_exits_fails_with_its_status),
    ("a console that refuses the token fails with its word, exit 70",
     scenario_a_console_that_refuses_the_token_fails_with_its_word),
    ("--check against a listening agent exits 0 and names the console",
     scenario_check_against_a_listening_agent_exits_0_and_names_the_console),
    ("--check against a closed port exits non-zero with one line",
     scenario_check_against_a_closed_port_exits_nonzero_with_one_line),
    ("the env file beats the environment",
     scenario_env_file_beats_the_environment),
    ("a flag beats the env file",
     scenario_a_flag_beats_the_env_file),
    ("the token is never printed",
     scenario_the_token_is_never_printed),
    ("a missing address or token is refused by name",
     scenario_a_missing_value_is_refused_by_name),
    ("a refused token names the console's word, exit 70",
     scenario_a_refused_token_names_the_consoles_word),
    ("key flags are refused with --check too",
     scenario_key_paths_are_refused_with_check_too),
    ("a bad --timeout is refused by name",
     scenario_a_bad_timeout_is_refused_by_name),
]


def main():
    global ARIEL_HOST
    binary = sys.argv[1] if len(sys.argv) > 1 else "./ariel-mcp"
    ARIEL_HOST = sys.argv[2] if len(sys.argv) > 2 else "./ariel-host"
    for title, scenario in SCENARIOS:
        check(title, lambda scenario=scenario: scenario(binary))
    failed = [name for name, ok in results if not ok]
    if failed:
        print("\n%d mcp scenario(s) failed" % len(failed))
        return 1
    print("\nall %d mcp scenarios passed" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
