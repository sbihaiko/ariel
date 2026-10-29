#!/usr/bin/env python3
"""Headless acceptance for ariel-mcp, driven over stdio as a client does.

Spawns the host-built server and writes one JSON-RPC 2.0 object per line to its
standard input, reading one per line from its standard output. No stub stands
in for the protocol: every answer is what the binary wrote to the wire.
"""

import json
import os
import subprocess
import sys

PROTOCOL_REVISION = "2026-07-28"
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


def session(binary, lines):
    """Run the server with lines on stdin and return its parsed replies."""
    payload = "".join(json.dumps(line) + "\n" for line in lines)
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


INITIALIZE = request(1, "initialize", {
    "protocolVersion": PROTOCOL_REVISION,
    "capabilities": {},
    "clientInfo": {"name": "acceptance", "version": "0"},
})


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


def scenario_key_path_refuses_to_start(binary):
    proc = subprocess.run([binary, "--key", "/nonexistent/owner.key"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30)
    assert proc.returncode != 0, proc
    assert proc.stdout == b"", proc.stdout


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
    ("--list-tools prints what tools/list answers",
     scenario_list_tools_matches_tools_list),
    ("a key path refuses to start and prints nothing",
     scenario_key_path_refuses_to_start),
]


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./ariel-mcp"
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
