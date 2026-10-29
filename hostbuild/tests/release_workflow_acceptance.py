#!/usr/bin/env python3
"""Headless check of the ariel-mcp release workflow and of the binaries it ships.

Reads the workflow files as text and scans the host-built ariel-mcp. Where the
local compiler can cross-build for x86_64, it also builds one into a scratch
directory and scans that. It never publishes, never reads a key and never
touches a console.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

HOSTBUILD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(HOSTBUILD)
MCP_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "mcp-release.yml")
PAYLOAD_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "payload.yml")
PAYLOAD_WORKFLOW_SHA256 = "4a3d27fe90dd6309740857bdb4abdfe9234e8067cf832f570833f3c63e90d04b"

ASSETS = ["ariel-mcp-macos-arm64", "ariel-mcp-macos-x86_64", "ariel-mcp-linux-x86_64"]

TEST_KEY_HEX = "299e18435f88e321120e74f83f1b3f3f530ca0d51cad39f3ed45b86b8007f922"
# The markers the payload build pins a key or an anchor with (Makefile, platform_ps5.c).
BINARY_MARKERS = ["ARIEL_PUBKEY", "ARIEL_RECOVERY_PUBKEY", "ARIEL_TEST_PUBKEY",
                  "ps5_anchor", TEST_KEY_HEX]
# The workflow may name the markers when it scans for them; it may not pin, read or sign with a key.
WORKFLOW_MARKERS = ["secrets.", "PUBKEY=", "PUBKEY:", "ANCHOR=", "-DARIEL_",
                    "owner.key", "recovery.key", "ariel-sign", TEST_KEY_HEX]

CFLAGS = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
          "-O2", "-pthread", "-I..", "-I.", "-DARIEL_HOST_BUILD=1",
          '-DMCP_SERVER_VERSION="0.0.0"']

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


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def steps(text):
    """Return (title, body) for each step of a workflow, in order."""
    found = []
    for line in text.splitlines():
        if line.strip().startswith("- name:"):
            found.append([line.strip()[len("- name:"):].strip(), []])
        elif found:
            found[-1][1].append(line)
    return [(title, "\n".join(body)) for title, body in found]


def scan_binary(path):
    with open(path, "rb") as handle:
        data = handle.read()
    hits = [marker for marker in BINARY_MARKERS if marker.encode() in data]
    assert not hits, "%s carries %s" % (os.path.basename(path), hits)


def cross_compiles_x86_64(cc):
    with tempfile.TemporaryDirectory() as scratch:
        source = os.path.join(scratch, "probe.c")
        with open(source, "w") as handle:
            handle.write("int main(void) { return 0; }\n")
        probe = subprocess.run(
            [cc, "-arch", "x86_64", "-o", os.path.join(scratch, "probe"), source],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return probe.returncode == 0


def scenario_workflow_names_the_three_assets():
    text = read_text(MCP_WORKFLOW)
    for asset in ASSETS:
        assert asset in text, "%s is not named in %s" % (asset, MCP_WORKFLOW)


def scenario_missing_binary_fails_the_release():
    for title, body in steps(read_text(MCP_WORKFLOW)):
        if ("missing" in title.lower() and all(a in body for a in ASSETS)
                and re.search(r"(test|\[) -[sfe] ", body) and "exit 1" in body):
            return
    raise AssertionError("no step fails the release when a binary is missing")


def scenario_workflow_scans_binaries_for_key_and_anchor_markers():
    for title, body in steps(read_text(MCP_WORKFLOW)):
        if ("grep" in body and "ARIEL_PUBKEY" in body and "ps5_anchor" in body
                and "exit 1" in body):
            return
    raise AssertionError("no step fails the release when a binary carries a key or an anchor")


def scenario_workflow_references_no_key_anchor_or_secret():
    text = read_text(MCP_WORKFLOW)
    for marker in WORKFLOW_MARKERS:
        assert marker not in text, "the workflow references %r" % marker


def scenario_publishes_on_release_and_no_payload():
    text = read_text(MCP_WORKFLOW)
    assert re.search(r"^\s*release:", text, re.M) and "published" in text, (
        "the workflow does not run on a published release")
    assert "ariel-ps5" not in text, "the workflow names the payload"


def scenario_payload_workflow_is_untouched():
    with open(PAYLOAD_WORKFLOW, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assert digest == PAYLOAD_WORKFLOW_SHA256, (
        "payload.yml differs from its base commit (sha256 %s)" % digest)


def scenario_host_build_binary_carries_no_key_or_anchor():
    scan_binary(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HOSTBUILD, "ariel-mcp"))


def scenario_x86_64_cross_build_carries_no_key_or_anchor():
    with tempfile.TemporaryDirectory() as scratch:
        out = os.path.join(scratch, "ariel-mcp")
        subprocess.run(
            [os.environ.get("CC", "cc"), "-arch", "x86_64", *CFLAGS, "-o", out,
             "mcp_main.c", "mcp.c", "mcp_link.c"],
            cwd=HOSTBUILD, check=True)
        scan_binary(out)


def main():
    scenarios = [
        ("the workflow names all three ariel-mcp assets", scenario_workflow_names_the_three_assets),
        ("the workflow fails the release when a binary is missing",
         scenario_missing_binary_fails_the_release),
        ("the workflow scans the binaries for key and anchor markers",
         scenario_workflow_scans_binaries_for_key_and_anchor_markers),
        ("the workflow references no key, anchor or secret",
         scenario_workflow_references_no_key_anchor_or_secret),
        ("the workflow runs on a published release and publishes no payload",
         scenario_publishes_on_release_and_no_payload),
        ("the payload workflow is byte-identical to its base commit",
         scenario_payload_workflow_is_untouched),
        ("the host build's ariel-mcp carries no key or anchor",
         scenario_host_build_binary_carries_no_key_or_anchor),
    ]
    cc = os.environ.get("CC", "cc")
    if cross_compiles_x86_64(cc):
        scenarios.append(("the x86_64 cross build of ariel-mcp carries no key or anchor",
                          scenario_x86_64_cross_build_carries_no_key_or_anchor))
    else:
        print("SKIP the x86_64 cross build: %s cannot target x86_64 here" % cc)
    for title, scenario in scenarios:
        check(title, scenario)
    failed = [name for name, ok in results if not ok]
    if failed:
        print("\n%d release scenario(s) failed" % len(failed))
        return 1
    print("\nall %d release scenarios passed" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
