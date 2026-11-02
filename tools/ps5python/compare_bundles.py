"""Compare two built bundles file by file.

The manifest of each bundle is the record of what was built. Two clean builds
are the same build only when every path and every hash agree; anything else is
named, including a file present in one bundle and absent from the other.
"""

import argparse
import json
import os
import sys


def manifest(root):
    path = os.path.join(root, "MANIFEST.json")
    if not os.path.isfile(path):
        raise SystemExit(f"missing MANIFEST.json in {root}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f).get("files", {})


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("first")
    p.add_argument("second")
    args = p.parse_args(argv)

    a = manifest(args.first)
    b = manifest(args.second)
    problems = []
    for rel in sorted(set(a) - set(b)):
        problems.append(f"only in first: {rel}")
    for rel in sorted(set(b) - set(a)):
        problems.append(f"only in second: {rel}")
    for rel in sorted(set(a) & set(b)):
        if a[rel] != b[rel]:
            problems.append(f"differs: {rel} {a[rel]} != {b[rel]}")

    if problems:
        for line in problems:
            print("REPRO FAIL " + line)
        return 1
    print(f"REPRO OK {len(a)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
