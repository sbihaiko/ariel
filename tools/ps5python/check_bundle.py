"""Check that a PS5 Python bundle matches its manifest.

The manifest lists every file the bundle carries, except the manifest and the
pins record, which sit beside it.
A missing file, an unexpected file, a changed byte or a native library fails the
check and names the path, so a bundle cannot pass by looking roughly right.
"""

import argparse
import hashlib
import json
import os
import sys

NATIVE_SUFFIXES = (".so", ".sprx", ".dylib", ".dll")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("bundle")
    args = p.parse_args(argv)

    root = args.bundle
    manifest_path = os.path.join(root, "MANIFEST.json")
    if not os.path.isfile(manifest_path):
        print(f"BUNDLE FAIL missing MANIFEST.json at {manifest_path}")
        return 1
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    files = manifest.get("files", {})

    actual = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if rel in ("MANIFEST.json", "PINS.json"):
                continue
            actual.append(rel)

    expected = set(files)
    seen = set(actual)
    problems = []
    for rel in sorted(expected - seen):
        problems.append(f"missing {rel}")
    for rel in sorted(seen - expected):
        problems.append(f"unexpected {rel}")
    for rel in sorted(seen & expected):
        if rel.endswith(NATIVE_SUFFIXES):
            problems.append(f"native library {rel}")
            continue
        digest = sha256(os.path.join(root, rel))
        if digest != files[rel]:
            problems.append(f"changed {rel} {digest} != {files[rel]}")

    if problems:
        for line in problems:
            print("BUNDLE FAIL " + line)
        return 1

    print(f"BUNDLE OK {len(seen)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
