"""Assemble the reproducible PS5 Python bundle.

The bundle is the runtime, the app and every pure-Python dependency it needs.
The dependencies are fetched as pinned sdists and verified by SHA-256, never
installed with pip on the console and never taken from a native wheel.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request

PACKAGES = [
    {
        "name": "dulwich",
        "version": "1.2.20",
        "url": "https://files.pythonhosted.org/packages/18/92/e47acfff672d6219d1bba1c210f902c1ad4a58d8c68eb89fe0b786f00a68/dulwich-1.2.20.tar.gz",
        "sha256": "28e1f48098d2cb157e722588466070cbefdfe8093c2a141c568b01362296c0f3",
        "dir": "dulwich",
        "copy": ["dulwich"],
        "drop": ["dulwich/tests"],
    },
    {
        "name": "urllib3",
        "version": "2.8.0",
        "url": "https://files.pythonhosted.org/packages/e3/05/b17359e1cefb4f909b5e40b1b90a496d987258916dbbf88e842c729f510e/urllib3-2.8.0.tar.gz",
        "sha256": "63bf2ead4c879426ebf22ef2a781eeb4aa3b4ae798a0435506f8687fd5bb9b63",
        "dir": "urllib3",
        "copy": ["urllib3"],
        "drop": [],
    },
    {
        "name": "certifi",
        "version": "2026.10.23",
        "url": "https://files.pythonhosted.org/packages/fd/11/b524cbd9bbdaca58608e4cf4053fd463417549e1959fa8d3aa18319f9555/certifi-2026.10.23.tar.gz",
        "sha256": "a9895e6e2758b371e0545e321a3a8fd1fcfd9829ada8824a936dfb16aaaf36cd",
        "dir": "certifi",
        "copy": ["certifi"],
        "drop": [],
    },
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(pkg, cache):
    os.makedirs(cache, exist_ok=True)
    name = pkg["url"].rsplit("/", 1)[-1]
    archive = os.path.join(cache, name)
    if not os.path.isfile(archive):
        with urllib.request.urlopen(pkg["url"], timeout=120) as r, open(archive, "wb") as f:
            shutil.copyfileobj(r, f)
    digest = sha256(archive)
    if digest != pkg["sha256"]:
        raise SystemExit(f"pin mismatch for {name}: {digest}")
    root = os.path.join(cache, pkg["name"] + "-" + pkg["version"])
    if not os.path.isdir(root):
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(cache, filter="data")
    return root


def copytree(src, dst):
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--python-build", required=True, help="checkout of ps5-python")
    p.add_argument("--out", default="dist/ps5-python")
    p.add_argument("--cache", default=os.path.expanduser("~/.cache/ariel/ps5python"))
    args = p.parse_args(argv)

    src = args.python_build
    out = args.out
    build = os.path.join(src, "build", "ps5")
    for rel in ("python-web.elf", "python-app-supervisor.elf", "cpython-lib"):
        if not os.path.exists(os.path.join(build, rel)):
            raise SystemExit(f"missing build artifact: {os.path.join(build, rel)}")

    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    for rel in ("python-web.elf", "python-app-supervisor.elf"):
        shutil.copy2(os.path.join(build, rel), os.path.join(out, rel))
    copytree(os.path.join(build, "cpython-lib"), os.path.join(out, "cpython-lib"))
    copytree(os.path.join(src, "web"), os.path.join(out, "web"))

    app = os.path.join(out, "apps", "ps5-git")
    os.makedirs(app)
    for name in ("app.json", "main.py", "git_runner.py"):
        shutil.copy2(os.path.join("ps5git", name), os.path.join(app, name))
    lib = os.path.join(app, "lib")
    os.makedirs(lib)

    pins = {"packages": []}
    for pkg in PACKAGES:
        root = fetch(pkg, args.cache)
        for sub in pkg["copy"]:
            copytree(os.path.join(root, sub), os.path.join(lib, os.path.basename(sub)))
        for drop in pkg["drop"]:
            shutil.rmtree(os.path.join(lib, drop), ignore_errors=True)
        pins["packages"].append(
            {"name": pkg["name"], "version": pkg["version"], "url": pkg["url"], "sha256": pkg["sha256"]}
        )

    version_file = os.path.join(src, "CPYTHON_VERSION.txt")
    with open(version_file, "r", encoding="utf-8") as f:
        pins["cpython"] = f.read().strip()
    pins["sdk"] = os.environ.get("PS5_PAYLOAD_SDK", "")
    try:
        pins["compiler"] = subprocess.run(
            [os.path.join(pins["sdk"], "bin", "prospero-clang"), "--version"],
            capture_output=True, text=True, timeout=30,
        ).stdout.splitlines()[0]
    except Exception as exc:  # noqa: BLE001
        pins["compiler"] = f"unavailable: {exc}"
    with open(os.path.join(out, "PINS.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, sort_keys=True)
        f.write("\n")

    files = {}
    for dirpath, _, filenames in os.walk(out):
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, out)
            if rel in ("MANIFEST.json", "PINS.json"):
                continue
            files[rel] = sha256(path)
    with open(os.path.join(out, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump({"files": files}, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"BUNDLE BUILT {len(files)} files at {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
