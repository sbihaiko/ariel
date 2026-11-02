"""Put the built runtime and the spike app on the console, then start them.

The console has no loader port open, so the ELFs are started by the telnet
shell, which runs a path with elfldr_spawn. Everything else goes over ftpsrv.
Both launchers default to 8090 (HTTP), 8091 (REPL) and 8092 (supervisor) when
they receive no arguments, which is what a shell-started ELF gets.
"""

import argparse
import os
import sys
import time

import deploy


def push(host, local, remote_root):
    conn = deploy.ftp(host)
    try:
        return deploy.upload_tree(conn, local, remote_root)
    finally:
        conn.quit()


def push_file(host, local, remote):
    conn = deploy.ftp(host)
    try:
        deploy.upload(conn, local, remote)
    finally:
        conn.quit()


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=deploy.DEFAULT_HOST)
    p.add_argument("--build", required=True, help="ps5-python build/ps5 directory")
    p.add_argument("--state", required=True, help="local directory holding the console state files")
    p.add_argument("--app", default="ps5git", help="local app bundle directory")
    p.add_argument("--no-start", action="store_true")
    p.add_argument("--wait", type=float, default=2.0)
    args = p.parse_args(argv)

    runtime = os.path.join(args.build, "cpython-lib")
    web = os.path.join(os.path.dirname(os.path.abspath(args.build)), "..", "web")
    web = os.path.normpath(web)

    pushed = 0
    pushed += push(args.host, runtime, "/data/python/runtime/cpython-lib")
    pushed += push(args.host, web, "/data/python/web")
    pushed += push(args.host, args.app, "/data/python/apps/" + os.path.basename(args.app.rstrip("/")))
    pushed += push(args.host, args.state, "/data/ps5-git")
    for name in ("python-web.elf", "python-app-supervisor.elf"):
        push_file(args.host, os.path.join(args.build, name), "/data/python/runtime/" + name)
        pushed += 1
    print(f"uploaded {pushed} files")

    if args.no_start:
        return 0

    deploy.run_elf(args.host, "/data/python/runtime/python-app-supervisor.elf", args.wait)
    time.sleep(1)
    deploy.run_elf(args.host, "/data/python/runtime/python-web.elf", args.wait)
    print("started supervisor and launcher")
    return 0


if __name__ == "__main__":
    sys.exit(main())
