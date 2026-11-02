"""Deploy the PS5 Python runtime, app bundles and assets to the console.

The console has no package manager and no writable package index. This script
copies a local tree over ftpsrv (2121) and starts an ELF through the telnet
shell (2323), which runs it with elfldr_spawn.
"""

import argparse
import ftplib
import os
import socket
import sys
import time

DEFAULT_HOST = os.environ.get("PS5_HOST", "192.168.68.108")
FTP_PORT = int(os.environ.get("PS5_FTP_PORT", "2121"))
TELNET_PORT = int(os.environ.get("PS5_TELNET_PORT", "2323"))


def ftp(host):
    conn = ftplib.FTP()
    conn.connect(host, FTP_PORT, timeout=30)
    conn.login()
    return conn


def ensure_dir(conn, path):
    parts = [p for p in path.split("/") if p]
    cur = ""
    for part in parts:
        cur += "/" + part
        try:
            conn.mkd(cur)
        except ftplib.error_perm:
            pass


def upload(conn, local, remote):
    ensure_dir(conn, remote.rsplit("/", 1)[0])
    with open(local, "rb") as f:
        conn.storbinary("STOR " + remote, f)


def upload_tree(conn, local_root, remote_root):
    count = 0
    for dirpath, dirnames, filenames in os.walk(local_root):
        rel = os.path.relpath(dirpath, local_root)
        remote_dir = remote_root if rel == "." else remote_root + "/" + rel.replace(os.sep, "/")
        ensure_dir(conn, remote_dir)
        for name in filenames:
            upload(conn, os.path.join(dirpath, name), remote_dir + "/" + name)
            count += 1
    return count


def run_elf(host, path, wait=2.0):
    with socket.create_connection((host, TELNET_PORT), timeout=30) as s:
        banner = s.recv(4096)
        s.sendall((path + "\n").encode())
        time.sleep(wait)
        try:
            return banner + s.recv(4096)
        except socket.timeout:
            return banner


def cmd_app(args):
    conn = ftp(args.host)
    n = upload_tree(conn, args.local, "/data/python/apps/" + args.id)
    conn.quit()
    print(f"app {args.id}: {n} files")
    return 0


def cmd_tree(args):
    conn = ftp(args.host)
    n = upload_tree(conn, args.local, args.remote)
    conn.quit()
    print(f"tree {args.local} -> {args.remote}: {n} files")
    return 0


def cmd_file(args):
    conn = ftp(args.host)
    upload(conn, args.local, args.remote)
    conn.quit()
    print(f"file {args.local} -> {args.remote}")
    return 0


def cmd_start(args):
    for path in args.path:
        out = run_elf(args.host, path, args.wait)
        sys.stdout.buffer.write(out)
        sys.stdout.write(f"\nstarted {path}\n")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("app"); s.add_argument("id"); s.add_argument("local"); s.set_defaults(fn=cmd_app)
    s = sub.add_parser("tree"); s.add_argument("local"); s.add_argument("remote"); s.set_defaults(fn=cmd_tree)
    s = sub.add_parser("file"); s.add_argument("local"); s.add_argument("remote"); s.set_defaults(fn=cmd_file)
    s = sub.add_parser("start"); s.add_argument("path", nargs="+"); s.add_argument("--wait", type=float, default=2.0); s.set_defaults(fn=cmd_start)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
