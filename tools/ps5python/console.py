"""Host-side access to the console for the PS5 Git spike.

The console runs the CPython web launcher on port 8090 and ftpsrv on 2121.
This module is the single place the host reaches either of them, so tests and
the end-to-end check do not carry their own socket code.
"""

import argparse
import ftplib
import json
import os
import sys
import urllib.request

DEFAULT_HOST = os.environ.get("PS5_HOST", "192.168.68.108")
HTTP_PORT = int(os.environ.get("PS5_HTTP_PORT", "8090"))
FTP_PORT = int(os.environ.get("PS5_FTP_PORT", "2121"))


def base(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def get_json(host: str, path: str, timeout: float = 30) -> dict:
    with urllib.request.urlopen(base(host, HTTP_PORT) + path, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def ftp(host: str) -> ftplib.FTP:
    conn = ftplib.FTP()
    conn.connect(host, FTP_PORT, timeout=30)
    conn.login()
    return conn


def cmd_status(args) -> int:
    print(json.dumps(get_json(args.host, "/api/status"), indent=2))
    return 0


def cmd_logs(args) -> int:
    data = get_json(args.host, f"/api/logs?since={args.since}")
    print(json.dumps(data, indent=2) if args.json else data.get("data", ""), end="")
    return 0


def cmd_launch(args) -> int:
    from urllib.parse import urlencode
    query = urlencode({"app": args.app, "args": args.args})
    print(json.dumps(get_json(args.host, f"/api/launch?{query}"), indent=2))
    return 0


def cmd_stop(args) -> int:
    req = urllib.request.Request(
        base(args.host, HTTP_PORT) + f"/api/app/stop?job_id={args.job}", method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        print(r.read().decode("utf-8"))
    return 0


def cmd_fetch(args) -> int:
    conn = ftp(args.host)
    chunks = []
    conn.retrbinary(f"RETR {args.remote}", chunks.append)
    conn.quit()
    data = b"".join(chunks)
    if args.dest == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(args.dest, "wb") as f:
            f.write(data)
    return 0


def cmd_put(args) -> int:
    conn = ftp(args.host)
    parent = args.remote.rsplit("/", 1)[0]
    parts = [p for p in parent.split("/") if p]
    cur = ""
    for p in parts:
        cur += "/" + p
        try:
            conn.mkd(cur)
        except ftplib.error_perm:
            pass
    with open(args.local, "rb") as f:
        conn.storbinary(f"STOR {args.remote}", f)
    conn.quit()
    return 0


def cmd_sha(args) -> int:
    conn = ftp(args.host)
    size = conn.size(args.remote)
    print(f"{size} {args.remote}")
    conn.quit()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status"); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("logs"); s.add_argument("--job", type=int); s.add_argument("--since", default="0"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_logs)
    s = sub.add_parser("launch"); s.add_argument("--app", required=True); s.add_argument("--args", default=""); s.set_defaults(fn=cmd_launch)
    s = sub.add_parser("stop"); s.add_argument("--job", type=int, required=True); s.set_defaults(fn=cmd_stop)
    s = sub.add_parser("fetch"); s.add_argument("remote"); s.add_argument("dest", nargs="?", default="-"); s.set_defaults(fn=cmd_fetch)
    s = sub.add_parser("put"); s.add_argument("local"); s.add_argument("remote"); s.set_defaults(fn=cmd_put)
    s = sub.add_parser("sha"); s.add_argument("remote"); s.set_defaults(fn=cmd_sha)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
