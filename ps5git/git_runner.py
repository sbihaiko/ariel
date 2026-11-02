"""Git operations for the console, implemented with dulwich.

Nothing here starts a process. The token is read from a mode-0600 file and is
passed to the client as a credential, never written into the repository config,
a commit message or a log line.
"""

import os
import stat
import sys
import time
import urllib.error
import urllib.request

from dulwich import porcelain
from dulwich.config import ConfigFile
from dulwich.repo import Repo

STATE = os.environ.get("PS5GIT_STATE", "/data/ps5-git")
TOKEN_FILE = os.environ.get("PS5GIT_TOKEN_FILE", STATE + "/secrets/token")
CA_FILE = os.environ.get("PS5GIT_CA_FILE", STATE + "/ca.pem")
IDENTITY = b"ps5 <ps5@ariel.invalid>"


def log(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def token():
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        value = f.read().strip()
    if not value:
        raise SystemExit("TOKEN REFUSED empty")
    return value


def token_mode_ok():
    mode = stat.S_IMODE(os.stat(TOKEN_FILE).st_mode)
    return mode == 0o600, oct(mode)


def config():
    cfg = ConfigFile()
    cfg.set((b"http",), b"sslVerify", b"true")
    cfg.set((b"http",), b"sslCAInfo", CA_FILE.encode())
    cfg.set((b"user",), b"name", b"ps5")
    cfg.set((b"user",), b"email", b"ps5@ariel.invalid")
    return cfg


def head(repo):
    try:
        return repo.head().decode()
    except KeyError:
        return "0" * 40


def auth_check(owner_repo):
    ok, mode = token_mode_ok()
    if not ok:
        log("AUTH FAIL token mode=%s expected=0600" % mode)
        return 1
    req = urllib.request.Request(
        "https://api.github.com/repos/" + owner_repo,
        headers={
            "Authorization": "Bearer " + token(),
            "Accept": "application/vnd.github+json",
            "User-Agent": "ps5-git-spike",
        },
    )
    try:
        import ssl

        ctx = ssl.create_default_context(cafile=CA_FILE)
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            import json

            data = json.loads(r.read().decode())
    except Exception as exc:  # noqa: BLE001
        log("AUTH FAIL %s: %s" % (type(exc).__name__, exc))
        return 1
    permissions = data.get("permissions") or {}
    if not permissions.get("push"):
        log("AUTH FAIL no push permission")
        return 1
    log("AUTH OK scope=repo:%s mode=%s" % (owner_repo, mode))
    return 0


def clone(url, target):
    porcelain.clone(
        url,
        target,
        branch=b"main",
        username="x-access-token",
        password=token(),
        config=config(),
    )
    repo = Repo(target)
    log("CLONE " + head(repo))
    return 0


def pull(directory, branch):
    repo = Repo(directory)
    before = head(repo)
    ref = b"refs/heads/" + branch.encode()
    porcelain.pull(
        repo,
        remote_location="origin",
        refspecs=[ref + b":" + ref],
        ff_only=True,
        fast_forward=True,
        username="x-access-token",
        password=token(),
        config=config(),
    )
    after = head(repo)
    porcelain.reset(repo, "hard", after)
    log("PULL %s..%s" % (before, after))
    return 0


def switch_to_results(repo, main_sha):
    refs = repo.get_refs()
    target = b"refs/heads/ps5/results"
    if target in refs:
        porcelain.checkout(repo, b"ps5/results")
    else:
        porcelain.checkout(repo, target=main_sha, new_branch=b"ps5/results")
    try:
        porcelain.merge(
            repo,
            [main_sha],
            author=IDENTITY,
            committer=IDENTITY,
        )
        log("RESULTS MERGE " + main_sha.id.decode())
    except Exception as exc:  # noqa: BLE001
        log("RESULTS MERGE CONFLICT %s: %s" % (type(exc).__name__, exc))
        raise SystemExit(1)


def commit_results(directory, source, message):
    repo = Repo(directory)
    main_sha = repo[b"refs/heads/main"]
    remote_url = repo.get_config().get((b"remote", b"origin"), b"url").decode()
    switch_to_results(repo, main_sha)
    rel = "results/" + os.path.basename(source)
    dest = os.path.join(directory, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(source, "rb") as f:
        data = f.read()
    with open(dest, "wb") as f:
        f.write(data)
    porcelain.add(repo, paths=[rel.encode()])
    sha = porcelain.commit(
        repo,
        message=message.encode(),
        author=IDENTITY,
        committer=IDENTITY,
    )
    log("COMMIT " + sha.decode())
    porcelain.push(
        repo,
        remote_location=remote_url,
        refspecs=[b"refs/heads/ps5/results:refs/heads/ps5/results"],
        username="x-access-token",
        password=token(),
        config=config(),
    )
    log("PUSH OK " + sha.decode())
    porcelain.checkout(repo, b"main")
    return sha


def show(directory, rev):
    repo = Repo(directory)
    commit = repo[rev.encode()]
    log("SHA " + commit.id.decode())
    log("AUTHOR " + commit.author.decode(errors="replace"))
    log("COMMITTER " + commit.committer.decode(errors="replace"))
    log("MESSAGE " + commit.message.decode(errors="replace").strip())
    return 0


def run(argv):
    if not argv:
        log("usage: git_runner <clone|pull|auth-check|commit-results|show|head>")
        return 2
    cmd = argv[0]
    if cmd == "auth-check":
        return auth_check(argv[1])
    if cmd == "clone":
        return clone(argv[1], argv[2])
    if cmd == "pull":
        directory = argv[argv.index("--dir") + 1]
        branch = argv[argv.index("--branch") + 1] if "--branch" in argv else "main"
        return pull(directory, branch)
    if cmd == "head":
        repo = Repo(argv[argv.index("--dir") + 1])
        log(head(repo))
        return 0
    if cmd == "commit-results":
        directory = argv[argv.index("--dir") + 1]
        source = argv[argv.index("--file") + 1]
        message = argv[argv.index("--message") + 1]
        commit_results(directory, source, message)
        return 0
    if cmd == "show":
        directory = argv[argv.index("--dir") + 1]
        return show(directory, argv[argv.index("--rev") + 1])
    log("unknown command " + cmd)
    return 2


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
