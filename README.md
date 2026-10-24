# Ariel

**A PS5 payload shell built for AI agents.**

Ariel is a fork of [ps5-payload-dev/shsrv](https://github.com/ps5-payload-dev/shsrv), the telnet-like shell server for jailbroken PS5 consoles. It keeps everything shsrv already does and grows it in one direction: letting an AI agent, such as Claude, talk to the console safely. The agent should be able to inspect the system, download payloads from GitHub, run them, and recover on its own when something crashes, without ever being able to leave the console in a broken state.

> **Status:** early development. Today the code is still shsrv. The features described under [Goals](#goals) are the roadmap, not something that already works.

---

## Why Ariel exists

Coding agents like Claude Code are good at diagnosing systems: they run a command, read the output, form a hypothesis and run the next command. A jailbroken PS5 is a system worth diagnosing, but it is a hostile place for an agent:

- There is no real Unix shell. Agents cannot run Claude Code or Node.js on the console itself.
- The existing shell (shsrv) was built for humans typing into telnet. Arguments are split on whitespace with no quoting, output is free-form text, there is no exit status and no pagination.
- Getting a new payload onto the console is a manual process (download, FTP, send to the ELF loader), and a bad payload can crash or hang the system.
- Everything lives in RAM. A reboot wipes the jailbreak and every running payload.

Ariel closes that gap. The idea is that an agent connects to one endpoint on the console and gets a predictable, safe, recoverable interface to it.

## Goals

### Stage 1: hello world, end to end

The first milestone is the smallest loop that proves the whole idea: an agent builds a payload on a computer, pushes it to the console, the owner approves it with a key they hold, and the agent runs it and reads its output. The [quick start](docs/quick-start.md#after-stage-1) is this stage's acceptance test, and it runs headless in CI against a host build of Ariel.

- **An agent port (2324)** next to the telnet shell: raw TCP with no telnet negotiation, so a binary upload arrives intact. One command per connection after `auth`, no prompts, and every reply ends with an `exit <status>` line ([exit codes](docs/exit-codes.md)).
- **An access token** on the agent port. Every connection starts with `auth <token>`; Ariel shows the token on the console at first start.
- **`payload push <name> <size> <sha256>`** uploads a locally built ELF over the same connection, so no FTP server is needed. Ariel stages it and the console shows its hash.
- **Approval by the owner's key.** A push answers `approval_required <id>`; the owner signs the exact action with a key the agent does not hold. Approving a pushed build also approves running that exact build.
- **`payload commit <staging-id>`** moves an approved upload into Ariel's store. The bytes are sent once.
- **`payload list`** reads the state file and answers one `payload <name> ...` line per installed payload, with its source, version identifiers, hash, path, whether it is running and `previous=<sha256|->`, the build the last commit replaced (`-` when there is none). It changes nothing.
- **`payload run --wait <name>`** runs a committed payload in the foreground through the ELF loader (no `chmod`), streams its output and reports the payload's exit status on a `status <n>` line, apart from the protocol's `exit` line.
- **A host build** of Ariel behind a platform port, with a test clock and a virtual controller that can only deny, for tests. It never ships in the PS5 build.

The agent port offers only these commands. Everything else, including every command that changes the system, stays on the telnet shell exactly as in upstream shsrv until Stage 2. Until then, approval protects only the agent port: anyone who can reach the telnet shell can still do what they can today.

**What protects the telnet shell is the [trusted-network rule](#safety-model) and nothing else.** It listens on port 2323 on every interface, asks for no token and no approval, and is the owner's escape hatch: the approval gate does not cover it. The decision is [ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md) decision 10, and [docs/telnet-boundary.md](docs/telnet-boundary.md) holds the manual check for this boundary. The headless suite covers the other half: the agent port refuses every command that changes the system, and a push waits for an approval.

### Stage 2: persist and recover

Make the console safe to leave in an agent's hands:

1. **Download a payload from a GitHub release**, by repository name, following the latest release or a pinned tag, and only from an allowlist of sources. Ariel records the immutable identifiers of what it downloaded (release ID, asset ID), since tags can be moved.
2. **Verify it** with SHA-256 before anything is executed. A hash published in the same release only detects corruption, not tampering, so the expected hash must come from somewhere Ariel trusts: either it is pinned in the allowlist, or the owner approves the new hash with their key (see [Safety model](#safety-model)), after which it is pinned.
3. **Run it in the background** through the ELF loader, tracking its PID and capturing its output to a log the agent can read later.
4. **Persist it**: record what is installed (source, identifiers, hash, path) in a state file under `/data`, and keep the autoload configuration up to date so payloads come back after a reboot. Approving an installation explicitly includes approving that the payload runs on every boot. `autoload safe-boot` skips autoload on the next boot, so a payload that crashes the console at startup can always be removed.
5. **Roll back on failure**: keep the previous version of every payload and a snapshot of the autoload configuration before each change. Changes are atomic and recorded in a journal, so a change interrupted by a crash or power loss is completed or undone the next time Ariel starts. A new version that crashes or fails its health check (explicit criteria and a timeout, defined per payload) is replaced by the last known good version automatically.
6. **Gate everything that changes the system on the agent port**: every existing command that changes the system, starts code or reveals the environment, including running an ELF by path (the full list is in [Command coverage](#command-coverage)). The telnet shell is not gated: its copies of these commands stay ungated and need no token, as in upstream shsrv. It is the owner's escape hatch, and gating it needs a designed recovery path for a lost key first ([ADR-0008](docs/adr/0008-the-telnet-shell-stays-outside-the-gate.md), [#15](https://github.com/sbihaiko/ariel/issues/15), [the telnet boundary](docs/telnet-boundary.md)).

Ariel itself is never overwritten while it is running, so the agent can never lock itself out.

Ariel is not the boot loader: autoload is run at boot by another loader, and Ariel manages its configuration and keeps itself in it. So Ariel cannot re-check a payload's hash at boot; making Ariel the boot-time autoloader is a later decision.

New commands in this stage (see [Command coverage](#command-coverage)):

- `payload install | run | list | logs | rollback | config`. `run` without `--wait` starts a payload in the background and captures its output to a log; `config` sets a payload's health check.
- `autoload show | edit | safe-boot`, to inspect the autoload configuration and to boot without it when a payload keeps crashing.
- `sha256sum`, because the existing `sum` is a BSD checksum, not SHA-256.
- `unzip` and `tar`, because many GitHub releases ship payloads inside an archive.
- `reboot`, gated, to test that installed payloads survive a restart.
- `approval status <id>`, to poll a pending approval.
- `audit tail [n]`, to read the audit log: the newest `n` lines, at most 64.

### Stage 3: an interface agents can rely on

Once the agent can operate the console safely, make the shell easy for it to use correctly:

- Proper argument parsing with quotes.
- Exit status and a separate error channel for every command, extending the Stage 1 grammar to all of them.
- Optional JSON output for `ps`, `ls`, `stat` and similar commands.
- Pagination and size limits, so a large directory or log does not flood the agent's context.
- Strictly non-interactive commands: no prompts in the middle of a session.
- No pipes or redirection. Commands that would need them get their own flags instead, such as `grep -c` for `| wc -l` and `--limit` for `| head`.

New and extended commands in this stage:

- Reading logs and large files: `head`, `tail`, `wc`, and a size limit on `cat`.
- Writing files without redirection: `write <path>`, which reads the content from stdin.
- Missing flags on existing commands: `ls -l -a`, `grep -r -l -c`, more `find` predicates, `rm -r` and `cp -r`.
- Diagnostics: `date`, `dmesg`, `du`, a `sysinfo` command that aggregates `uname`, `uptime` and memory, and `timeout` so a command cannot hang the connection.
- Optional: `diff` and network diagnostics (`ifconfig`, `netstat`, `ping`).

### Stage 4 (optional): sessions

Stages 1 to 3 are enough for an agent to operate the console. Stages 4 and 5 are optional conveniences on top of them.

Agents usually reach the console through one-shot connections (one command per connection, e.g. `printf 'auth %s\nls --json /data\n' "$ARIEL_TOKEN" | nc ps5 2324`), so state such as the working directory would otherwise be lost between commands. Ariel keeps optional sessions on the console side:

- `session new` returns a random 128-bit session ID and its TTL. Prefixing a command with `@<sid>` runs it inside that session, and `session close` ends it.
- A session holds only minimal state: working directory, environment and timestamps. It carries no authorization. Creating a session requires the access token, and every gated command still needs its own approval. Payloads started from a session are not tied to it and keep running after it ends.
- Sessions expire after a period of inactivity, and the number of concurrent sessions is capped, so a client that forgets to close them cannot exhaust the console's RAM.
- An unknown or expired ID returns an explicit `session_expired` error instead of silently falling back, so the agent knows to open a new session (for example after a reboot).
- Session IDs are generated by a cryptographically secure random number generator and treated as secrets. Over plain-text connections they can still be sniffed, which is why they never authorize anything on their own.
- Sessions are isolated from each other, but the file system and installed payloads are shared. Stage 2 operations such as installing and rolling back take a global lock.
- Sessions are a convenience, not a requirement. Every command also works without one, using absolute paths.

### Stage 5 (optional): MCP

Expose the same capabilities as an [MCP](https://modelcontextprotocol.io) server, so any MCP client (Claude Code, Claude Desktop, or a local agent) can connect with structured tools instead of parsing shell text. The planned tool families are processes, payloads, file system, system information and logs. MCP is stateless since protocol version 2026-07-28, so a Stage 4 session ID is passed to each tool as an ordinary argument, as the specification recommends for server-minted handles.

## Command coverage

Which bash commands an agent can expect on Ariel. Each row is an Ariel command. The **bash equivalent** column is filled in only when the name differs from bash; an empty cell means the command has the same name in bash.

**Today:** ✅ complete · ⚠️ partial · ❌ missing. **Plan:** S1 to S4 are Stages 1 to 4. "Gated" commands need the owner's approval before they run (see [Safety model](#safety-model)).

| Ariel | bash equivalent | Today (shsrv) | Plan |
|---|---|---|---|
| `pwd`, `cd` | | ✅ | S4: working directory kept across connections with sessions |
| `ls` | | ⚠️ no flags | S3: `-l`, `-a`, `--json`, pagination |
| `stat`, `file` | | ✅ | S3: `--json` |
| `cat` | | ✅ | S3: size limit |
| `head`, `tail`, `wc` | | ❌ | S3 |
| `grep` | | ⚠️ only `-i`, `-n` | S3: `-r`, `-l`, `-c` |
| `find` | | ⚠️ only `-name`, `-type` | S3: more predicates |
| `cmp`, `hexdump` | | ✅ | |
| `diff` | | ❌ | S3, optional |
| `df` | | ✅ | |
| `du` | | ❌ | S3 |
| `mkdir`, `rmdir`, `touch`, `ln` | | ✅ | S2: gated |
| `cp`, `mv` | | ⚠️ no `-r` | S2: gated. S3: `-r` |
| `rm` | | ⚠️ one file, no `-r` | S2: gated. S3: `-r` |
| `chmod`, `chown`, `chgrp` | | ✅ | S2: gated |
| `write <path>` | `echo > file`, `tee` | ❌ | S3, gated |
| `tar`, `unzip` | | ❌ | S2 |
| `ps` | | ✅ | S3: `--json` |
| `procstat` | `/proc/<pid>/*` | ✅ | |
| `kill` | | ✅ | S2: gated, critical processes protected |
| `payload run` | `cmd &`, `nohup` | ❌ | S1: `--wait` runs an approved build in the foreground. S2: background runs with a log |
| `payload push`, `payload commit` | `scp`, `curl -T` | ❌ | S1, hash approved by the owner |
| `timeout` | | ❌ | S3 |
| `sleep`, `id`, `sync` | | ✅ | |
| `env`, `export`, `exec` | | ✅ | S2: gated |
| `sysinfo` | `uname`, `uptime`, `free` | ⚠️ raw values via `sysctl` | S3 |
| `date` | | ❌ | S3 |
| `dmesg` | | ❌ only through klogsrv | S3 |
| `mount`, `umount`, `chroot`, `mknod` | | ✅ | S2: gated |
| `reboot` | | ⚠️ host build simulates it; PS5 path not yet run on a console | S2: gated |
| `http2_get -o` | `curl -o`, `wget` | ✅ no verification | S2: gated and restricted to the download allowlist. `payload install` adds the hash check |
| `sha256sum` | | ❌ (`sum` is a BSD checksum) | S2 |
| `ifconfig`, `netstat`, `ping` | | ❌ | S3, optional |

PS5-specific commands with no bash equivalent: `hbldr`, `hbdbg`, `launch`, `pkg_install`, `suspend`, `notify`, `reptyr`, `authid`, `sfoinfo` and `sfocreate` (all in shsrv; from Stage 2 all but `authid`, `sfoinfo` and `sfocreate` are gated, and `sfocreate` joins them in #49), plus `payload` (Stage 1), `approval` and `autoload` (Stage 2) and `session` (Stage 4).

Out of scope: pipes, redirection, `&&`, shell variables and scripts, editors, `ssh`, `top` and package managers. The agent composes logic on its own side, on the computer it runs on.

## Safety model

An agent that can download, write and execute code on a console with kernel privileges needs firm limits. Ariel is designed around these rules:

- **Reading is allowed, within limits.** Inspecting processes, files and logs needs only the access token. Output is size-limited. `env` is gated, and Ariel's own secrets (its token and approval state) cannot be read through any gated command. The telnet shell is not gated and can still read them (see below).
- **Change is approved by the owner's signature.** Writing files, killing processes, mounting, rebooting, downloading and executing payloads are gated. Approving a payload version (at install or commit) also approves running that exact version, so a build is approved once, not once per run. A gated command does not run; Ariel answers with an `approval_required` error and an approval ID, and the owner's signer shows the exact action (command, target, hash, console, expiry) before they confirm. The action runs only after that signature verifies on the console. The approval is bound to that exact action, can be used once and expires after a short time. The agent cannot forge it, because it never holds the key. A flag such as `--confirm` would not be enough, since the agent could simply pass it. The alternative was measured on a real console and ruled out: a payload cannot read the pad, and borrowing it from the foreground title freezes the game ([ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md), [console findings](docs/console-findings.md)).
- **Allowlisted sources and trusted hashes.** Downloads come only from approved hosts and repositories, and a payload runs only if its hash is pinned in the allowlist or was approved by the owner.
- **Protected areas.** System partitions stay read-only. Critical system processes (such as SceShellCore) cannot be killed.
- **Designed to recover.** Every change is atomic and journaled, every payload has a previous version to fall back to, and `autoload safe-boot` disables autoload for one boot. This covers crashes, failed health checks and interrupted updates, but not every possible failure.
- **The telnet shell is outside the gate.** Approvals cover the agent port. The telnet shell on port 2323 is the owner's escape hatch: it listens on every interface, asks for no token and no approval, and can write files, kill processes, mount and run programs. Only the trusted-network rule below protects it. [docs/telnet-boundary.md](docs/telnet-boundary.md) has the manual check and the decision on its copies of the commands that move to the agent port.
- **Trusted network only.** The shell protocol is plain text, so the access token and session IDs can be sniffed by anyone on the same network. Ariel is meant for a trusted home network. On any other network, use an encrypted tunnel. On the agent port, the owner's signature keeps destructive actions safe even if the token leaks; it does not protect the telnet shell.
- **Untrusted content is data.** README files, web pages and logs read by an agent may contain instructions. Approval by a key the agent does not hold ensures that injected instructions cannot silently turn into code execution.
- **Auditable.** Ariel is open source and every action it takes is logged on the console.

From Stage 5, MCP tools are also marked as destructive, so the MCP client asks a human before even requesting approval.

## Quick start

To build Ariel, start it on a console and run your first `helloworld.elf` from its shell, follow the [quick start tutorial](docs/quick-start.md).

## Using it today

Until the Ariel features land, the shell behaves like upstream shsrv. Make sure [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr) is running, send the payload to port 9021 and connect with a telnet client on port 2323. Type `help` once connected to see the available commands (`cd`, `ls`, `mkdir`, `stat`, `ps` and others).

Payloads placed in a folder on the `PATH` (initialized to `/user/homebrew/bin` and `/mnt/usb0/homebrew/bin`) can be run directly. Homebrew that needs audio or video is launched through `hbldr`, and `hbdbg` starts it under gdb.

### Building

Ariel builds exactly like shsrv, with the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) installed on a Debian-based system: install `xxd`, point `PS5_PAYLOAD_SDK` at the SDK and run `make`.

### Known limitations (inherited from shsrv)

The session is not attached to a TTY, so homebrew that changes terminal properties will not work, and most commands are only partially implemented. Stage 3 addresses the limitations that matter most to agents.

## Why "Ariel"

The PS5's internal codename is **Prospero**, the sorcerer of Shakespeare's *The Tempest*. Prospero rules his island through **Ariel**, a spirit who carries out his orders, reports back what it sees, and does nothing on its own initiative. Ariel is also the one who longs to be trusted with freedom, and earns it by serving faithfully.

That is exactly the role of this project. Ariel is the servant that lives on Prospero's island (the console), takes orders from whoever is in charge (you, through an AI agent), reports what it finds, and never acts beyond what it was told. The name also fits the ecosystem's tradition of Prospero-themed projects, such as prospero-win.

## References and related projects

**Project documents**

- [Console findings](docs/console-findings.md): what the console allows the payload, the foreground title and the shell to do with the pad, with the error codes and addresses measured.
- [Controller spike](docs/controller-spike.md): the payload that produced those measurements.
- [Decisions](docs/adr/README.md): the architecture decision records, including [ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md) on the approval source.

**Upstream and core tooling** (ps5-payload-dev, GPLv3+)

- [shsrv](https://github.com/ps5-payload-dev/shsrv): the shell server Ariel is forked from.
- [elfldr](https://github.com/ps5-payload-dev/elfldr): the ELF loader that runs each payload as its own process, so a crashing payload does not take the loader down.
- [sdk](https://github.com/ps5-payload-dev/sdk): the payload SDK used to build Ariel.
- [websrv](https://github.com/ps5-payload-dev/websrv): web server with a homebrew launcher, ELF launcher and file system browser over HTTP.
- [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) and [klogsrv](https://github.com/ps5-payload-dev/klogsrv): FTP server and kernel log server, the usual companions for diagnostics.

**Payload management (design references)**

- [ChronicLoader](https://github.com/StonedModder/ChronicLoader-PS5-Payload): payload updater and `autoload.txt` manager. Its design (SHA-256 state, timestamped backups, managed autoload) inspired Ariel's Stage 2. It is distributed as a binary only, so no code is reused.
- [ps5-payload-manager](https://github.com/itsPLK/ps5-payload-manager): web-based payload store, launcher and autoload manager.

**AI on the console**

- [PS5LM](https://github.com/cobanov/PS5LM): runs LLMs locally on a jailbroken PS5 and exposes OpenAI- and Anthropic-compatible APIs, a possible fully offline brain for an Ariel agent.

**Protocols**

- [Model Context Protocol](https://modelcontextprotocol.io): the standard Ariel will implement in Stage 5.

## Legal

Ariel is a tool for consoles you own. It does not contain exploits, does not bypass DRM, and does not distribute copyrighted software. Using a jailbroken console may void your warranty and violate the terms of service of its manufacturer.

## License

Ariel is a derivative work of ps5-payload-shsrv by John Törnblom and contributors, and like the original it is licensed under the **GPLv3 or later**. Credit for the shell, the ELF loader and the SDK belongs to the ps5-payload-dev project.
