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

### Stage 1: download, run, persist, roll back

The first milestone is a shell that can, with a single command:

1. **Download a payload from a GitHub release**, by repository name, following the latest release or a pinned tag, and only from an allowlist of sources. Ariel records the immutable identifiers of what it downloaded (release ID, asset ID), since tags can be moved.
2. **Verify it** with SHA-256 before anything is executed. A hash published in the same release only detects corruption, not tampering, so the expected hash must come from somewhere Ariel trusts: either it is pinned in the allowlist, or a human approves the new hash on the console (see [Safety model](#safety-model)), after which it is pinned.
3. **Run it** through the ELF loader, tracking its PID and capturing its output to a log the agent can read later.
4. **Persist it**: record what is installed (source, identifiers, hash, path) in a state file under `/data`, and keep the autoload configuration up to date so payloads come back after a reboot. Approving an installation explicitly includes approving that the payload runs on every boot. `autoload safe-boot` skips autoload on the next boot, so a payload that crashes the console at startup can always be removed.
5. **Roll back on failure**: keep the previous version of every payload and a snapshot of the autoload configuration before each change. Changes are atomic (write a new file, then rename it into place) and recorded in a journal, so a change interrupted by a crash or power loss is completed or undone the next time Ariel starts. A new version that crashes or fails its health check (explicit criteria and a timeout, defined per payload) is replaced by the last known good version automatically.

Ariel itself is never overwritten while it is running, so the agent can never lock itself out.

Open design question: autoload is currently run at boot by another loader, not by Ariel. Ariel can only re-check each payload's hash before it starts at boot if Ariel itself becomes the component that runs autoload.

Stage 1 commands already follow a minimal machine-safe grammar: one command per line, no prompts, and an exit status on the last line. Stage 2 extends it to every command.

New commands in this stage (see [Command coverage](#command-coverage)):

- `payload install | run | list | logs | rollback`, the core of the stage. `run` starts a payload in the background and captures its output to a log.
- `autoload show | edit | safe-boot`, to inspect the autoload configuration and to boot without it when a payload keeps crashing.
- `sha256sum`, because the existing `sum` is a BSD checksum, not SHA-256.
- `unzip` and `tar`, because many GitHub releases ship payloads inside an archive.
- `reboot`, gated, to test that installed payloads survive a restart.
- `approval status <id>`, to check whether a pending action has been approved on the console.
- Gating for existing commands that change the system: `rm`, `kill`, `mount`, `umount`, `chroot` and `mknod`.

### Stage 2: an interface agents can rely on

Once the agent can reach the console, make the shell easy for it to use correctly:

- Proper argument parsing with quotes.
- Exit status and a separate error channel for every command.
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

### Stage 3 (optional): sessions

Stages 1 and 2 are enough for an agent to operate the console. Stages 3 and 4 are optional conveniences on top of them.

Agents usually reach the console through one-shot connections (one command per connection, e.g. `echo 'ls --json /data' | nc ps5 2323`), so state such as the working directory would otherwise be lost between commands. Ariel keeps optional sessions on the console side:

- `session new` returns a random 128-bit session ID and its TTL. Prefixing a command with `@<sid>` runs it inside that session, and `session close` ends it.
- A session holds only minimal state: working directory, environment and timestamps. It carries no authorization. Creating a session requires the access token, and every gated command still needs its own approval on the console. Payloads started from a session are not tied to it and keep running after it ends.
- Sessions expire after a period of inactivity, and the number of concurrent sessions is capped, so a client that forgets to close them cannot exhaust the console's RAM.
- An unknown or expired ID returns an explicit `session_expired` error instead of silently falling back, so the agent knows to open a new session (for example after a reboot).
- Session IDs are generated by a cryptographically secure random number generator and treated as secrets. Over plain-text connections they can still be sniffed, which is why they never authorize anything on their own.
- Sessions are isolated from each other, but the file system and installed payloads are shared. Stage 1 operations such as installing and rolling back take a global lock.
- Sessions are a convenience, not a requirement. Every command also works without one, using absolute paths.

### Stage 4 (optional): MCP

Expose the same capabilities as an [MCP](https://modelcontextprotocol.io) server, so any MCP client (Claude Code, Claude Desktop, or a local agent) can connect with structured tools instead of parsing shell text. The planned tool families are processes, payloads, file system, system information and logs. MCP is stateless since protocol version 2026-07-28, so a Stage 3 session ID is passed to each tool as an ordinary argument, as the specification recommends for server-minted handles.

## Command coverage

Which bash commands an agent can expect on Ariel. Each row is an Ariel command. The **bash equivalent** column is filled in only when the name differs from bash; an empty cell means the command has the same name in bash.

**Today:** ✅ complete · ⚠️ partial · ❌ missing. **Plan:** S1 and S2 are Stages 1 and 2. "Gated" commands need approval on the console before they run (see [Safety model](#safety-model)).

| Ariel | bash equivalent | Today (shsrv) | Plan |
|---|---|---|---|
| `pwd`, `cd` | | ✅ | S3: working directory kept across connections with sessions |
| `ls` | | ⚠️ no flags | S2: `-l`, `-a`, `--json`, pagination |
| `stat`, `file` | | ✅ | S2: `--json` |
| `cat` | | ✅ | S2: size limit |
| `head`, `tail`, `wc` | | ❌ | S2 |
| `grep` | | ⚠️ only `-i`, `-n` | S2: `-r`, `-l`, `-c` |
| `find` | | ⚠️ only `-name`, `-type` | S2: more predicates |
| `cmp`, `hexdump` | | ✅ | |
| `diff` | | ❌ | S2, optional |
| `df` | | ✅ | |
| `du` | | ❌ | S2 |
| `mkdir`, `rmdir`, `touch`, `ln` | | ✅ | S1: gated |
| `cp`, `mv` | | ⚠️ no `-r` | S1: gated. S2: `-r` |
| `rm` | | ⚠️ one file, no `-r` | S1: gated. S2: `-r` |
| `chmod`, `chown`, `chgrp` | | ✅ | S1: gated |
| `write <path>` | `echo > file`, `tee` | ❌ | S2, gated |
| `tar`, `unzip` | | ❌ | S1 |
| `ps` | | ✅ | S2: `--json` |
| `procstat` | `/proc/<pid>/*` | ✅ | |
| `kill` | | ✅ | S1: gated, critical processes protected |
| `payload run` | `cmd &`, `nohup` | ❌ | S1, gated, output captured to a log |
| `timeout` | | ❌ | S2 |
| `env`, `export`, `exec`, `sleep`, `id`, `sync` | | ✅ | |
| `sysinfo` | `uname`, `uptime`, `free` | ⚠️ raw values via `sysctl` | S2 |
| `date` | | ❌ | S2 |
| `dmesg` | | ❌ only through klogsrv | S2 |
| `mount`, `umount`, `chroot`, `mknod` | | ✅ | S1: gated |
| `reboot` | | ❌ | S1, gated |
| `http2_get -o` | `curl -o`, `wget` | ✅ no verification | S1: wrapped by `payload install` with allowlist and hash check |
| `sha256sum` | | ❌ (`sum` is a BSD checksum) | S1 |
| `ifconfig`, `netstat`, `ping` | | ❌ | S2, optional |

PS5-specific commands with no bash equivalent: `hbldr`, `hbdbg`, `launch`, `pkg_install`, `suspend`, `notify`, `authid`, `sfoinfo` and `sfocreate` (all in shsrv), plus `payload`, `autoload`, `approval` (Stage 1) and `session` (Stage 3).

Out of scope: pipes, redirection, `&&`, shell variables and scripts, editors, `ssh`, `top` and package managers. The agent composes logic on its own side, on the computer it runs on.

## Safety model

An agent that can download, write and execute code on a console with kernel privileges needs firm limits. Ariel is designed around these rules:

- **Reading is allowed, within limits.** Inspecting processes, files and logs needs only the access token. Output is size-limited, and environment variables and credential files are hidden unless explicitly requested.
- **Change is approved on the console.** Writing files, killing processes, mounting, rebooting, downloading and executing payloads are gated. A gated command does not run; Ariel answers with an `approval_required` error and an approval ID, and shows a notification on the console describing the exact action (command, target, hash). The action runs only after a human approves it with the controller. The approval is bound to that exact action, can be used once and expires after a short time. The agent cannot forge it, because it runs on another machine and has no access to the controller. A flag such as `--confirm` would not be enough, since the agent could simply pass it. Whether payloads can read controller input while another app is in the foreground is still to be validated; if not, a fallback is needed.
- **Allowlisted sources and trusted hashes.** Downloads come only from approved hosts and repositories, and a payload runs only if its hash is pinned in the allowlist or was approved on the console.
- **Protected areas.** System partitions stay read-only. Critical system processes (such as SceShellCore) cannot be killed.
- **Designed to recover.** Every change is atomic and journaled, every payload has a previous version to fall back to, and `autoload safe-boot` disables autoload for one boot. This covers crashes, failed health checks and interrupted updates, but not every possible failure.
- **Trusted network only.** The shell protocol is plain text, so the access token and session IDs can be sniffed by anyone on the same network. Ariel is meant for a trusted home network. On any other network, use an encrypted tunnel. On-console approval keeps destructive actions safe even if the token leaks.
- **Untrusted content is data.** README files, web pages and logs read by an agent may contain instructions. On-console approval ensures that injected instructions cannot silently turn into code execution.
- **Auditable.** Ariel is open source and every action it takes is logged on the console.

From Stage 4, MCP tools are also marked as destructive, so the MCP client asks a human before even requesting approval.

## Quick start

To build Ariel, start it on a console and run your first `helloworld.elf` from its shell, follow the [quick start tutorial](docs/quick-start.md).

## Using it today

Until the Ariel features land, the shell behaves like upstream shsrv. Make sure [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr) is running, send the payload to port 9021 and connect with a telnet client on port 2323. Type `help` once connected to see the available commands (`cd`, `ls`, `mkdir`, `stat`, `ps` and others).

Payloads placed in a folder on the `PATH` (initialized to `/user/homebrew/bin` and `/mnt/usb0/homebrew/bin`) can be run directly. Homebrew that needs audio or video is launched through `hbldr`, and `hbdbg` starts it under gdb.

### Building

Ariel builds exactly like shsrv, with the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) installed on a Debian-based system: install `xxd`, point `PS5_PAYLOAD_SDK` at the SDK and run `make`.

### Known limitations (inherited from shsrv)

The session is not attached to a TTY, so homebrew that changes terminal properties will not work, and most commands are only partially implemented. Stage 2 addresses the limitations that matter most to agents.

## Why "Ariel"

The PS5's internal codename is **Prospero**, the sorcerer of Shakespeare's *The Tempest*. Prospero rules his island through **Ariel**, a spirit who carries out his orders, reports back what it sees, and does nothing on its own initiative. Ariel is also the one who longs to be trusted with freedom, and earns it by serving faithfully.

That is exactly the role of this project. Ariel is the servant that lives on Prospero's island (the console), takes orders from whoever is in charge (you, through an AI agent), reports what it finds, and never acts beyond what it was told. The name also fits the ecosystem's tradition of Prospero-themed projects, such as prospero-win.

## References and related projects

**Upstream and core tooling** (ps5-payload-dev, GPLv3+)

- [shsrv](https://github.com/ps5-payload-dev/shsrv): the shell server Ariel is forked from.
- [elfldr](https://github.com/ps5-payload-dev/elfldr): the ELF loader that runs each payload as its own process, so a crashing payload does not take the loader down.
- [sdk](https://github.com/ps5-payload-dev/sdk): the payload SDK used to build Ariel.
- [websrv](https://github.com/ps5-payload-dev/websrv): web server with a homebrew launcher, ELF launcher and file system browser over HTTP.
- [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) and [klogsrv](https://github.com/ps5-payload-dev/klogsrv): FTP server and kernel log server, the usual companions for diagnostics.

**Payload management (design references)**

- [ChronicLoader](https://github.com/StonedModder/ChronicLoader-PS5-Payload): payload updater and `autoload.txt` manager. Its design (SHA-256 state, timestamped backups, managed autoload) inspired Ariel's Stage 1. It is distributed as a binary only, so no code is reused.
- [ps5-payload-manager](https://github.com/itsPLK/ps5-payload-manager): web-based payload store, launcher and autoload manager.

**AI on the console**

- [PS5LM](https://github.com/cobanov/PS5LM): runs LLMs locally on a jailbroken PS5 and exposes OpenAI- and Anthropic-compatible APIs, a possible fully offline brain for an Ariel agent.

**Protocols**

- [Model Context Protocol](https://modelcontextprotocol.io): the standard Ariel will implement in Stage 4.

## Legal

Ariel is a tool for consoles you own. It does not contain exploits, does not bypass DRM, and does not distribute copyrighted software. Using a jailbroken console may void your warranty and violate the terms of service of its manufacturer.

## License

Ariel is a derivative work of ps5-payload-shsrv by John Törnblom and contributors, and like the original it is licensed under the **GPLv3 or later**. Credit for the shell, the ELF loader and the SDK belongs to the ps5-payload-dev project.
