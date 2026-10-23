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

1. **Download a payload from a GitHub release**, by repository name, following the latest release or a pinned tag.
2. **Verify it** with SHA-256 before anything is executed, and only from an allowlist of sources.
3. **Run it** through the ELF loader, tracking its PID and capturing its output to a log the agent can read later.
4. **Persist it**: record what is installed (source, tag, hash, path) in a state file under `/data`, and keep the autoload configuration up to date so payloads come back after a reboot.
5. **Roll back on crash**: keep the previous working version of every payload and a snapshot of the autoload folder before each change. If a new version crashes or fails a health check, restore the last known good state automatically.

Ariel itself is never overwritten while it is running, so the agent can never lock itself out.

### Stage 2: an interface agents can rely on

Once the agent can reach the console, make the shell easy for it to use correctly:

- Proper argument parsing with quotes.
- Exit status and a separate error channel for every command.
- Optional JSON output for `ps`, `ls`, `stat` and similar commands.
- Pagination and size limits, so a large directory or log does not flood the agent's context.
- Strictly non-interactive commands: no prompts in the middle of a session.

### Stage 3: MCP

Expose the same capabilities as an [MCP](https://modelcontextprotocol.io) server, so any MCP client (Claude Code, Claude Desktop, or a local agent) can connect with structured tools instead of parsing shell text. The planned tool families are processes, payloads, file system, system information and logs.

## Safety model

An agent that can download, write and execute code on a console with kernel privileges needs firm limits. Ariel is designed around these rules:

- **Read is free, change is gated.** Inspecting processes, files and logs is allowed. Writing files, killing processes, downloading and executing payloads require an access token and are marked as destructive so the client asks a human first.
- **Allowlisted sources only.** Downloads come only from approved hosts and repositories, and every file is hash-checked before execution.
- **Protected areas.** System partitions stay read-only. Critical system processes (such as SceShellCore) cannot be killed.
- **Always recoverable.** Every change is preceded by a backup, and every payload has a previous version to fall back to.
- **Untrusted content is data.** README files, web pages and logs read by an agent may contain instructions. Ariel's confirmation gates exist so that injected instructions cannot silently turn into code execution.
- **Auditable.** Ariel is open source and every action it takes is logged on the console.

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

- [Model Context Protocol](https://modelcontextprotocol.io): the standard Ariel will implement in Stage 3.

## Legal

Ariel is a tool for consoles you own. It does not contain exploits, does not bypass DRM, and does not distribute copyrighted software. Using a jailbroken console may void your warranty and violate the terms of service of its manufacturer.

## License

Ariel is a derivative work of ps5-payload-shsrv by John Törnblom and contributors, and like the original it is licensed under the **GPLv3 or later**. Credit for the shell, the ELF loader and the SDK belongs to the ps5-payload-dev project.
