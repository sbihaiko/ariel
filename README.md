# Ariel

**A PS5 payload shell built for AI agents.**

Ariel is a fork of [ps5-payload-dev/shsrv](https://github.com/ps5-payload-dev/shsrv), the telnet-like shell server for jailbroken PS5 consoles. It keeps everything shsrv already does and grows it in one direction: letting an AI agent, such as Claude, talk to the console safely. The agent can inspect the system, download payloads from GitHub, run them, and recover on its own when something crashes, without ever being able to leave the console in a broken state.

> **Status:** Stages 1 to 5 are delivered and run on firmware 11.20; the current release is [`stage-5.1`](https://github.com/sbihaiko/ariel/releases/tag/stage-5.1). Stage 6, network sight, is specified ([#111](https://github.com/sbihaiko/ariel/issues/111)) and not started. Stage 7, the MCP server, is not started. See [Progress](#progress), [What is being done](#what-is-being-done) and [What is missing](#what-is-missing).
>
> **Target firmware: 11.20, and only 11.20 for now.** Ariel makes no claim about another firmware. One console is in hand, a CFI-2014 on 11.20, every validation run happens there, and a behaviour reported on another firmware is not a defect until that firmware is adopted. Adopting one is a decision with its own console run, not a patch. Supporting several firmware versions costs a lab this project does not have. The decision is [ADR-0011](docs/adr/0011-the-target-firmware-is-11-20.md).

---

## Why Ariel exists

Coding agents diagnose a system by running a command, reading the output and running the next one. A jailbroken PS5 is a hostile place for that: there is no real Unix shell to run the agent on; shsrv was built for humans typing into telnet, with whitespace splitting, free-form output, no exit status and no pagination; getting a payload onto the console is manual and a bad one can crash or hang the system; and everything lives in RAM, so a reboot wipes the jailbreak and every running payload. Ariel gives the agent one endpoint with a predictable, safe, recoverable interface.

## How it is today

### Progress

Work happens on the `dev` branch; `master` follows it at milestones. Each stage is a spec issue whose sub-issues are the work. Every console run is on a CFI-2014 on firmware 11.20.

| Stage | Spec | Delivered |
|---|---|---|
| 1. Hello world, end to end | [#1](https://github.com/sbihaiko/ariel/issues/1) | Console suite 10/10; the quick start and the telnet boundary check passed ([#11](https://github.com/sbihaiko/ariel/issues/11)). |
| 2. Persist and recover | [#2](https://github.com/sbihaiko/ariel/issues/2) | 2026-10-24. 37 sub-issues closed; console suite 36/36 and the telnet boundary check passed ([#46](https://github.com/sbihaiko/ariel/issues/46)). The key run rotated, revoked, froze, unfroze, started without the keyring and restored it ([console findings](docs/console-findings.md#issue-48-keys-on-the-console)). |
| 3. An interface agents can rely on | [#57](https://github.com/sbihaiko/ariel/issues/57) | Nine sub-issues closed; the host acceptance suite covers it, and the console evidence (read ranges, `cp -r`/`rm -r`, `sfocreate`/`sfoinfo`) is in [console findings](docs/console-findings.md#issue-61-64-and-49-stage-3-on-the-console). |
| 4. Addons, and sight as the first one | [#54](https://github.com/sbihaiko/ariel/issues/54) | 2026-10-25. The loader, the reference addon and `addons/ftp/` are done; sight is `shots`, accepted by the owner because no capture route returns an image ([#53](https://github.com/sbihaiko/ariel/issues/53), [#100](https://github.com/sbihaiko/ariel/issues/100)). |
| 5. Sessions (optional) | [#101](https://github.com/sbihaiko/ariel/issues/101) | 2026-10-25. Six sub-issues closed; the host acceptance suite covers the prefix, the directory, the relative paths, the environment and the limits, and the console round trip ran on the `stage-5` build ([#107](https://github.com/sbihaiko/ariel/issues/107)). |

Stage 3's nine pieces, issue and commit: the grammar, ADR-0012 ([#58](https://github.com/sbihaiko/ariel/issues/58), `8e87996`); one parser with quotes, the escaped canonical action and the 60 s deadline ([#59](https://github.com/sbihaiko/ariel/issues/59), `02e9f0e`); bounded readers and the `truncated` marker ([#60](https://github.com/sbihaiko/ariel/issues/60), `cadf9ec`); the binary `read` ([#61](https://github.com/sbihaiko/ariel/issues/61), `641f2f9`); `write`, gated ([#62](https://github.com/sbihaiko/ariel/issues/62), `9c2380e`); `--json` on `ps`, `ls`, `stat`, `df` and `find` ([#63](https://github.com/sbihaiko/ariel/issues/63), `cd62866`); `ls -l -a`, `grep -r -l -c -e`, `find -name -type`, `rm -r` and `cp -r` ([#64](https://github.com/sbihaiko/ariel/issues/64), `03eef1c`); `date`, `du`, `dmesg` and `sysinfo` ([#65](https://github.com/sbihaiko/ariel/issues/65), `e99af35`); `sfocreate`, gated ([#49](https://github.com/sbihaiko/ariel/issues/49), `5afbb06`).

### Installing and running it

The [quick start tutorial](docs/quick-start.md) goes from an empty checkout to a payload installed and run on a console, through the gate, with the owner's key. The short way is one script:

```console
$ sh tools/install/ariel.sh <console address>
```

It makes the two keys if they are not there, builds the payload with them pinned, sends it to port 9021, waits for the agent port, and leaves `ariel.env` holding `PS5_HOST` and `ARIEL_TOKEN`. `tools/install/ariel.command` is the same on a double-click on macOS and `tools/install/ariel.bat` on Windows; `--check` says what it would do and sends nothing. The build routes are in [the release notes below](#the-installer-and-release-stage-51).

By hand, it is four steps:

1. Clone the `stage-5.1` tag and run `make -C hostbuild`, which builds the signer as well as the host target.
2. Make two keys with `./hostbuild/ariel-sign keygen`: the primary that signs everyday approvals, and a recovery key kept offline.
3. Build the payload with both public keys pinned: `make ARIEL_PUBKEY=<primary> ARIEL_RECOVERY_PUBKEY=<recovery>`, 64 hex digits each. The two must differ, and setting `ARIEL_PUBKEY` without `ARIEL_RECOVERY_PUBKEY` stops the build, because the console would otherwise refuse every grant. The host build's own test key is not one a console accepts.
4. Send `ariel-ps5.elf` to port 9021, read the access token on the console, and talk to the agent port on 2324.

The release ships source only, and it has to: a build with no key pinned refuses every grant, and one pinned to someone else's keys could only be approved by them. The console carries the public half of **your** pair.

Ariel builds like shsrv, with the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) on a Debian-based system: install `xxd`, point `PS5_PAYLOAD_SDK` at the SDK and run `make`. `make test ARIEL_DEPLOY=yes PS5_HOST=<console>` sends `ariel-ps5.elf` to the console, and refuses without the explicit `ARIEL_DEPLOY`. The headless acceptance suite is `make -C hostbuild test`; it needs no console. The host build sits behind the same platform port, with a test clock and a test key that signs the approvals a scenario asks for, and none of it ships in the PS5 build.

On the console, [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr) must be running on 9021. Ariel stops any running shsrv and takes its place. The telnet shell still answers on port 2323 exactly like upstream: `help` lists its commands. Payloads in a folder on the `PATH` (`/user/homebrew/bin` and `/mnt/usb0/homebrew/bin`) run directly; homebrew that needs audio or video is launched through `hbldr`, and `hbdbg` starts it under gdb. Inherited from shsrv: the shell is not attached to a TTY, so homebrew that changes terminal properties will not work.

### The agent port

The agent port is 2324, raw TCP with no telnet negotiation, so a binary upload arrives intact. Every connection starts with `auth <token>`, the token Ariel shows on the console at first start; then one command per connection, no prompts, and every reply ends with an `exit <status>` line. Agents usually reach it one shot at a time, e.g. `printf 'auth %s\nls --json /data\n' "$ARIEL_TOKEN" | nc ps5 2324`.

**The grammar** ([ADR-0012](docs/adr/0012-the-agent-port-line-grammar.md)). Arguments are quoted; the tokenizer refuses `bad_quoting` and a line over 64 tokens, and a word a command does not take answers `bad_option`. One 60 s connection deadline answers `timed_out`. No answer carries more than 64 KiB; a cut answer ends with `truncated <shown> of <total>`, and `--limit` caps every listing that can flood. `read` answers `bytes <size> <sha256>`, then exactly that many bytes, with `--offset` and `--limit`. `write <path>` takes one frame of content. Every command has its own error channel and an exit status from [docs/exit-codes.md](docs/exit-codes.md); `ps`, `ls`, `stat`, `df`, `find` and `sysinfo` answer `--json` as one object per line ([docs/json-output.md](docs/json-output.md)). There are no pipes, redirection, `&&`, shell variables, scripts, editors, `ssh`, `top` or package managers; a command that would need a pipe gets a flag instead, such as `grep -c` for `| wc -l`, and the agent composes logic on its own machine.

**Payloads.** `payload push <name> <size> <sha256>` uploads a locally built ELF over the same connection, so no FTP server is needed; Ariel stages it and the console shows its hash. `payload install` downloads one from a GitHub release, by repository name, latest or a pinned tag, only from an allowlist of sources, recording the immutable release and asset IDs since tags can be moved, and verifying SHA-256 before anything runs; the expected hash is pinned in the allowlist or approved by the owner's key, after which it is pinned. `payload commit <staging-id>` moves an approved upload into the store; the bytes are sent once. `payload run --wait <name>` runs a committed payload in the foreground through the ELF loader (no `chmod`), streams its output and reports its exit on a `status <n>` line apart from the protocol's `exit`; without `--wait` it runs in the background, tracking the PID and capturing output to a log `payload logs` reads. `payload list` answers one `payload <name> ...` line per installed payload with source, version identifiers, hash, path, whether it is running, `failed=yes|no` and `previous=<sha256|->`, and changes nothing. `payload config` sets the health check (explicit criteria and a timeout); `payload rollback` returns to the previous version. `unzip` and `tar` unpack the archives releases ship, and refuse a member that escapes.

**Persistence and recovery.** What is installed is recorded in a state file under `/data`, and the autoload configuration is kept up to date so payloads come back after a reboot; approving an installation includes approving that it runs on every boot. `autoload show | edit | safe-boot` inspect it, edit it, and skip autoload on the next boot, so a payload that crashes the console at startup can always be removed. Every payload keeps its previous version and every change snapshots the autoload configuration first; changes are atomic and journaled, so one interrupted by a crash or power loss is completed or undone when Ariel next starts, and a new version that crashes or fails its health check is replaced by the last known good one. Ariel is never overwritten while it is running, so the agent can never lock itself out. Ariel is not the boot loader: another loader runs autoload at boot, so Ariel cannot re-check a payload's hash then; making it the boot-time autoloader is a later decision. `reboot`, gated, tests that installed payloads survive a restart.

**Keys.** The build pins a primary key that signs everyday approvals and an offline recovery key never on the agent's machine ([ADR-0009](docs/adr/0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md)). A keyring on the console tracks the active keys and a generation, so `key rotate | rotate-recovery` work without a rebuild and a signature under one generation never verifies under another. A leaked key can be stopped: the owner freezes the console over the telnet shell, and only the recovery key can `key unfreeze` or `key revoke` the compromised keys, suspending every grant they made. Damaged key state fails closed. [docs/key-recovery.md](docs/key-recovery.md) covers each case and where a rebuild is still needed. `approval status <id>` polls a pending approval; `audit tail [n]` reads the newest `n` audit lines, at most 64.

**Sessions** ([ADR-0014](docs/adr/0014-the-session-prefix-and-the-resolved-path.md)). Without a session every path is absolute, `pwd` answers `/`, `cd` answers `no_working_directory` and a relative path `relative_path`. `session new` mints a 32-hex-character (128-bit) ID from the platform's cryptographic random source and answers `session <sid> ttl 600`; `session close <sid>` answers `session_closed <sid>`; `session list` answers one `session <sid> idle <seconds> cwd <path> env <n>` line per live session. A first token `@<sid>` runs the line in that session: it starts at `/`, `cd PATH` moves it and judges the path as `ls` does, and the shell commands, the gated file commands and transfers, `write`, `unzip` and `tar` resolve a relative operand against its directory lexically, with a `..` that would leave `/` answering `bad_path`. Resolution happens before the gate, so the owner signs the absolute path, the session ID never enters the canonical action, and every gated command still asks for its own approval. `@<sid> export NAME=VALUE` is gated with `option.scope=session` in its challenge; `@<sid> env NAME` reads the session's value over the process environment, which a payload started there receives, copied at the spawn, so a later `export` never reaches a running payload and ending the session leaves its payloads running. An addon never sees a session. Limits: eight sessions (`session_full`, exit 1), 10 idle minutes, 16 names of at most 32 bytes and one assignment of at most 1024 bytes (`export_failed`, `bad_name`, `value_too_long`). A malformed, unknown or expired prefix answers `session_expired` (exit 93) before the rest of the line and before any gate. Sessions share the file system, the payload store and the global locks, live in process memory, and expire on restart. A session ID is sniffable like the token and `session list` shows every live ID to any token holder, but it authorizes nothing; the audit log records `session.new` and `session.close` with `-` as the target.

**Addons** ([ADR-0010](docs/adr/0010-an-addon-is-a-process-of-its-own.md), [docs/addons.md](docs/addons.md)). An addon is an ELF and a manifest that runs in a process of its own, through the one gate every other command uses, with the same audit words and exit codes. The agent cannot install, replace or remove one: addons live in a protected directory the file commands refuse like the token, and enter only by the owner, out of band. The process is bounded by a timeout, an output cap and a kill, so one that crashes, hangs or floods costs a refusal, not a reboot; a manifest that names another ABI version or platform is refused before the owner is asked. The repository holds two: [`addons/sight/`](addons/sight/), the reference the how-to points at, built by `make addon-sight`, which refuses because no capture route exists; and [`addons/ftp/`](addons/ftp/), one program installed under four names that moves files through the console's ftpsrv behind the gate ([its page](addons/ftp/README.md)). Neither is part of `make all`.

**Sight.** `shots` copies out of the gallery the console's own Create button writes at `/user/av_contents/photo`: `--last` the newest image, `--count <n>` the newest `n`, `--minutes <n>` the images of the last `n` minutes, `n` from 1 to 64. It captures nothing and writes nothing in the gallery. It is gated with the selector in the signed action (`option.select`); each copy lands under `/data/shots`, the reply names path, size and SHA-256, and an empty gallery answers `no_shots` before the owner is asked. Why it is a copy and not a capture is in [What is missing](#standing-limits).

### Command coverage

Which bash commands an agent can expect on Ariel. Each row is an Ariel command; the **bash equivalent** column is filled in only when the name differs from bash. **shsrv:** what upstream offers, the baseline Ariel started from: ✅ complete · ⚠️ partial · ❌ missing. **Plan:** S1 to S7 are Stages 1 to 7. "Gated" commands need the owner's approval before they run (see [Safety model](#safety-model)).

| Ariel | bash equivalent | shsrv | Plan |
|---|---|---|---|
| `pwd` | | ✅ | S5: `@<sid> pwd` answers the session's directory, and `/` on a connection with no session. The sessions themselves are `session new`, `session close <sid>` and `session list` |
| `cd` | | ✅ | S5: `@<sid> cd PATH` moves the session, and a connection with no session answers `no_working_directory` |
| `ls` | | ⚠️ no `-l` or `-a` | S3: `-l`, `-a`, `--limit` and `--json`, cut at 64 KiB |
| `stat`, `file` | | ✅ | |
| `cat` | | ✅ | S3: `--limit`, and a file over 64 KiB is cut |
| `read <path>` | `dd`, `head -c` | ❌ | S3: the binary frame of ADR-0012, `bytes <size> <sha256>`, with `--offset` and `--limit` |
| `head`, `tail`, `wc` | | ✅ | |
| `grep` | | ⚠️ only `-i`, `-n` | S3: `-r`, `-l`, `-c`, `-e`, `--`, `--limit` |
| `find` | | ⚠️ only `-name`, `-type` | S3: `-name`, `-type f\|d\|l`, `--limit`, `--json` |
| `cmp`, `hexdump` | | ✅ | |
| `diff` | | ❌ | Not built: `cmp` answers same-or-differ with the first offset and `hexdump` shows the bytes; a finer diff is the agent's own work on its own machine |
| `df` | | ✅ | |
| `du` | | ✅ | |
| `mkdir`, `rmdir`, `touch`, `ln` | | ✅ | S2: gated |
| `cp`, `mv` | | ⚠️ no `-r` | S2: gated. S3: `cp -r`, which asks once for the whole tree |
| `rm` | | ⚠️ one file, no `-r` | S2: gated. S3: `rm -r`, which asks once for the whole tree |
| `chmod`, `chown`, `chgrp` | | ✅ | S2: gated |
| `write <path>` | `echo > file`, `tee` | ✅ | S3: gated, one frame |
| `tar`, `unzip` | | ❌ | S2 |
| `ps` | | ✅ | |
| `procstat` | `/proc/<pid>/*` | ✅ | |
| `kill` | | ✅ | S2: gated, critical processes protected |
| `payload run` | `cmd &`, `nohup` | ❌ | S1: `--wait` runs an approved build in the foreground. S2: background runs with a log |
| `payload push`, `payload commit` | `scp`, `curl -T` | ❌ | S1, hash approved by the owner |
| `timeout` | | ❌ | Not built: the 60 s connection deadline answers `timed_out`, and a health check carries its own bound through `payload config` |
| `sleep`, `id`, `sync` | | ✅ | |
| `env`, `export`, `exec` | | ✅ | S2: gated |
| `sysinfo` | `uname`, `uptime`, `free` | ✅ | |
| `date` | | ✅ | |
| `dmesg` | | ✅ | |
| `mount`, `umount`, `chroot`, `mknod` | | ✅ | S2: gated |
| `reboot` | | ❌ | S2: gated; the host build simulates it |
| `http2_get -o` | `curl -o`, `wget` | ✅ no verification | S2: gated and restricted to the download allowlist. `payload install` adds the hash check |
| `sha256sum` | | ❌ (`sum` is a BSD checksum) | Not built: `read <path> --limit 0` answers `bytes 0 <sha256>`, the whole file's hash, in one read-only call |
| `netstat` | | ❌ | S6 (optional): built only if its console probe proves the socket table is readable; see [Stage 6](#stage-6-optional-network-sight) |
| `ifconfig` | | ❌ | S6 (optional): the interfaces, with address, mask and state; built only if its probe passes |
| `ping` | | ❌ | S6 (optional): whether an address answers, with a capped count and deadline; built only if its probe passes |

PS5-specific commands with no bash equivalent: `hbldr`, `hbdbg`, `launch`, `pkg_install`, `suspend`, `notify`, `reptyr`, `authid`, `sfoinfo` and `sfocreate` (all in shsrv; from Stage 2 all but `authid` and `sfoinfo` are gated, and `sfocreate` joined them in Stage 3, #49), plus `payload` (Stage 1), `approval` and `autoload` (Stage 2), `shots` (Stage 4) and `session` (Stage 5).

### Safety model

An agent that can download, write and execute code on a console with kernel privileges needs firm limits. These are Ariel's:

- **Reading is allowed, within limits.** Inspecting processes, files and logs needs only the access token, and output is size-limited. `env` is gated, and Ariel's own secrets (its token and approval state) cannot be read through any gated command.
- **Change is approved by the owner's signature.** Writing files, killing processes, mounting, rebooting, downloading and executing payloads are gated: Ariel answers `approval_required <id>` instead of running, the owner's signer shows the exact action (command, target, hash, console, expiry), and the action runs only after that signature verifies on the console. The approval is bound to that action, used once and short-lived. The agent cannot forge it because it never holds the key; a flag such as `--confirm` would not do, since the agent could pass it. Approving a payload version, at install or commit, also approves running that exact version, so a build is approved once, not once per run. The controller was measured as the alternative and ruled out: a payload cannot read the pad, and borrowing it from the foreground title freezes the game ([ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md), [console findings](docs/console-findings.md)).
- **Allowlisted sources and trusted hashes.** Downloads come only from approved hosts and repositories, and a payload runs only if its hash is pinned in the allowlist or was approved by the owner.
- **Protected areas.** System partitions stay read-only. Critical system processes (such as SceShellCore) cannot be killed.
- **Designed to recover.** Atomic journaled changes, a previous version of every payload and `autoload safe-boot` cover crashes, failed health checks and interrupted updates, but not every possible failure.
- **The telnet shell is outside the gate.** Approvals cover the agent port. The telnet shell on port 2323 is the owner's escape hatch: it listens on every interface, asks for no token and no approval, can write, kill, mount and run, and can read the secrets the gated commands refuse ([ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md) decision 10, [ADR-0008](docs/adr/0008-the-telnet-shell-stays-outside-the-gate.md)). [docs/telnet-boundary.md](docs/telnet-boundary.md) holds the manual check; the headless suite covers the other half, that the agent port refuses every command that changes the system and a push waits for an approval.
- **Trusted network only.** The protocol is plain text, so the access token and session IDs can be sniffed by anyone on the same network. Ariel is meant for a trusted home network; on any other, use an encrypted tunnel. On the agent port the owner's signature keeps destructive actions safe even if the token leaks; nothing but the network protects the telnet shell.
- **Untrusted content is data.** README files, web pages and logs an agent reads may contain instructions; approval by a key the agent does not hold means injected instructions cannot silently turn into code execution.
- **Auditable.** Ariel is open source and every action it takes is logged on the console.

## What is being done

### Stage 6 (optional): network sight

The spec is [#111](https://github.com/sbihaiko/ariel/issues/111), which replaces [#94](https://github.com/sbihaiko/ariel/issues/94) (a spec for `netstat` alone, under the number 7 the stage carried then; its spike never ran). Nothing of it is built yet.

No current command says which ports the console listens on or which peers it is connected to: the only way to learn whether a payload is serving is to try to connect, where a refusal and a slow accept read the same. The address the agent connected to says nothing about a second interface or one that is down, and a failed download cannot separate an address that never answered from one that refused. The console answers ping while asleep and running no payload ([#71](https://github.com/sbihaiko/ariel/issues/71)), so a reply says the network stack is alive, never that a payload is.

The stage is three read-only, ungated commands, numeric addresses only, each bounded so none can hold the console, and each built only if its own console probe passes on 11.20:

- `netstat [-l] [-t] [-u] [--limit N] [--json]`: one line per socket, `<proto> <local-address>:<port> <peer-address>:<port|-> <state>`, TCP first then UDP, sorted by local port then address, under the readers' 64 KiB cap and `truncated` marker; `-l` selects listening TCP sockets and every UDP endpoint. JSON keys: `proto`, `local_address`, `local_port`, `peer_address`, `peer_port`, `state`.
- `ifconfig [--json]`: one line per interface address, `<name> <state> <address> <mask>`, state `up` or `down` by administrative state, `-` for a missing IPv4 address. JSON keys: `name`, `state`, `address`, `mask`.
- `ping [-c N] [-W MS] ADDRESS`: one line, `ping <address> <sent> <received> <min> <avg> <max>` in whole milliseconds, exit 0 when at least one reply arrived, `no_reply` and exit 1 otherwise. `-c` is 1 to 10 (default 4), `-W` 1 to 5000 ms (default 1000), so the worst case is 50 s, inside the connection deadline. A literal IPv4 address only; a fixed probe whose reply bytes are never returned. No `--json`.

The probe comes first and is a payload of its own, as the controller, capture and share spikes were: never linked into Ariel, run with the owner present, three probes from least to most risky (the interface list, the socket tables, the echo), a selector to run one alone, and a log under `/data` so a freeze is attributable. A failed probe is a result: the findings record the transcript, the coverage row keeps "not built" and gains the reason, and the stage closes either way. The console build answers from system calls, never a shell-out; the host build reports its own machine, as `ps` and `sysinfo` do. No new exit status and no change to the approval design: `bad_option`, `bad_argument`, `missing_operand`, `operation_failed`, the platform refusal and `no_reply` carry every failure. Out of scope: IPv6 and names, MAC addresses, speeds, counters and carrier state, any change to the network, and ports probed in bulk.

### The installer and release stage-5.1

[`stage-5.1`](https://github.com/sbihaiko/ariel/releases/tag/stage-5.1) is the same payload as `stage-5` plus a smaller install ([#110](https://github.com/sbihaiko/ariel/issues/110)). `tools/install/ariel.sh` now builds with a local LLVM when the machine has one, downloading the PS5 payload SDK itself on the way, and falls back to a container with the SDK inside when it does not; an SDK already on the machine (`PS5_PAYLOAD_SDK` set) is used as it is, and `ARIEL_BUILD=local` or `ARIEL_BUILD=docker` forces one route. On Windows the local route does not exist yet: `ariel.bat` runs `ariel.ps1`, which builds in Docker Desktop, so that must be installed and running there. The release's assets are the four installer scripts; the payload is still built by you, with your keys.

## What is missing

### Stage 7 (optional): MCP

Not started. The plan is to expose the same capabilities as an [MCP](https://modelcontextprotocol.io) server, so any MCP client (Claude Code, Claude Desktop, or a local agent) can connect with structured tools instead of parsing shell text. The planned tool families are processes, payloads, file system, system information, logs and network sight, so `netstat` is a tool from the start. MCP is stateless since protocol version 2026-07-28, so a Stage 5 session ID is passed to each tool as an ordinary argument, as the specification recommends for server-minted handles. MCP tools that change the console would be marked destructive, so the client asks a human before even requesting approval.

### Commands deliberately not built

Three commands were planned and dropped because another mechanism already covers each, and the [coverage table](#command-coverage) says so on their rows: `diff`, covered by `cmp` (same-or-differ with the first offset) and `hexdump`, a finer comparison being the agent's own work on its own machine; `timeout`, covered by the 60 s connection deadline that answers `timed_out` and by the bound a health check carries through `payload config`; and `sha256sum`, covered by `read <path> --limit 0`, which answers `bytes 0 <sha256>` in one read-only call, so a separate command would add a word and no capability.

### Network sight, until a probe passes

`netstat`, `ifconfig` and `ping` are not on the agent port. Each waits on its own console probe, none of which has run; what each will answer when built is in [Stage 6](#stage-6-optional-network-sight). Until then the console's address is the one the agent connected to, and a failed download is the only reachability answer.

### Standing limits

- **No screen capture on 11.20.** Both routes a payload can reach were measured and neither returns an image. The system screenshot daemon's IPC client loads and takes its parameters, but `Capture` never completes and the console freezes until the owner resets it by hand, so no capture attempt runs unless the owner is present and willing to reset it ([#55](https://github.com/sbihaiko/ariel/issues/55), [#79](https://github.com/sbihaiko/ariel/issues/79), [console findings](docs/console-findings.md#issue-55-the-capture-api-on-the-console)). The share library `libSceShare.native.sprx` loads and every export resolves, but `sceShareInitialize` answers `0x81960001` because `SceShareLibIpmiService` never answers a non-negative value, every later call answers `0x8196000C` (not initialized), and the library compares no authid, so the payload's identity is not what is refused; it never wedges the console and never produces a file ([#100](https://github.com/sbihaiko/ariel/issues/100), [console findings](docs/console-findings.md#issue-100-the-share-route-and-the-error-it-stops-at)). So `addons/sight/` has nothing to call and stays a reference that refuses, and sight is `shots`, which copies what the Create button wrote.
- **The telnet shell is outside the gate.** Port 2323 asks for no token and no approval, and the only thing that protects it is the network ([Safety model](#safety-model)).
- **Trusted network only.** Plain text, sniffable token and session IDs; an encrypted tunnel anywhere but a trusted home network.
- **One firmware.** 11.20 only ([ADR-0011](docs/adr/0011-the-target-firmware-is-11-20.md)), and Ariel does not re-check a payload's hash at boot, because another loader runs autoload.

## Why "Ariel"

The PS5's internal codename is **Prospero**, the sorcerer of Shakespeare's *The Tempest*. Prospero rules his island through **Ariel**, a spirit who carries out his orders, reports back what it sees, and does nothing on its own initiative. That is the role of this project: the servant on Prospero's island (the console) that takes orders from whoever is in charge (you, through an AI agent), reports what it finds, and never acts beyond what it was told. The name also fits the ecosystem's tradition of Prospero-themed projects, such as prospero-win.

## References and related projects

**Project documents**

- [Console findings](docs/console-findings.md): what the console allows, with the error codes and addresses measured.
- [Controller spike](docs/controller-spike.md): the payload that produced the pad measurements.
- [Decisions](docs/adr/README.md): the architecture decision records.

**Upstream and core tooling** (ps5-payload-dev, GPLv3+)

- [shsrv](https://github.com/ps5-payload-dev/shsrv): the shell server Ariel is forked from.
- [elfldr](https://github.com/ps5-payload-dev/elfldr): the ELF loader that runs each payload as its own process, so a crashing payload does not take the loader down.
- [sdk](https://github.com/ps5-payload-dev/sdk): the payload SDK used to build Ariel.
- [websrv](https://github.com/ps5-payload-dev/websrv): homebrew launcher, ELF launcher and file browser over HTTP.
- [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) and [klogsrv](https://github.com/ps5-payload-dev/klogsrv): FTP server and kernel log server, the usual companions for diagnostics.

**Payload management (design references)**

- [ChronicLoader](https://github.com/StonedModder/ChronicLoader-PS5-Payload): payload updater and `autoload.txt` manager. Its design (SHA-256 state, timestamped backups, managed autoload) inspired Ariel's Stage 2. It is distributed as a binary only, so no code is reused.
- [ps5-payload-manager](https://github.com/itsPLK/ps5-payload-manager): web-based payload store, launcher and autoload manager.

**AI on the console**

- [PS5LM](https://github.com/cobanov/PS5LM): runs LLMs locally on a jailbroken PS5 and exposes OpenAI- and Anthropic-compatible APIs, a possible fully offline brain for an Ariel agent.

**Protocols**

- [Model Context Protocol](https://modelcontextprotocol.io): the standard Ariel will implement in Stage 7.

## Legal

Ariel is a tool for consoles you own. It does not contain exploits, does not bypass DRM, and does not distribute copyrighted software. Using a jailbroken console may void your warranty and violate the terms of service of its manufacturer.

## License

Ariel is a derivative work of ps5-payload-shsrv by John Törnblom and contributors, and like the original it is licensed under the **GPLv3 or later**. Credit for the shell, the ELF loader and the SDK belongs to the ps5-payload-dev project.
