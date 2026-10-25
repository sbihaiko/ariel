# Ariel

**A PS5 payload shell built for AI agents.**

Ariel is a fork of [ps5-payload-dev/shsrv](https://github.com/ps5-payload-dev/shsrv), the telnet-like shell server for jailbroken PS5 consoles. It keeps everything shsrv already does and grows it in one direction: letting an AI agent, such as Claude, talk to the console safely. The agent should be able to inspect the system, download payloads from GitHub, run them, and recover on its own when something crashes, without ever being able to leave the console in a broken state.

> **Status:** Stages 1 to 3 are done, with their console runs on firmware 11.20. Stage 4 is in progress: addons, their process contract and the one gate are done, and `addons/ftp/` works on a console ([#89](https://github.com/sbihaiko/ariel/issues/89)); the stage's **pilot addon is not built**, because [`addons/sight/`](addons/sight/) runs a capture and no capture route a payload can reach has produced an image yet ([#53](https://github.com/sbihaiko/ariel/issues/53), with the share route measured in [#100](https://github.com/sbihaiko/ariel/issues/100)). Stages 5 and 6 have not started. See [Progress](#progress).
>
> **Target firmware: 11.20, and only 11.20 for now.** Ariel makes no claim about another firmware. One console is in hand, on 11.20, every validation run happens there, and a behaviour reported on another firmware is not a defect until that firmware is adopted. Adopting one is a decision with its own console run, not a patch. This is deliberately selfish while the shell is young: supporting several firmware versions costs a lab this project does not have. The decision is [ADR-0011](docs/adr/0011-the-target-firmware-is-11-20.md).

---

## Why Ariel exists

Coding agents like Claude Code are good at diagnosing systems: they run a command, read the output, form a hypothesis and run the next command. A jailbroken PS5 is a system worth diagnosing, but it is a hostile place for an agent:

- There is no real Unix shell. Agents cannot run Claude Code or Node.js on the console itself.
- The existing shell (shsrv) was built for humans typing into telnet. Arguments are split on whitespace with no quoting, output is free-form text, there is no exit status and no pagination.
- Getting a new payload onto the console is a manual process (download, FTP, send to the ELF loader), and a bad payload can crash or hang the system.
- Everything lives in RAM. A reboot wipes the jailbreak and every running payload.

Ariel closes that gap. The idea is that an agent connects to one endpoint on the console and gets a predictable, safe, recoverable interface to it.

## Progress

Work happens on the `dev` branch; `master` follows it at milestones. Each stage is a spec issue whose sub-issues are the work. Every console run is on a CFI-2014 on firmware 11.20.

| Stage | Spec | Status |
|---|---|---|
| 1. Hello world, end to end | [#1](https://github.com/sbihaiko/ariel/issues/1) | ✅ Done. Console suite 10/10; the quick start and the telnet boundary check passed ([#11](https://github.com/sbihaiko/ariel/issues/11)). |
| 2. Persist and recover | [#2](https://github.com/sbihaiko/ariel/issues/2) | ✅ Done on 2026-10-24. 37 sub-issues closed; console suite 36/36 and the telnet boundary check passed ([#46](https://github.com/sbihaiko/ariel/issues/46)). |
| 3. An interface agents can rely on | [#57](https://github.com/sbihaiko/ariel/issues/57) | ✅ Done. Nine sub-issues closed; the host acceptance suite covers it. |
| 4. Addons, and sight as the first one | [#54](https://github.com/sbihaiko/ariel/issues/54) | 🚧 In progress. Addons, their process contract and the one gate are done, and `addons/ftp/` moves bytes on a console ([#89](https://github.com/sbihaiko/ariel/issues/89)); the stage's **pilot addon is not built**, because it runs a capture ([#53](https://github.com/sbihaiko/ariel/issues/53)) and no capture route a payload can reach has answered with an image ([#100](https://github.com/sbihaiko/ariel/issues/100)). |
| 5. Sessions (optional) | | Not started. |
| 6. MCP (optional) | | Not started. |
| 7. Network sight (optional) | [#94](https://github.com/sbihaiko/ariel/issues/94) | Not started; one command, and a console spike gates it. |

**Stage 2** built everything [its goals](#stage-2-persist-and-recover) name, and `unzip` and `tar` refuse a member that escapes. The key work is the hierarchy and rotation ([#15](https://github.com/sbihaiko/ariel/issues/15), [#51](https://github.com/sbihaiko/ariel/issues/51)), the freeze ([#47](https://github.com/sbihaiko/ariel/issues/47)), revoking a lineage and suspending its grants ([#52](https://github.com/sbihaiko/ariel/issues/52)), and failing closed on damaged key state ([#48](https://github.com/sbihaiko/ariel/issues/48)). The key run on the console rotated, revoked, froze, unfroze, started without the keyring and restored it ([console findings](docs/console-findings.md#issue-48-keys-on-the-console)).

**Stage 3** implements the grammar of [ADR-0012](docs/adr/0012-the-agent-port-line-grammar.md):

| Issue | Delivered | Commit |
|---|---|---|
| [#58](https://github.com/sbihaiko/ariel/issues/58) | The grammar, ADR-0012 | `8e87996` |
| [#59](https://github.com/sbihaiko/ariel/issues/59) | One parser: quotes, the escaped canonical action the owner signs, the 60 s connection deadline | `02e9f0e` |
| [#60](https://github.com/sbihaiko/ariel/issues/60) | Bounded readers and the `truncated` marker | `cadf9ec` |
| [#61](https://github.com/sbihaiko/ariel/issues/61) | The binary `read` | `641f2f9` |
| [#62](https://github.com/sbihaiko/ariel/issues/62) | `write`, gated | `9c2380e` |
| [#63](https://github.com/sbihaiko/ariel/issues/63) | `--json` on `ps`, `ls`, `stat`, `df` and `find` | `cd62866` |
| [#64](https://github.com/sbihaiko/ariel/issues/64) | Missing flags: `ls -l -a`, `grep -r -l -c -e`, `find -name -type`, `rm -r` and `cp -r` | `03eef1c` |
| [#65](https://github.com/sbihaiko/ariel/issues/65) | Diagnostics: `date`, `du`, `dmesg` and `sysinfo` | `e99af35` |
| [#49](https://github.com/sbihaiko/ariel/issues/49) | `sfocreate`, gated | `5afbb06` |

The tokenizer refuses `bad_quoting` and a line over 64 tokens, and a word a command does not take answers `bad_option`. The deadline answers `timed_out`, so there is no separate `timeout`. No answer carries more than 64 KiB. A cut answer ends with `truncated <shown> of <total>`, and `read` answers `bytes <size> <sha256>`, then exactly that many bytes. Every command has its own error channel and an exit status from [docs/exit-codes.md](docs/exit-codes.md). The JSON commands and `sysinfo` answer one object per line ([docs/json-output.md](docs/json-output.md)), and `--limit` caps every listing that can flood. `cp -r` and `rm -r` are gated like every other file command. The optional `diff` and the network diagnostics were not built. The console evidence (read ranges, `cp -r`/`rm -r`, `sfocreate`/`sfoinfo`) is in [console findings](docs/console-findings.md#issue-61-64-and-49-stage-3-on-the-console).

## Goals

### Stage 1: hello world, end to end

The first milestone is the smallest loop that proves the whole idea: an agent builds a payload on a computer, pushes it to the console, the owner approves it with a key they hold, and the agent runs it and reads its output. The [quick start](docs/quick-start.md#after-stage-1) is this stage's acceptance test, and it runs headless in CI against a host build of Ariel.

- **An agent port (2324)** next to the telnet shell: raw TCP with no telnet negotiation, so a binary upload arrives intact. One command per connection after `auth`, no prompts, and every reply ends with an `exit <status>` line ([exit codes](docs/exit-codes.md)).
- **An access token** on the agent port. Every connection starts with `auth <token>`; Ariel shows the token on the console at first start.
- **`payload push <name> <size> <sha256>`** uploads a locally built ELF over the same connection, so no FTP server is needed. Ariel stages it and the console shows its hash.
- **Approval by the owner's key.** A push answers `approval_required <id>`; the owner signs the exact action with a key the agent does not hold. Approving a pushed build also approves running that exact build.
- **`payload commit <staging-id>`** moves an approved upload into Ariel's store. The bytes are sent once.
- **`payload list`** reads the state file and answers one `payload <name> ...` line per installed payload, with its source, version identifiers, hash, path, whether it is running, whether it is marked failed (`failed=yes|no`, always present, before `previous`) and `previous=<sha256|->`, the build the last commit replaced (`-` when there is none). It changes nothing.
- **`payload run --wait <name>`** runs a committed payload in the foreground through the ELF loader (no `chmod`), streams its output and reports the payload's exit status on a `status <n>` line, apart from the protocol's `exit` line.
- **A host build** of Ariel behind a platform port, with a test clock and a virtual controller that can only deny, for tests. It never ships in the PS5 build.

The agent port offers only these commands. Every command that changes the system stays on the telnet shell, exactly as in upstream shsrv, until Stage 2 gates it on the agent port.

**What protects the telnet shell is the [trusted-network rule](#safety-model) and nothing else.** It listens on port 2323 on every interface, asks for no token and no approval, and is the owner's escape hatch: the approval gate does not cover it. The decision is [ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md) decision 10, and [docs/telnet-boundary.md](docs/telnet-boundary.md) holds the manual check for this boundary. The headless suite covers the other half: the agent port refuses every command that changes the system, and a push waits for an approval.

### Stage 2: persist and recover

Make the console safe to leave in an agent's hands:

1. **Download a payload from a GitHub release**, by repository name, following the latest release or a pinned tag, and only from an allowlist of sources. Ariel records the immutable identifiers of what it downloaded (release ID, asset ID), since tags can be moved.
2. **Verify it** with SHA-256 before anything is executed. A hash published in the same release only detects corruption, not tampering, so the expected hash must come from somewhere Ariel trusts: either it is pinned in the allowlist, or the owner approves the new hash with their key (see [Safety model](#safety-model)), after which it is pinned.
3. **Run it in the background** through the ELF loader, tracking its PID and capturing its output to a log the agent can read later.
4. **Persist it**: record what is installed (source, identifiers, hash, path) in a state file under `/data`, and keep the autoload configuration up to date so payloads come back after a reboot. Approving an installation explicitly includes approving that the payload runs on every boot. `autoload safe-boot` skips autoload on the next boot, so a payload that crashes the console at startup can always be removed.
5. **Roll back on failure**: keep the previous version of every payload and a snapshot of the autoload configuration before each change. Changes are atomic and recorded in a journal, so a change interrupted by a crash or power loss is completed or undone the next time Ariel starts. A new version that crashes or fails its health check (explicit criteria and a timeout, defined per payload) is replaced by the last known good version automatically.
6. **Gate everything that changes the system on the agent port**: every existing command that changes the system, starts code or reveals the environment, including running an ELF by path (the full list is in [Command coverage](#command-coverage)). The telnet shell stays outside the gate, as [Stage 1](#stage-1-hello-world-end-to-end) says. Gating it needs a designed recovery path for a lost key first ([ADR-0008](docs/adr/0008-the-telnet-shell-stays-outside-the-gate.md), [the telnet boundary](docs/telnet-boundary.md)), and that path is the key hierarchy in item 7.
7. **Survive a leaked or lost key.** The build pins two keys: a primary that signs everyday approvals and an offline recovery key that is never on the agent's machine. A keyring on the console tracks the active keys and a generation, so the owner can rotate either key without a rebuild, and a signature made under one generation never verifies under another. A leaked key can be stopped: the owner freezes the console over the telnet shell, and only the recovery key can lift the freeze or revoke the compromised keys, suspending every grant they made. Damaged key state fails closed.

Ariel itself is never overwritten while it is running, so the agent can never lock itself out.

Ariel is not the boot loader: autoload is run at boot by another loader, and Ariel manages its configuration and keeps itself in it. So Ariel cannot re-check a payload's hash at boot; making Ariel the boot-time autoloader is a later decision.

New commands in this stage (see [Command coverage](#command-coverage)):

- `payload install | run | list | logs | rollback | config`. `run` without `--wait` starts a payload in the background and captures its output to a log; `config` sets a payload's health check.
- `autoload show | edit | safe-boot`, to inspect the autoload configuration and to boot without it when a payload keeps crashing.
- `sha256sum` was planned here and is not built: `read <path> --limit 0` answers `bytes 0 <sha256>`, the whole file's hash, in one read-only call, so a separate command would add a word and no capability.
- `unzip` and `tar`, because many GitHub releases ship payloads inside an archive.
- `reboot`, gated, to test that installed payloads survive a restart.
- `approval status <id>`, to poll a pending approval.
- `audit tail [n]`, to read the audit log: the newest `n` lines, at most 64.
- `key rotate | rotate-recovery | unfreeze | revoke`, to manage the owner's keys.

### Stage 3: an interface agents can rely on

Once the agent can operate the console safely, make the shell easy for it to use correctly. The grammar every command shares — quoting, the escaped canonical action, one frame for bytes, one output cap and one deadline — is [ADR-0012](docs/adr/0012-the-agent-port-line-grammar.md); this stage is where it is implemented.

- Proper argument parsing with quotes.
- Exit status and a separate error channel for every command, extending the Stage 1 grammar to all of them.
- Optional JSON output for `ps`, `ls`, `stat` and similar commands.
- Pagination and size limits, so a large directory or log does not flood the agent's context.
- Strictly non-interactive commands: no prompts in the middle of a session.
- No pipes or redirection. Commands that would need them get their own flags instead, such as `grep -c` for `| wc -l` and `--limit` for `| head`.

New and extended commands in this stage:

- Reading logs and large files: `head`, `tail`, `wc`, and a size limit on `cat`, including a way to pull a binary file back for Stage 4's screenshot.
- Writing files without redirection: `write <path>`, which reads the content from stdin.
- Missing flags on existing commands: `ls -l -a`, `grep -r -l -c`, more `find` predicates, `rm -r` and `cp -r`.
- Diagnostics: `date`, `dmesg`, `du`, and a `sysinfo` command that aggregates `uname`, `uptime` and memory. `timeout` was planned here and is not built: the 60 s connection deadline answers `timed_out`, and a health check carries its own bound through `payload config`.
- Optional, not built: `diff` (`cmp` answers same-or-differ and `hexdump` shows the bytes; a finer comparison is the agent's own work on its own machine), and `ifconfig` and `ping` (the console's address is the one the agent connected to, and a download that fails already answers reachability). `netstat` moved to [Stage 7](#stage-7-optional-network-sight), where it waits on a console spike.

### Stage 4: addons, and sight as the first one

An agent can read text all day and still be blind to what the console is doing: a game stuck on a menu, a system dialog waiting for an answer, a crash screen. This stage gives it sight, and it gives the console a way to gain capabilities that were not built into the payload.

An **addon** is an ELF and a manifest, and it runs in a process of its own ([ADR-0010](docs/adr/0010-an-addon-is-a-process-of-its-own.md)):

- Ariel is the gate and the router. An addon's command goes through the one gate every other command uses: a single-use approval of the canonical action, the audit words of the same shape, and codes from `docs/exit-codes.md`. There is no second gate.
- The agent cannot install, replace or remove an addon. Addons live in a protected directory that the file commands refuse like the token, and they enter only by the owner, out of band.
- The process is the isolation, and it is bounded on three sides: a timeout, an output cap and a kill. An addon that crashes, hangs or floods costs a refusal, not a reboot.
- A manifest that names another ABI version or another platform is refused before the owner is asked.

The how-to, with every manifest field, the process contract and the bounds, is [docs/addons.md](docs/addons.md). The repository holds two addons. [`addons/sight/`](addons/sight/) is the reference: it is the worked example every section of the how-to points at, and `make addon-sight` builds it once the capture path exists. [`addons/ftp/`](addons/ftp/) is the first addon that does work rather than refuse: one program built once and installed under four names, which moves files through the console's ftpsrv behind the one gate ([its page](addons/ftp/README.md)). Neither is part of `make all`.

The pilot addon the stage promised is the screenshot ([#53](https://github.com/sbihaiko/ariel/issues/53)), and it is what keeps the stage open: `addons/sight/` builds and installs once a capture path exists, and neither route a payload can reach has answered with an image yet. What the stage asks of it:

- One capture, one signature. The screen can show personal content, so the owner signs the action itself and not a bare path, and the audit log carries the path, the size and the hash.
- The shot lands under `/data`, never in Ariel's protected state directory, and Stage 3's reader returns it under its size limit.
- The capture API was measured on a real console ([#55](https://github.com/sbihaiko/ariel/issues/55)) before anything was built on it. It is the system screenshot daemon's IPC client: a payload loads it and sets its parameters, but `Capture` never completes, and **the console freezes until the owner resets it by hand** ([#79](https://github.com/sbihaiko/ariel/issues/79)). A screenshot therefore needs a path that does not hang the console, and **no capture attempt runs unless the owner is present and willing to reset it** ([console findings](docs/console-findings.md#issue-55-the-capture-api-on-the-console)).
- The other route was measured too ([#100](https://github.com/sbihaiko/ariel/issues/100)): the share library, `libSceShare.native.sprx`, loads in a payload and every export resolves, but `sceShareInitialize` answers `0x81960001` (an internal error) and every call made without a finished init answers `0x8196000C` (the library was not initialized). A null parameter block is still rejected by the export's own validation (`0x81960002`), so the calls run; the library never finishes starting. It never wedges the console and it never produces a file ([console findings](docs/console-findings.md#issue-100-the-share-route-and-the-error-it-stops-at)).

### Stage 5 (optional): sessions

Stages 1 to 4 are enough for an agent to operate the console and to see it; the two below are conveniences on top of them.

Agents usually reach the console through one-shot connections (one command per connection, e.g. `printf 'auth %s\nls --json /data\n' "$ARIEL_TOKEN" | nc ps5 2324`), so state such as the working directory would otherwise be lost between commands. Ariel keeps optional sessions on the console side:

- `session new` returns a random 128-bit session ID and its TTL. Prefixing a command with `@<sid>` runs it inside that session, and `session close` ends it.
- A session holds only minimal state: working directory, environment and timestamps. It carries no authorization. Creating a session requires the access token, and every gated command still needs its own approval. Payloads started from a session are not tied to it and keep running after it ends.
- Sessions expire after a period of inactivity, and the number of concurrent sessions is capped, so a client that forgets to close them cannot exhaust the console's RAM.
- An unknown or expired ID returns an explicit `session_expired` error instead of silently falling back, so the agent knows to open a new session (for example after a reboot).
- Session IDs are generated by a cryptographically secure random number generator and treated as secrets. Over plain-text connections they can still be sniffed, which is why they never authorize anything on their own.
- Sessions are isolated from each other, but the file system and installed payloads are shared. Stage 2 operations such as installing and rolling back take a global lock.
- Sessions are a convenience, not a requirement. Every command also works without one, using absolute paths.

### Stage 6 (optional): MCP

Expose the same capabilities as an [MCP](https://modelcontextprotocol.io) server, so any MCP client (Claude Code, Claude Desktop, or a local agent) can connect with structured tools instead of parsing shell text. The planned tool families are processes, payloads, file system, system information and logs. MCP is stateless since protocol version 2026-07-28, so a Stage 5 session ID is passed to each tool as an ordinary argument, as the specification recommends for server-minted handles.

### Stage 7 (optional): network sight

Stage 4 gave the agent sight of the screen. This one gives it sight of the console's own network state, which no current command exposes: which ports the console listens on and which peers it is connected to. Today an agent can only infer that by trying to connect ([#94](https://github.com/sbihaiko/ariel/issues/94)).

- One command, `netstat [-l] [-t] [-u] [--limit N] [--json]`, read-only and ungated like `ps` and `sysinfo`, numeric addresses only, bounded by the readers' 64 KiB cap and its `truncated` marker.
- It answers which payload is serving and which is not, which is the question an agent asks right after it launches one.
- A console spike comes first: prove on firmware 11.20 that a payload can enumerate the socket table without freezing the console or needing privileges it lacks, and record the interface it used in [console findings](docs/console-findings.md). The command is built only if the spike passes, and the stage closes either way. A failed spike is a result, as the capture spike was for sight.
- It deliberately builds no `ping`, `ifconfig`, `diff`, `timeout` or `sha256sum`: each is already covered by another mechanism, and the coverage table below says which.
- No new exit code and no change to the approval design: a read-only command is not gated, and `operation_failed` and the platform refusal carry its failures.

## Command coverage

Which bash commands an agent can expect on Ariel. Each row is an Ariel command. The **bash equivalent** column is filled in only when the name differs from bash; an empty cell means the command has the same name in bash.

**shsrv:** what upstream shsrv offers, the baseline Ariel started from: ✅ complete · ⚠️ partial · ❌ missing. **Plan:** S1 to S7 are Stages 1 to 7; S1 to S3 items are on `dev` and `master` (see [Progress](#progress)). "Gated" commands need the owner's approval before they run (see [Safety model](#safety-model)).

| Ariel | bash equivalent | shsrv | Plan |
|---|---|---|---|
| `pwd`, `cd` | | ✅ | S5: working directory kept across connections with sessions |
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
| `netstat` | | ❌ | S7 (optional): built only if the console spike proves the socket table is readable; see [Stage 7](#stage-7-optional-network-sight) |
| `ifconfig`, `ping` | | ❌ | Not built: the console's address is the one the agent connected to, and a download that fails already answers reachability |

PS5-specific commands with no bash equivalent: `hbldr`, `hbdbg`, `launch`, `pkg_install`, `suspend`, `notify`, `reptyr`, `authid`, `sfoinfo` and `sfocreate` (all in shsrv; from Stage 2 all but `authid` and `sfoinfo` are gated, and `sfocreate` joined them in Stage 3, #49), plus `payload` (Stage 1), `approval` and `autoload` (Stage 2) `session` (Stage 5) and `screenshot` (Stage 4).

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
- **Key rotation and recovery.** The primary and recovery keys can be rotated, and a lost or leaked key has a recovery path. [docs/key-recovery.md](docs/key-recovery.md) covers each case and the trust boundary, and says where the procedure still needs a rebuild.
- **Untrusted content is data.** README files, web pages and logs read by an agent may contain instructions. Approval by a key the agent does not hold ensures that injected instructions cannot silently turn into code execution.
- **Auditable.** Ariel is open source and every action it takes is logged on the console.

From Stage 6, MCP tools are also marked as destructive, so the MCP client asks a human before even requesting approval.

## Quick start

To build Ariel, start it on a console and run your first `helloworld.elf` from its shell, follow the [quick start tutorial](docs/quick-start.md).

## Using it today

Make sure [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr) is running and send `shsrv-ps5.elf` to port 9021. Ariel stops any running shsrv and takes its place. An agent connects to the agent port, 2324, with the token Ariel shows on the console at first start (the [quick start](docs/quick-start.md) walks through it). The telnet shell still answers on port 2323 exactly like upstream shsrv: type `help` once connected to see its commands (`cd`, `ls`, `mkdir`, `stat`, `ps` and others).

Payloads placed in a folder on the `PATH` (initialized to `/user/homebrew/bin` and `/mnt/usb0/homebrew/bin`) can be run directly. Homebrew that needs audio or video is launched through `hbldr`, and `hbdbg` starts it under gdb.

### Building

Ariel builds exactly like shsrv, with the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) installed on a Debian-based system: install `xxd`, point `PS5_PAYLOAD_SDK` at the SDK and run `make`.

To pin the owner's keys into the build, set both `ARIEL_PUBKEY` (the primary key that signs everyday approvals) and `ARIEL_RECOVERY_PUBKEY` (the offline recovery key), as 64 hex digits each: `make ARIEL_PUBKEY=<primary> ARIEL_RECOVERY_PUBKEY=<recovery>`. The two must differ, and setting `ARIEL_PUBKEY` without `ARIEL_RECOVERY_PUBKEY` stops the build, because the console would otherwise refuse every grant. The host build's test key is refused on the PS5 build.

`make test` sends `shsrv-ps5.elf` to the console at `PS5_HOST` and refuses unless you ask for it by name: `make test ARIEL_DEPLOY=yes PS5_HOST=<console>`. The headless acceptance suite is `make -C hostbuild test`; it needs no console.

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

- [Model Context Protocol](https://modelcontextprotocol.io): the standard Ariel will implement in Stage 6.

## Legal

Ariel is a tool for consoles you own. It does not contain exploits, does not bypass DRM, and does not distribute copyrighted software. Using a jailbroken console may void your warranty and violate the terms of service of its manufacturer.

## License

Ariel is a derivative work of ps5-payload-shsrv by John Törnblom and contributors, and like the original it is licensed under the **GPLv3 or later**. Credit for the shell, the ELF loader and the SDK belongs to the ps5-payload-dev project.
