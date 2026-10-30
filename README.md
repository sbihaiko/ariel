# Ariel

**A PS5 payload shell built for AI agents.**

Ariel is a fork of [ps5-payload-dev/shsrv](https://github.com/ps5-payload-dev/shsrv), the telnet-like shell server for jailbroken PS5 consoles. It keeps everything shsrv does and grows it in one direction: letting an AI agent, such as Claude, inspect the console, download payloads from GitHub, run them and recover on its own when something crashes, without ever being able to leave the console in a broken state. Coding agents diagnose a system by running a command, reading the output and running the next one, and a jailbroken PS5 is a hostile place for that: there is no real Unix shell to run the agent on; shsrv was built for humans at a telnet prompt, with whitespace splitting, free-form output, no exit status and no pagination; getting a payload onto the console is manual, and a bad one can crash or hang the system; and everything lives in RAM, so a reboot wipes the jailbreak and every running payload. Ariel gives the agent one endpoint with a predictable, safe, recoverable interface.

The target firmware is 11.20, and only 11.20 for now ([ADR-0011](docs/adr/0011-the-target-firmware-is-11-20.md)). One console is in hand, a CFI-2014 on 11.20, every validation run happens there, and a behaviour reported on another firmware is not a defect until that firmware is adopted, which is a decision with its own console run, not a patch; supporting several firmware versions costs a lab this project does not have. On that console Stages 1 to 5 are delivered, and the current release is [`stage-5.1`](https://github.com/sbihaiko/ariel/releases/tag/stage-5.1). Stage 6, network sight ([#111](https://github.com/sbihaiko/ariel/issues/111)), has `ifconfig` and `ping` built and `netstat` not built; the judging verbs of [#119](https://github.com/sbihaiko/ariel/issues/119) — `verify`, `verify --all`, `trace`, `trace --list` and `trace --diff` — are in the current tree; Stage 7, the MCP server, is not started. See [Progress](#progress), [What is being done](#what-is-being-done) and [What is missing](#what-is-missing).

---

## How it is today

### Progress

Work happens on the `dev` branch and `master` follows it at milestones. Each stage is a spec issue whose sub-issues are the work, and every console run is on the CFI-2014 on 11.20.

Stage 1, hello world end to end ([#1](https://github.com/sbihaiko/ariel/issues/1)), passed its console suite 10/10, the quick start and the telnet boundary check ([#11](https://github.com/sbihaiko/ariel/issues/11)). Stage 2, persist and recover ([#2](https://github.com/sbihaiko/ariel/issues/2)), closed on 2026-10-24 with 37 sub-issues, a console suite of 36/36 and the boundary check passed again ([#46](https://github.com/sbihaiko/ariel/issues/46)); its key run rotated, revoked, froze, unfroze, started without the keyring and restored it ([console findings](docs/console-findings.md#issue-48-keys-on-the-console)).

Stage 3, an interface agents can rely on ([#57](https://github.com/sbihaiko/ariel/issues/57)), closed nine sub-issues: the grammar and its [ADR-0012](docs/adr/0012-the-agent-port-line-grammar.md), one parser with quotes and the escaped canonical action, bounded readers with the `truncated` marker, the binary `read` and the one-frame `write`, `--json` on the table commands, the missing flags on `ls`, `grep` and `find`, recursive `rm` and `cp`, the diagnostics (`date`, `du`, `dmesg`, `sysinfo`) and a gated `sfocreate`. The host acceptance suite covers it, and the console evidence for read ranges, `cp -r`/`rm -r` and `sfocreate`/`sfoinfo` is in [console findings](docs/console-findings.md#issue-61-64-and-49-stage-3-on-the-console).

Stage 4, addons with sight as the first one ([#54](https://github.com/sbihaiko/ariel/issues/54)), closed on 2026-10-25: the loader, the reference addon and `addons/ftp/` are done, and sight is `shots`, accepted by the owner because no capture route returns an image ([#53](https://github.com/sbihaiko/ariel/issues/53), [#100](https://github.com/sbihaiko/ariel/issues/100)). Stage 5, sessions, optional ([#101](https://github.com/sbihaiko/ariel/issues/101)), closed the same day with six sub-issues; the host acceptance suite covers the prefix, the directory, the relative paths, the environment and the limits, and the console round trip ran on the `stage-5` build ([#107](https://github.com/sbihaiko/ariel/issues/107)).

Judging what a change did ([#119](https://github.com/sbihaiko/ariel/issues/119)) followed Stage 6: `verify`, `verify --all`, `trace`, `trace --list` and `trace --diff` are in the current tree, and `pkg_install` now ends by naming the title it installed. The four losses are re-read against those verbs in [the loss record](docs/ps5-data-loss.md#the-four-losses-re-read-against-verify-trace-and-pkg_install).

### Installing and running it

The [quick start tutorial](docs/quick-start.md) goes from an empty checkout to a payload installed and run on a console, through the gate, with the owner's key. The short way is one script:

```console
$ sh tools/install/ariel.sh <console address>
```

It makes the two keys if they are not there, builds the payload with them pinned, sends it to port 9021, waits for the agent port, and leaves `ariel.env` holding `PS5_HOST` and `ARIEL_TOKEN`. `tools/install/ariel.command` is the same on a double-click on macOS and `tools/install/ariel.bat` on Windows, and `--check` says what it would do and sends nothing. Where the build happens depends on the machine ([#110](https://github.com/sbihaiko/ariel/issues/110)): a local LLVM means a local build, with the PS5 payload SDK downloaded on the way, and Docker is the fallback, building in a container that carries the SDK; an SDK already on the machine, with `PS5_PAYLOAD_SDK` set, is used as it is, and `ARIEL_BUILD=local` or `ARIEL_BUILD=docker` forces a route. Windows has no local route yet: `ariel.bat` runs `ariel.ps1`, which needs Docker Desktop running. The release carries those four scripts as its assets, and the payload is still built by you, with your keys.

By hand it is four steps. Clone the `stage-5.1` tag and run `make -C hostbuild`, which builds the signer as well as the host target. Make two keys with `./hostbuild/ariel-sign keygen`, a primary that signs everyday approvals and a recovery key kept offline. Build the payload with both public keys pinned, `make ARIEL_PUBKEY=<primary> ARIEL_RECOVERY_PUBKEY=<recovery>`, 64 hex digits each and different, because setting `ARIEL_PUBKEY` alone stops the build as a build with one key would refuse every grant. Send `ariel-ps5.elf` to port 9021, read the access token on the console, and talk to the agent port on 2324. The release ships source only, and it has to: the console carries the public half of **your** pair, so a build pinned to anyone else's keys could only be approved by them.

The gate is one command, `sh tools/gate.sh`: it builds the payload on whichever route the machine has (an exported `PS5_PAYLOAD_SDK` with LLVM, the SDK in `~/.local/share`, or a container from `tools/install/Dockerfile.sdk`), runs the host build and its headless acceptance suite, and names each half on its own line. A half it cannot run is reported `unavailable` and fails the gate, because a build that never happened is not a pass ([#118](https://github.com/sbihaiko/ariel/issues/118), [ADR-0015](docs/adr/0015-the-gate-is-one-command.md)).

Ariel builds like shsrv, with the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) on a Debian-based system: install `xxd`, point `PS5_PAYLOAD_SDK` at the SDK and run `make`. `make test ARIEL_DEPLOY=yes PS5_HOST=<console>` sends `ariel-ps5.elf` to the console and refuses without the explicit `ARIEL_DEPLOY`. The headless acceptance suite, `make -C hostbuild test`, needs no console: the host build sits behind the same platform port, with a test clock and a test key that signs the approvals a scenario asks for, and none of it ships in the PS5 build.

On the console, [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr) must be running on 9021; it runs each payload as a process of its own, so a crashing payload does not take the loader down. Ariel stops any running shsrv and takes its place. The telnet shell still answers on port 2323 exactly like upstream, and `help` lists its commands. Payloads in a folder on the `PATH` (`/user/homebrew/bin` and `/mnt/usb0/homebrew/bin`) run directly; homebrew that needs audio or video is launched through `hbldr`, and `hbdbg` starts it under gdb. Inherited from shsrv, the shell is not attached to a TTY, so homebrew that changes terminal properties will not work.

### Using the console from an agent

`ariel-mcp` is the host-side MCP server: one binary per machine, with no checkout and no toolchain. A machine that has never seen this repository runs the block below in order, with the console address and the access token the owner gives in place of `<console address>` and `<token>`. `<home>` is the output of `echo $HOME`, because TOML does not expand it.

1. Download the binary for this machine from the stable release address:

   ```sh
   case "$(uname -s)-$(uname -m)" in
     Darwin-arm64) asset=ariel-mcp-macos-arm64 ;;
     Darwin-x86_64) asset=ariel-mcp-macos-x86_64 ;;
     Linux-x86_64) asset=ariel-mcp-linux-x86_64 ;;
     *) echo "no ariel-mcp binary for $(uname -s) $(uname -m)" >&2; exit 1 ;;
   esac
   curl -fL -o "$HOME/ariel-mcp" "https://github.com/sbihaiko/ariel/releases/latest/download/$asset"
   ```

2. Make it executable:

   ```sh
   chmod +x "$HOME/ariel-mcp"
   ```

3. Register it with Claude Code:

   ```sh
   claude mcp add -s user ariel -e PS5_HOST=<console address> -e ARIEL_TOKEN=<token> -- "$HOME/ariel-mcp"
   ```

4. Register it with Codex by appending this table to `~/.codex/config.toml`:

   ```toml
   [mcp_servers.ariel]
   command = "<home>/ariel-mcp"
   env = { PS5_HOST = "<console address>", ARIEL_TOKEN = "<token>" }
   ```

5. Prove it works. This is the last step:

   ```sh
   "$HOME/ariel-mcp" --check --host <console address> --token <token>
   ```

   On success it prints one line and exits 0:

   ```console
   ariel-mcp: console <console address>:2324 accepted the token
   ```

   A refused token or an unreachable console exits 1 with one `ariel-mcp:` line that names what failed.

The surface gives no signing, no capture and no restart. The server holds no key and never signs: a change that needs approval returns a challenge, and the owner signs it on their own machine. It gives no screen capture: `shots` copies an image the console's Create button already wrote. It gives no restart: there is no reboot tool, and `reboot` on the console answers `reboot_unsupported`. Claude Code and Codex are the two clients this section covers.

### The agent port

The agent port is 2324, raw TCP with no telnet negotiation, so a binary upload arrives intact. Every connection starts with `auth <token>`, the token Ariel shows on the console at first start; then one command per connection, no prompts, and every reply ends with an `exit <status>` line, so agents reach it one shot at a time, e.g. `printf 'auth %s\nls --json /data\n' "$ARIEL_TOKEN" | nc ps5 2324`. A command called gated below needs the owner's signature before it runs; the design is in [Safety model](#safety-model).

**The grammar** ([ADR-0012](docs/adr/0012-the-agent-port-line-grammar.md), the full rules). Arguments are quoted, a line holds at most 64 tokens, one connection holds a 60 s deadline, and no answer carries more than 64 KiB: a cut answer ends with `truncated <shown> of <total>`, and `--limit` caps every listing that can flood. `read` answers a binary frame, `write` takes one. Every command has its own error channel and an exit status from [docs/exit-codes.md](docs/exit-codes.md); the table commands answer `--json` as one object per line ([docs/json-output.md](docs/json-output.md)). There are no pipes, redirection, `&&`, shell variables, scripts, editors, `ssh`, `top` or package managers: a command that would need a pipe gets a flag instead, such as `grep -c` for `| wc -l`, and the agent composes logic on its own machine.

**Payloads.** `payload push <name> <size> <sha256>` uploads a locally built ELF over the same connection, so no FTP server is needed; Ariel stages it and the console shows its hash. `payload install` downloads one from a GitHub release, by repository name, latest or a pinned tag, only from an allowlist of sources, recording the immutable release and asset IDs since tags can be moved, and verifying SHA-256 before anything runs; the expected hash is pinned in the allowlist or approved by the owner's key. `payload commit <staging-id>` moves an approved upload into the store, so the bytes are sent once. `payload run --wait <name>` runs a committed payload in the foreground through the ELF loader, streams its output and reports the payload's status on a `status <n>` line apart from the protocol's `exit`; without `--wait` it runs in the background with a log `payload logs` reads. `payload list` describes what is installed and changes nothing, `payload config` sets the health check, and `payload rollback` returns to the previous version. `unzip` and `tar` unpack the archives releases ship and refuse a member that escapes.

**Persistence and recovery.** What is installed is recorded in a state file under `/data`, and the autoload configuration is kept up to date so payloads come back after a reboot; approving an installation includes approving that it runs on every boot. `autoload show | edit | safe-boot` inspect it, edit it, and skip autoload on the next boot, so a payload that crashes the console at startup can always be removed. Every payload keeps its previous version and every change snapshots the autoload configuration first; changes are atomic and journaled, so one interrupted by a crash or power loss is completed or undone when Ariel next starts, and a new version that crashes or fails its health check is replaced by the last known good one. Ariel is never overwritten while it is running, so the agent can never lock itself out. `reboot` does not restart the machine on this firmware: no call from a payload does, and the probe behind [#135](https://github.com/sbihaiko/ariel/issues/135) is how that was measured. `reboot(2)` puts the console into standby, `sceSystemServiceRequestReboot`, `sceSystemStateMgrReboot` and `sceSystemServiceRequestPowerOff` answer success and change nothing, and `sceApplicationSystemReboot` is refused; every payload keeps its ports and the jailbreak stays loaded across that standby. So `reboot` on the console answers `reboot_unsupported` with exit 1 and asks nobody, and the standby has an honest route of its own, the shell's `suspend` built-in. What a payload can do is shut the console down through the console's own path: the gated `shutdown` command calls `sceShellCoreUtilRequestShutdown`, which unmounts both removable volumes and runs the `/user` cleaner before the machine goes off, and its challenge signs the mounted volumes it will unmount and their hash. The transcript is in [console findings](docs/console-findings.md#issue-135-what-the-system-shutdown-path-does-on-firmware-11200005).

**Keys.** The build pins a primary key that signs everyday approvals and an offline recovery key never on the agent's machine ([ADR-0009](docs/adr/0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md)). A keyring on the console tracks the active keys and a generation, so `key rotate` and `key rotate-recovery` work without a rebuild and a signature under one generation never verifies under another. A leaked key can be stopped: the owner freezes the console over the telnet shell, and only the recovery key can unfreeze or revoke, suspending every grant the compromised keys made. Damaged key state fails closed, and [docs/key-recovery.md](docs/key-recovery.md) covers each case and where a rebuild is still needed. `approval status <id>` polls a pending approval; `audit tail [n]` reads the newest audit lines.

**Sessions** ([ADR-0014](docs/adr/0014-the-session-prefix-and-the-resolved-path.md)). Without a session every path is absolute and a relative one answers `relative_path`. `session new` mints a 32-hex-character ID with a 600-second idle window; `session close <sid>` ends it, and `session list` shows the live ones with their directory and their environment size. A first token `@<sid>` runs the line in that session, which starts at `/`. A relative operand resolves against the session's directory lexically, before the gate, so the owner signs the absolute path, the session ID never enters the canonical action, and every gated command still asks for its own approval. `export` and `env` work per session, the environment reaching a payload at the spawn, so a later `export` never reaches a running payload and closing the session leaves its payloads running. The limits are eight sessions, ten idle minutes and sixteen names of at most 32 bytes; a malformed, unknown or expired prefix answers `session_expired` (exit 93) before the rest of the line and before any gate. Sessions share the file system, the payload store and the global locks, live in process memory, expire on restart, and authorize nothing: an ID is as sniffable as the token, and `session list` shows every live one to any token holder.

**Addons** ([ADR-0010](docs/adr/0010-an-addon-is-a-process-of-its-own.md), [docs/addons.md](docs/addons.md)). An addon is an ELF and a manifest that runs in a process of its own, through the one gate every other command uses, with the same audit words and exit codes. The agent cannot install, replace or remove one: addons live in a protected directory the file commands refuse like the token, and enter only by the owner, out of band. The process is bounded by a timeout, an output cap and a kill, so one that crashes, hangs or floods costs a refusal, not a reboot, and a manifest that names another ABI version or platform is refused before the owner is asked. The repository holds two, neither part of `make all`: [`addons/sight/`](addons/sight/), the reference the how-to points at, built by `make addon-sight`, which refuses because no capture route exists; and [`addons/ftp/`](addons/ftp/), one program installed under four names that moves files through the console's ftpsrv behind the gate ([its page](addons/ftp/README.md)).

**Sight.** `shots` copies out of the gallery the console's own Create button writes at `/user/av_contents/photo`: `--last` the newest image, `--count <n>` the newest `n`, `--minutes <n>` the images of the last `n` minutes, `n` from 1 to 64. It captures nothing and writes nothing in the gallery. It is gated with the selector in the signed action (`option.select`); each copy lands under `/data/shots`, the reply names path, size and SHA-256, and an empty gallery answers `no_shots` before the owner is asked. Why it is a copy and not a capture is in [Standing limits](#standing-limits).

**Judging a change** ([#119](https://github.com/sbihaiko/ariel/issues/119)). `verify <TITLE>` says whether one installed title is whole: one line per check, `ok <check>` or `finding <kind> <detail>`, then `whole <TITLE>` with exit 0 or `not_whole <TITLE>` with exit 1; `--size N` and `--sha256 H` compare `app.pkg` against what the caller expects. A title is whole when `app.pkg`, `app.pbm`, `app.json`, `app.xml` and `sce_sys/param.sfo` are regular files of at least one byte, and its `user/appmeta/<TITLE>` entry exists; its licence must exist and its content ID must name the title's `PARAM.SFO` content ID, never the directory name. A title with no licence answers `finding licence_missing <TITLE>`. A file over 256 MiB is not hashed: it answers `too_large_to_verify` and the title is not whole. A title whose directory is absent answers `not_installed`. `verify --all [--floor N]` runs the same checks over every installed title, then the console-wide ones — a licence naming no title (`licence_orphan`), a staging directory naming no title (`staging_orphan`), free space below the floor (`space_below`) and a store it could not list (`unsupported`) — and answers `whole console` with exit 0 or `not_whole console` with exit 1. Neither verb asks the owner, and neither writes anything.

**Trace.** `trace NAME` records the console's state before something risky, in Ariel's own record directory under `/data/ariel/traces/records`: `clock`, `uptime`, `free`, `mounts`, `titles` with each title's bytes, `metadata`, `licences`, `running` and the `boot` marker, with names escaped so a space or a `%` in a path cannot be read as a second field. It answers the record in full, then `recorded NAME`; each count line gives the total and each list shows at most sixteen entries, so a console with many titles still fits the answer cap. Eight records are kept and survive a restart, `--replace` writes over one, and a kept name answers `trace_exists` (96) without it. `trace --list` names the records in name order and `trace --diff NAME` reads the console again and answers one line per changed field, `<field> <before> <after>` with `absent` on the missing side, then `changed <n>`; a diff with nothing changed answers the single word `trace_unchanged`, and a name that is not kept answers `trace_missing` (95). `clock` and `uptime` are never compared, `free` only when it moves by more than 16 MiB and the boot marker only when it moves by more than a second, because those move on their own. A diff is evidence, never a verdict: it says what moved, and whether that is a loss is the owner's reading.

### What the agent can do

The port offers one command per connection, and the set is chosen so that an agent can see the console, move files, install and run payloads, keep its place between connections and recover from a bad payload — while nothing that changes the console happens without the owner's signature. Every answer is lines of text ending in `exit <status>`, with a word on its own channel when it fails ([docs/exit-codes.md](docs/exit-codes.md)), so an agent branches on a word and never parses prose. Where a shell would need a pipe, a flag stands in: `grep -c` for `| wc -l`, `--json` for a parser, `--limit` and the 64 KiB cap for a pager.

| What it is for | Commands | Asks the owner |
|---|---|---|
| Looking around the file system | `ls`, `stat`, `file`, `df`, `du`, `find`, `cat`, `head`, `tail`, `wc`, `grep`, `cmp`, `hexdump` | no |
| Pulling a binary back | `read`, which answers a byte range with the file's size and SHA-256, and `sha256sum` | no |
| Reading the machine | `ps`, `procstat`, `dmesg`, `sysinfo`, `date`, `sysctl` for a parameter, `id`, `authid`, `sfoinfo`, `sum`, `sync`, `echo`, `help`, `sleep` | no |
| Seeing the network | `ifconfig [--json]`; `ping [-c N] [-W MS] ADDRESS`, with `N` from 1 to 10 (4 by default), `MS` from 1 to 5000 (1000 by default) and a literal IPv4 address | no |
| Changing files | `mkdir`, `rmdir`, `touch`, `ln -s` (a gated symbolic link), `ln` (a hard link, which this console refuses), `cp`, `mv`, `rm`, `chmod`, `chown`, `chgrp`, `write`, `unzip`, `tar` ([#137](https://github.com/sbihaiko/ariel/issues/137)) | yes |
| Installing and running payloads | `payload push`, `payload commit`, `payload install`, `payload config`, `payload rollback`, `payload run`, `payload list`, `payload logs` | push, commit, install, config and rollback; `run`, `list` and `logs` ask nobody |
| Keeping a place between connections | `session new`, `session close`, `session list`, the `@<sid>` prefix, `pwd`, `cd`, `export`, `env` | `export` and `env` |
| Following an approval | `approval grant`, `approval status`, `audit tail` | `grant` submits the owner's signature; the others, no |
| Managing the keys | `key rotate`, `key rotate-recovery`, `key revoke`, `key unfreeze`, `key adopt-anchor` | yes |
| Surviving a reboot | `autoload show`, `autoload edit`, `autoload safe-boot` | `edit` and `safe-boot` |
| Changing the system | `kill`, `mount`, `umount`, `chroot`, `mknod`, `exec`, `sysctl` for a write, `http2_get` | yes |
| Stopping or suspending the console | `shutdown`, which goes through the console's own path; `reboot`, which answers `reboot_unsupported` because no route from a payload restarts the console; the shell's `suspend` built-in, which suspends rather than restarts | `shutdown` and `suspend` |
| Seeing the screen | `shots` | yes |
| Judging what it changed | `verify`, `verify --all`, `trace`, `trace --list`, `trace --diff` | no |
| Running an addon | `addon list`, `addon check`, `addon run` | `run` |
| The console's own built-ins | `hbldr`, `hbdbg`, `launch`, `pkg_install`, which ends by naming the title it installed, its bytes and its hash or `-`, `suspend`, `notify`, `reptyr`, `sfocreate` | yes |

`authid` and `sfoinfo` are the two PS5 commands that read only, and `sfocreate` joined the gated set in Stage 3 ([#49](https://github.com/sbihaiko/ariel/issues/49)). `pkg_install` is the one built-in that answers a fact it measured rather than the call's return: an install is accepted before it is finished, so the command waits for the app directory and the title's parts, then answers `installed <TITLE> <bytes> <sha256>`, or `install_incomplete <TITLE> <part>` naming the first missing part — `package`, `sfo`, `appmeta` or `licence` — with exit 1. For a finished source package over 256 MiB, its hash is not read and the successful ending is `installed <TITLE> <bytes> -`; a name with no title ID ends `install_incomplete - package`. `ifconfig` and `ping` are the two network commands on the port, each built from a probe that passed on 11.20 ([Stage 6](#stage-6-optional-network-sight)). `netstat` is not built at all, because this firmware exposes no socket table. `diff` and `timeout` are deliberately absent: what covers each is in [What is missing](#commands-deliberately-not-built).

### Safety model

An agent that can download, write and execute code on a console with kernel privileges needs firm limits. Reading is allowed within limits: inspecting processes, files and logs needs only the access token, output is size-limited, `env` is gated, and Ariel's own secrets, its token and approval state, cannot be read through any gated command.

Change is approved by the owner's signature. Writing files, killing processes, mounting, shutting the console down or suspending it, downloading and executing payloads are gated: Ariel answers `approval_required <id>` instead of running, the owner's signer shows the exact action (command, target, hash, console, expiry), and the action runs only after that signature verifies on the console. The approval is bound to that action, used once and short-lived. The agent cannot forge it because it never holds the key, which is why a flag such as `--confirm` would not do: the agent could pass it. Approving a payload version, at install or commit, also approves running that exact version, so a build is approved once, not once per run. The controller was measured as the alternative and ruled out, because a payload cannot read the pad and borrowing it from the foreground title freezes the game ([ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md), [console findings](docs/console-findings.md)). Untrusted content stays data: README files, web pages and logs an agent reads may contain instructions, and approval by a key the agent does not hold means injected instructions cannot silently turn into code execution.

Downloads come only from approved hosts and repositories, and a payload runs only if its hash is pinned in the allowlist or was approved by the owner. System partitions stay read-only, and critical system processes such as SceShellCore cannot be killed. Atomic journaled changes, a previous version of every payload and `autoload safe-boot` cover crashes, failed health checks and interrupted updates, but not every possible failure. Ariel is open source and every action it takes is logged on the console.

The telnet shell is outside the gate. Approvals cover the agent port; the telnet shell on port 2323 is the owner's escape hatch, listens on every interface, asks for no token and no approval, can write, kill, mount and run, and can read the secrets the gated commands refuse ([ADR-0006](docs/adr/0006-the-controller-is-the-approval-source.md) decision 10, [ADR-0008](docs/adr/0008-the-telnet-shell-stays-outside-the-gate.md)). [docs/telnet-boundary.md](docs/telnet-boundary.md) holds the manual check, and the headless suite covers the other half, that the agent port refuses every command that changes the system and a push waits for an approval. The protocol is plain text, so the access token and session IDs can be sniffed by anyone on the same network: Ariel is meant for a trusted home network, and on any other an encrypted tunnel. On the agent port the owner's signature keeps destructive actions safe even if the token leaks; nothing but the network protects the telnet shell.

## What is being done

### Stage 6 (optional): network sight

The spec is [#111](https://github.com/sbihaiko/ariel/issues/111), which replaces [#94](https://github.com/sbihaiko/ariel/issues/94), a spec for `netstat` alone under the number 7 the stage carried then, whose spike never ran. Its sub-issues are closed or refused, and the spec closed on 2026-10-26. The spike ran on 2026-10-25 on the CFI-2014 at firmware 11.20 and answered two of its three questions: the interface list and the loopback echo were read, so `ifconfig` and `ping` are built; the socket tables were refused under the FreeBSD names, so `netstat` is not built ([#117](https://github.com/sbihaiko/ariel/issues/117), [console findings](docs/console-findings.md#network-spike-the-three-probes-on-firmware-1120)).

No current command says which ports the console listens on or which peers it is connected to: the only way to learn whether a payload is serving is to try to connect, where a refusal and a slow accept read the same. The address the agent connected to says nothing about a second interface or one that is down, and a failed download cannot separate an address that never answered from one that refused. The console answers ping while asleep and running no payload ([#71](https://github.com/sbihaiko/ariel/issues/71)), so a reply says the network stack is alive, never that a payload is.

The stage is three read-only, ungated commands over numeric addresses only, each bounded so none can hold the console, and each built only if its own console probe passes on 11.20. What each probe answered, and whether its command exists:

- **`ifconfig`: built.** Probe 1 read the interface list through `PF_ROUTE` and `NET_RT_IFLIST`: 1408 bytes, 4 interfaces, 5 addresses. The command lists every interface with its address, mask and administrative state, and takes `--json`. [Transcript](docs/console-findings.md#probe-1-interfaces)
- **`netstat`: not built.** Probe 2 asked for the TCP and UDP socket tables under `net.inet.tcp.pcblist` and `net.inet.udp.pcblist`, and both were refused with errno 2 on the size query, so this firmware gives no socket table under those names. The command was to list the sockets, one line each, and [#114](https://github.com/sbihaiko/ariel/issues/114) is closed as not planned. [Transcript](docs/console-findings.md#probe-2-sockets)
- **`ping`: built.** Probe 3 opened a raw ICMP socket, and a loopback echo came back. The command answers whether a literal IPv4 address replies and how long it took, with the count capped at ten and each wait at five seconds, so the worst case is 50 s, inside the connection deadline; it sends a fixed probe and never returns the reply's bytes. [Transcript](docs/console-findings.md#probe-3-echo)

The line formats, the JSON keys and every refusal word are fixed in the spec, so a ticket never has to invent one.

The probe came first and was a payload of its own, as the controller, capture and share spikes were: never linked into Ariel, run with the owner present, three probes from least to most risky (the interface list, the socket tables, the echo), a selector to run one alone, and a log under `/data` so a freeze is attributable. A failed probe is a result: the findings record the transcript, the command list says it is not built and gives the reason, and the stage closes either way — which is what happened to `netstat`. The console build answers from system calls, never a shell-out, and the host build reports its own machine, as `ps` and `sysinfo` do. There is no new exit status and no change to the approval design: `bad_option`, `bad_argument`, `missing_operand`, `operation_failed`, the platform refusal and `no_reply` carry every failure.

## What is missing

### Stage 7 (optional): MCP

Not started. The plan is to expose the same capabilities as an [MCP](https://modelcontextprotocol.io) server, so any MCP client (Claude Code, Claude Desktop, or a local agent) can connect with structured tools instead of parsing shell text. The planned tool families are processes, payloads, file system, system information, logs and network sight, the last covering `ifconfig` and `ping`, the two commands Stage 6 built. MCP is stateless since protocol version 2026-07-28, so a Stage 5 session ID is passed to each tool as an ordinary argument, as the specification recommends for server-minted handles. MCP tools that change the console would be marked destructive, so the client asks a human before even requesting approval.

### Commands deliberately not built

Two commands were planned and dropped because another mechanism already covers each: `diff`, which `cmp` (same-or-differ with the first differing offset) and `hexdump` cover, a finer comparison being the agent's own work on its own machine; and `timeout`, which the 60 s connection deadline covers with `timed_out`, and a health check with the bound `payload config` gives it. `netstat` is missing for a third reason: the console's kernel does not expose the socket tables under the names a payload can reach, so no command on the port can list them. Its sub-issue [#114](https://github.com/sbihaiko/ariel/issues/114) is closed as not planned ([Stage 6](#stage-6-optional-network-sight), [console findings](docs/console-findings.md#network-spike-the-three-probes-on-firmware-1120)). `ifconfig` and `ping` are not in this list because their probes passed: `ifconfig` and `ping` are built.

### Standing limits

There is no screen capture on 11.20. Both routes a payload can reach were measured and neither returns an image: the screenshot daemon's IPC client loads and takes its parameters, but `Capture` never completes and the console freezes until the owner resets it by hand ([#55](https://github.com/sbihaiko/ariel/issues/55), [#79](https://github.com/sbihaiko/ariel/issues/79)), and the share library loads and resolves every export, but initialization answers `0x81960001` because the service behind it never answers, so it never produces a file ([#100](https://github.com/sbihaiko/ariel/issues/100)). The transcripts are in [console findings](docs/console-findings.md#issue-55-the-capture-api-on-the-console). So `addons/sight/` has nothing to call and stays a reference that refuses, and sight is `shots`, which copies what the Create button wrote.

Ariel makes a symbolic link with `ln -s TARGET PATH`, gated like the other changes, and a read or a change never follows one into a protected object. A hard link is refused on this console: `ln` answers `operation_failed`, measured on 11.20 on both `/data` (nullfs over ufs) and the USB volume (exFAT). `mv` renames the name and copies only across filesystems, so it does not need a hard link; that is not yet measured on the console. A filesystem that cannot hold a symbolic link answers `link_unsupported` and creates nothing when `symlinkat` answers `EOPNOTSUPP`; the exFAT stick's answer is not yet measured ([#137](https://github.com/sbihaiko/ariel/issues/137)). A symbolic link lets the same file be shared between two emulators that each want their own directory, so the ROMs need not sit twice on the console.

Ariel is also not the boot loader: another loader runs autoload at boot, so Ariel cannot re-check a payload's hash then, and making it the boot-time autoloader is a later decision.

## Why "Ariel"

The PS5's internal codename is **Prospero**, the sorcerer of Shakespeare's *The Tempest*. Prospero rules his island through **Ariel**, a spirit who carries out his orders, reports back what it sees, and does nothing on its own initiative. That is the role of this project: the servant on Prospero's island (the console) that takes orders from whoever is in charge (you, through an AI agent), reports what it finds, and never acts beyond what it was told. The name also fits the ecosystem's tradition of Prospero-themed projects, such as prospero-win.

## References and related projects

The project's own documents are the [console findings](docs/console-findings.md), what the console allows with the error codes and addresses measured; the [console setup](docs/console-setup.md), how this console is jailbroken and how a package becomes an install; the [controller spike](docs/controller-spike.md), the payload that produced the pad measurements; and the [decisions](docs/adr/README.md), the architecture decision records. The upstream shell, ELF loader and SDK are linked where they are used above; the other ps5-payload-dev tools (GPLv3+) are [websrv](https://github.com/ps5-payload-dev/websrv), a homebrew launcher, ELF launcher and file browser over HTTP, and [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) and [klogsrv](https://github.com/ps5-payload-dev/klogsrv), the FTP server and kernel log server that are the usual companions for diagnostics.

The two payload managers that served as design references are [ChronicLoader](https://github.com/StonedModder/ChronicLoader-PS5-Payload), whose SHA-256 state, timestamped backups and managed autoload inspired Stage 2, and [ps5-payload-manager](https://github.com/itsPLK/ps5-payload-manager), a web-based store, launcher and autoload manager; ChronicLoader ships as a binary, so no code is reused. [PS5LM](https://github.com/cobanov/PS5LM) runs LLMs locally on a jailbroken PS5 and could be a fully offline brain for an Ariel agent, and the [Model Context Protocol](https://modelcontextprotocol.io) is the standard Ariel will implement in Stage 7.

## Legal

Ariel is a tool for consoles you own. It does not contain exploits, does not bypass DRM, and does not distribute copyrighted software. Using a jailbroken console may void your warranty and violate the terms of service of its manufacturer.

## License

Ariel is a derivative work of ps5-payload-shsrv by John Törnblom and contributors, and like the original it is licensed under the **GPLv3 or later**. Credit for the shell, the ELF loader and the SDK belongs to the ps5-payload-dev project.
