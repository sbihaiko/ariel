# Addons

An addon is a capability Ariel does not build in: an ELF and a manifest, in a directory of its own, run in a process of its own. This page is the how-to. Its reference is [`addons/sight/`](../addons/sight/), a screenshot addon that builds with `make addon-sight` and is never part of `make all`. The decision behind this shape is [ADR-0010](adr/0010-an-addon-is-a-process-of-its-own.md).

Every claim below is what the code does; the code path is `addon.c` for the manifest, the file and the process, and `agent.c` (`addon_run_command`) for the gate.

## Where an addon lives

An addon is a directory `/data/ariel/addons/<name>/` holding two files:

- `manifest`, a text file that says what the addon is (below).
- `elf`, the program, built for the console (PS5 SDK) and for ABI 1.

Ariel reads both each time an addon is checked or run. Nothing is cached, so a replaced file is judged again.

The owner installs an addon out of band, by a route the owner runs by hand and outside the agent port. The agent cannot install, replace or remove one: the agent port has no command that writes to the addon directory, and its file commands refuse every path under `/data/ariel/addons` with `protected` (87), including a link to one and a hard link to a file in it. `find` and `du` skip it. This is [ADR-0010](adr/0010-an-addon-is-a-process-of-its-own.md) decision 3.

## The manifest

The manifest is a regular file of at most 512 bytes. Each line is `key value`, one space between key and value, and the file ends with a newline. Each key appears exactly once, in any order. Any other line, key or value, a missing key or a repeated one makes the manifest malformed.

| Field | Form | Rule | Answer when it does not match |
| --- | --- | --- | --- |
| `name` | `name <name>` | Must equal the addon's directory name. The name is a payload name: 1 to 32 characters of `a-z`, `0-9`, `-` and `_`, starting with a letter or digit. | `manifest_malformed <name>` (92) when it differs; `bad_name` (exit 1) for an invalid directory name |
| `args` | `args <min>-<max>` | The number of arguments the addon takes. `min` and `max` are one or two decimal digits, `max` is at most 8, and `min` is not above `max`. | `addon_refused <name> args` (exit 1) for a run with a count outside the range |
| `abi` | `abi <n>` | The Ariel ABI the addon was built against: decimal, up to six digits. This build is ABI `1`. | `addon_refused <name> abi` (exit 1) |
| `platform` | `platform <ps5\|host>` | The platform the addon was built for. This build is `ps5` on the console and `host` on the host build. | `addon_refused <name> platform` (exit 1) |

An addon built for another ABI or another platform is refused by name, before the owner is asked. A run of it answers `addon_refused` and is audited as `addon.refused`, with no `addon.request`. When both `abi` and `platform` differ, the reply names `abi`, because the ABI is checked first.

The other manifest answers are:

- `addon check <name>` answers `addon <name> ok` and `exit 0` for an accepted manifest.
- A directory with no `manifest` file answers `manifest_missing <name>` and `exit 91`.
- A manifest that is malformed, or not a regular file, answers `manifest_malformed <name>` and `exit 92`.
- `addon list` prints one line per addon, then `exit 0`. One bad manifest does not hide the others.

The manifest's SHA-256 is computed over the file's bytes as read. It is the value the approval names (see the gate rule below).

## The elf

The `elf` file must be a regular file, not a link, of more than zero and at most 4 MiB bytes. A missing or unreadable `elf` answers `operation_failed` (exit 1). A run checks it before the owner is asked, and the refusal is audited as `addon.refused`.

## The process contract

When a run is granted, Ariel starts the `elf` in a process of its own:

- **Arguments.** `argv[0]` is the addon's name and `argv[1]` onward are the arguments the agent passed. The count is within the manifest's `args` range.
- **Environment.** Empty. The token, the keyring and the state directory are not passed, and the addon never receives Ariel's credentials.
- **Reads.** It reads its arguments and nothing else from Ariel. Its standard input is not part of the contract, so an addon must not wait on it.
- **Writes.** Its standard output and standard error go to the same pipe, which Ariel reads and copies, as the addon writes it, into a new file `/data/addon-<name>-<ms>`. `<ms>` is the platform clock in milliseconds. Nothing is written inside `/data/ariel`.
- **Working directory.** On the console the process starts in `/`. The host build starts it in the host build's own working directory.
- **Success.** An addon says it succeeded by exiting with status 0. Ariel keeps the file and answers `result /data/addon-<name>-<ms>`, then `status 0` and `exit 0`.
- **Failure.** An addon says it failed by exiting with any non-zero status. A death by signal is also a failure. Ariel then answers `operation_failed` (exit 1) and removes the file, so what the addon wrote to standard error, which is part of its output, does not reach the agent.
- **Start.** If the process cannot start, the run answers `spawn_failed` (exit 1).

Starting an addon is serialized with every other ELF start under the loader lock.

## The bounds

A run is bounded on three sides. Each bound ends the run with its own answer and removes the output.

- **Timeout.** The process has 10 seconds from the start. At the deadline Ariel kills it and answers `timed_out` (exit 1).
- **Output cap.** Standard output and standard error together may write 64 KiB (65536 bytes). More than that kills the process and answers `too_large` (exit 1). Exactly 64 KiB is allowed.
- **Kill.** Ariel kills with `SIGKILL` on a timeout, an output overflow or a failed read of the pipe, then reaps the process.

So a crash costs the run `operation_failed`, a hang costs `timed_out`, and a flood costs `too_large`. Each is a refusal of that run. Ariel keeps answering on the agent port afterwards, and the host build's acceptance suite proves this for each of the three.

## The gate rule

An addon's command is a gated command, like every other one. Ariel is the only gate.

- The first answer to `addon run <name> [args...]` is `approval_required` (75) with a challenge. The challenge names the command `addon`, the addon's name, the SHA-256 of its manifest, and the arguments (their count and a hash). The owner signs that challenge, and the approval is single-use, as for every other gated command.
- The addon's manifest is judged before the owner is asked (see above), so a refused addon is never presented for a signature.
- After a grant the run goes through the same audit words as every other gated command: `addon.request`, `addon.done` before the process starts, and `addon.failed` for each failed outcome. A denial is `addon.denied`; a stale approval is `addon.stale`.
- An addon has no approval path of its own, and it is not handed the token, the approval state or the state directory.

The process boundary bounds a run and keeps the addon out of Ariel's memory. It is not a sandbox: the addon has the privileges a payload has on the console, and it is trusted to the extent the owner installed it.

The challenge does not name the `elf` file's bytes. It names the manifest, as [ADR-0010](adr/0010-an-addon-is-a-process-of-its-own.md) decision 2 does. An `elf` replaced after the owner's grant would therefore run under that grant. The agent cannot make that replacement, because it has no path into the addon directory; the owner is the one who installs an `elf`.

## Writing your own

1. Copy [`addons/sight/`](../addons/sight/) to a new directory. The directory name is the addon's name.
2. Set `name` in `manifest` to that same name, and set `args`, `abi 1` and `platform ps5`.
3. Write the program so that it reads its arguments from `argv`, writes its result to standard output, and exits with 0 on success and non-zero on failure.
4. Build it with the PS5 SDK into `elf`, and install the directory under `/data/ariel/addons/` out of band.
5. Check it with `addon check <name>`, then run it with `addon run <name>`, and sign the challenge.

## The reference: sight

[`addons/sight/`](../addons/sight/) holds the reference addon's source (`sight.c`) and manifest. `make addon-sight` builds `addons/sight/sight.elf` with the PS5 SDK. The target is not part of `make all`, the same as the spikes, so the payload build never carries an example.

The manifest is `name sight`, `args 0-0`, `abi 1` and `platform ps5`. On the host build `addon check sight` answers `addon_refused sight platform`, which the acceptance suite checks.

The source names `sceScreenShotCapture` and never calls it. A capture attempt freezes the console until the owner resets it by hand ([console findings](console-findings.md)), so the addon refuses every run: it writes one line to standard error and exits with 2, and the run answers `operation_failed`. The source makes no capture call, so no capture is attempted on the console; a run on the console only answers the refusal.
