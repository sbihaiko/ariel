# Exit codes of the agent port

The registry of every `exit <n>` value the agent port answers. A number is assigned here before code uses it, and a number is never reused for another meaning. A reply always ends with one `exit` line; the word on the line before it names the reason.

`payload run --wait` reports the payload's own status on a `status <n>` line, then `exit 0`. A payload's status never appears on the `exit` line.

`payload run <name>` without `--wait` answers `pid <n>` then `exit 0` at once and runs the payload in the background, cut at its timeout. `payload logs <name>` shows what the payload printed, then `exit 0`; for a payload still running it waits until the payload exits. `payload list` marks a background payload that is still going as running.

A shell command (`pwd`, `cd`, a read-only command that takes a path: `ls`, `stat`, `file`, `cat`, `grep`, `find`, `cmp`, `hexdump`, `df`, `sha256sum`, or an inspection command: `echo`, `help`, `id`, `sync`, `sleep`, `sum`, `sfoinfo`, `ps`, `procstat`, `sysctl`, `authid`) writes its output and its error word to the connection and ends with `exit <n>`, where `n` is the command's own status: 0 for success, 1 for an error such as `relative_path` or `no_working_directory`. `grep` and `cmp` also exit 1 when nothing matches or the files differ. A connection has no working directory, so every path is absolute and `cd` always fails.

The inspection commands add these error words, all with exit 1: `missing_operand` (an operand is required), `bad_duration` (`sleep` takes whole seconds from 0 to 60), `not_a_pid` (`procstat` takes a decimal pid), `no_such_process` (no process has that pid), and `not_sfo` (the file is not a PARAM.SFO). On the host build, `authid` answers `not available on this platform`, because it reads the console's kernel credentials. A `sysctl` write (`sysctl name=value`) is not a command of the agent port and answers `unknown_command`.

## Assigned

| Exit | Word | Meaning | What the agent does |
|---|---|---|---|
| 0 | | Success | |
| 1 | `unknown_command`, `bad_name`, `unknown_payload`, `grant_failed`, `already_running`, `too_many_runs`, `no_log`, `log_failed`, `spawn_failed`, others | Any other error | Read the word; do not retry as is |
| 70 | | Missing or wrong token; the connection is closed | Fix the token |
| 75 | `approval_required` | The action waits for the owner's signature; the reply carries the challenge | Have the owner sign, send `approval grant`, then repeat the command |
| 76 | `approval_busy` | Too many pending approvals, or a notification shown less than 10 s ago | Wait and push again |
| 77 | `approval_denied` | The owner refused. Only the host build's virtual source can refuse; the PS5 has no refusal, an unsigned approval expires | Do not retry |
| 78 | `approval_stale` | The approved target changed, or the approval is gone | Push again |
| 79 | `signature_invalid` | The signature does not verify against the pinned key | Do not retry with the same signature |
| 80 | `staging_full` | Staging is over its count or size limit | Wait for the TTL or commit pending objects |
| 81 | `upload_mismatch` | The upload ended early, ran past its size, or its hash differs | Push again |
| 82 | `busy` | Four connections are already served | Retry shortly |
| 83 | `signature_malformed` | The signature, console or action hash is not well-formed hex or is too long | Fix the `approval grant` line |
| 84 | `approval_replayed` | The signature's nonce was already consumed | Push again for a fresh challenge |
| 85 | `signature_action_mismatch` | The signer signed a different action than this approval | Sign this approval's challenge |
| 86 | `signature_console_mismatch` | The signer signed for another console | Sign with this console's identity |
| 87 | `protected` | The command reads one of Ariel's protected objects: the token, the approval state or the consumed nonces, directly, through a symbolic link or through a hard link. Refused even with an approval | Do not retry; these files are Ariel's own |
| 88 | `approval_expired` | The approval passed its expiry before it was granted or used | Push again |

Free from 89. The `status <n>` line is outside this registry.
