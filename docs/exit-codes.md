# Exit codes of the agent port

The registry of every `exit <n>` value the agent port answers. A number is assigned here before code uses it, and a number is never reused for another meaning. A reply always ends with one `exit` line; the word on the line before it names the reason.

`payload run --wait` reports the payload's own status on a `status <n>` line, then `exit 0`. A payload's status never appears on the `exit` line.

A shell command (`pwd`, `ls <absolute path>`, `cd`) writes its output and its error word to the connection and ends with `exit <n>`, where `n` is the command's own status: 0 for success, 1 for an error such as `relative_path` or `no_working_directory`. A connection has no working directory, so every path is absolute and `cd` always fails.

## Assigned

| Exit | Word | Meaning | What the agent does |
|---|---|---|---|
| 0 | | Success | |
| 1 | `unknown_command`, `bad_name`, `unknown_payload`, `grant_failed`, others | Any other error | Read the word; do not retry as is |
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
| 88 | `approval_expired` | The approval passed its expiry before it was granted or used | Push again |

## Reserved for Stage 2 (#2)

| Exit | Word | Meaning |
|---|---|---|
| 87 | `protected` | The command touches one of Ariel's protected objects, a critical process, or a path outside the writable roots. Refused even with an approval |

Free from 89. The `status <n>` line is outside this registry.
