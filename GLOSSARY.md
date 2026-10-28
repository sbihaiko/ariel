# Glossary

Domain terms of Ariel. Use these words, in this sense, in code, tests, issues and docs.

## Console and ports

- **Console**: the jailbroken PS5 Ariel runs on.
- **ELF loader**: the payload (elfldr, port 9021) that loads ELF files sent to it. Ariel starts payloads through it.
- **Payload**: an ELF that runs on the console through the ELF loader. Ariel is one; the builds an agent pushes or installs are others.
- **Agent port**: TCP 2324. Raw, one command per connection after `auth`, every reply ends with an `exit <n>` line. The approval gate covers it.
- **Telnet shell**: TCP 2323, the shell inherited from shsrv. No token and no approval; the owner's escape hatch, outside the gate (ADR-0008).
- **Trusted-network rule**: the console sits on a network the owner trusts, or is reached through an encrypted tunnel. The only protection of the telnet shell.

## People

- **Owner**: the person who holds the signing key and decides what runs on the console.
- **Agent**: the program (an AI agent or a script) that talks to the agent port. It holds the access token, never the key.

## Access and approval

- **Access token**: 32 hex digits Ariel generates on first start. The first line of every agent connection is `auth <token>`. It lets a client talk; it approves nothing.
- **Gated command**: a command that does not run until the owner approves it. It answers `approval_required` (75) with a challenge.
- **Approval**: a single-use, short-lived permission for one exact action, bound to its facts. Pending, granted, expired or consumed.
- **Facts**: what an approval is bound to (name, size, hash, staging ID, path, release IDs, and so on). Ariel checks them again before it acts and answers `approval_stale` (78) if one changed.
- **Challenge**: the line `challenge <id> <console> <nonce> <issued-ms> <expires-ms> <action-hex> <generation>` the owner signs.
- **Canonical action**: the one byte encoding of an action, built by one function. The signer shows it and the signature covers it (ADR-0006).
- **Owner key**: the Ed25519 key pair whose public half is pinned into the build (`ARIEL_PUBKEY`). The approval source on the console.
- **Signer**: the owner's tool that shows a challenge's action and signs it (`ariel-sign`).
- **Nonce**: random, single-use value in each challenge. Persisted as consumed before the action runs, so a replay answers `approval_replayed` (84).
- **Console identity**: the name the console signs under (`ARIEL_CONSOLE_ID`, default `ps5`).
- **Grant ledger**: the protected file `grants` that records each persistent grant a key made (an install, a pin, an autoload entry) with the keyring generation that approved it, and the generation ranges `key revoke` declared compromised.
- **Suspended grant**: a grant whose generation a revocation declared compromised. Its build stays in the store but does not run, install or autoload, until an active key approves it again. Exit 90 (`suspended`).
- **Revocation by lineage**: `key revoke --since N`, signed by the recovery key: every primary from generation N to the current one is treated as compromised, and all their grants are suspended at once, because a leaked primary could have rotated to keys of its own.

## Store

- **Staging object**: an uploaded build waiting for approval, outside the store. Limited in count, size and TTL.
- **Store**: Ariel's hash-addressed directory of approved builds.
- **Version**: one immutable build of a payload, identified by its SHA-256 and, for releases, by release and asset IDs.
- **State file** (Stage 2): the single record of installed payloads, their versions, sources and health checks.
- **Journal** (Stage 2): the log that makes each change to the store or autoload atomic: prepared, committed, done or rolled back.
- **Previous version** (Stage 2): the version a rollback returns to.
- **Health check** (Stage 2): what makes an activated version healthy: one-shot (exits 0 in time) or service (still running after its grace period, optionally with a port open).

## Sessions (Stage 5)

- **Session**: optional state on the console side, named by its ID, that holds a working directory and a small environment between connections. It carries no authority and it dies with the process. A connection that names no session keeps the older behaviour: `pwd` at `/`, `cd` refused, every path absolute.
- **Session ID**: 32 lowercase hex characters (128 bits) that `session new` mints. A malformed, unknown or expired one answers `session_expired` (93).
- **Session prefix**: `@<id>` as the first token of a command line; the rest of the line runs inside that session.

## Sources

- **Download allowlist** (Stage 2): the hosts, repositories and CDN suffix a release may come from.
- **Pinned hash** (Stage 2): a SHA-256 the allowlist trusts for a payload, set in advance or by an approval.

## Boot

- **Autoload**: the configuration of the loader that starts payloads at boot. Ariel manages it; it is not the boot loader.
- **Safe-boot**: `autoload safe-boot`, which skips autoload for the next boot only.

## Protection

- **Protected object** (Stage 2): a file or process of Ariel's that no command may touch, approved or not. Answers `protected` (87).
- **Critical process**: a system process, such as SceShellCore, that `kill` refuses even with an approval.
- **Audit log** (Stage 2): the console-side record of every gated action, approval, install, run, rollback and recovery.

## Testing

- **Host build**: Ariel built for the computer, with a virtual approval source and a test clock, under `hostbuild/`.
- **Headless suite**: the acceptance scenarios run against the host build (`make -C hostbuild test`).
- **Console suite**: the scenarios that need no test clock, run against a real console when `PS5_HOST` is set.
- **Platform port**: the one interface between Ariel's logic and the OS, with a PS5 and a host implementation.
- **Test clock**: the host-only clock the suite moves instead of waiting.
- **Simulated reboot**: on the host build, a granted `reboot` that restarts Ariel's process and runs the autoload entries, as a boot does.
- **Crash restart**: a restart of Ariel that runs no autoload entry and restarts no payload.

## Verification

- **Title**: an application installed on the console, identified by its title ID.
- **License**: the file `/user/license/fake<CONTENTID>.rif` that lets a title run. Its content ID must equal the `CONTENT_ID` entry of the title's `PARAM.SFO` (ADR-0016).
- **Verify**: the read-only check that one title is structurally whole (`verify TITLE`). It changes nothing and needs no approval. `verify --all` is specified and not built.
- **Finding**: one failed check, reported as `finding <kind> <detail>`. Its kind is one of the closed set in `docs/exit-codes.md`.
- **Snapshot**: a bounded, named record of the console's state, kept by `trace`. Its fields are fixed and hold no file contents, token or approval state.
