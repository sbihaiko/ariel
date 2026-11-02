# ADR-0019: The console's Git credential is owner-delivered and repository-scoped

## Status

Accepted. 2026-11-02.

## Context

The PS5 Git spike ([SPEC #149](https://github.com/sbihaiko/ariel/issues/149))
asks the console to push to a private fixture repository. The console is a
jailbroken device on the LAN: every process on it can read every file on it,
and there is no secure store to put a secret in beyond a mode-0600 file.

The convenient credential is the owner's `gh` CLI OAuth token. It carries
`repo`, `workflow`, `gist`, `project` and `read:org`, so it reaches every
repository the owner can push to. Copying it to the console would put a
credential for the owner's whole account on that device.

Creating a scope-limited credential instead needs the owner: GitHub asks for
sudo mode (passkey, security key, GitHub Mobile, authenticator or password) on
the fine-grained token page, and none of those can be produced by an agent.
The owner was consulted through the GPT-6 Astra proxy, which ruled for a
repository-scoped token and against ever copying the broad one.

## Decision

1. A credential placed on the console is a fine-grained token limited to the
   one repository the work needs, and to the permission that work needs.
2. An agent never copies a broad OAuth token, a personal password or a
   long-lived account credential onto a console to get past a blocked step.
3. The token lives in one mode-0600 file. It is never written into a Git
   config, a commit, a log line or the repository checkout.
4. When creating the credential needs the owner's second factor, the loop
   stops at that boundary, records the exact reason on the ticket and in
   `docs/ps5python-owner-steps.md`, and resumes when the owner has done it.
5. The token is revoked when the spike ends, and its expiration is short.

## Consequences

- A spike that needs a credential cannot finish unattended; that is a
  deliberate stop, not a failure of the loop.
- The runner must fail closed: a missing token, a token file whose mode is not
  0600, or a token without push permission is refused by name, and the refusal
  changes nothing.
- The owner carries the cost of one manual step per credential.

## Guard

None yet. This rule is a draft until a named guard test exists; the runner's
`auth_check` refuses the two conditions it can observe, but no test pins the
behaviour yet.
