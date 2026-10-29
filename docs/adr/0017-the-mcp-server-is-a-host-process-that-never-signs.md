# ADR-0017: The MCP server is a host process that never signs

## Status

Accepted. 2026-10-29.

## Context

Stage 7 exposes the console's commands as an MCP server, so an MCP client gets typed tools instead of parsing shell text. Three choices shape that server, and each is easy to reopen later for a good-sounding reason: where the server runs, whether it can approve anything, and what it is built from.

The approval model is fixed by [ADR-0006](0006-the-controller-is-the-approval-source.md) and [ADR-0009](0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md): the owner's signature is the approval, and the key stays with the owner. A client that could sign would make every gated command reachable from the network by whoever holds the client. The server must therefore add a transport and no authority.

The console already speaks the agent port's line grammar ([ADR-0012](0012-the-agent-port-line-grammar.md)), and its gate, audit and deadline are already decided. A server that reuses that grammar inherits all three without a second copy of the policy.

## Decision

1. **Topology.** The MCP server, `ariel-mcp`, is a host-side process. It speaks MCP over stdio to the client and the line grammar of [ADR-0012](0012-the-agent-port-line-grammar.md) over TCP 2324 to the console. It adds no payload code, no payload binary and no new console port. The console remains the authority for every gate, audit and deadline.

2. **The server never signs.** The server holds no private key and reads none. It refuses to start when a key path is passed to it, under any flag. A tool that needs an approval returns the `challenge` line to the client, the owner signs it with `ariel-sign`, and the signature comes back in the next call. The approval model of [ADR-0009](0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md) is unchanged by a new client.

3. **Language and build.** The server is C11 in the host build, compiled by the same `make -C hostbuild` that builds `ariel-host`, with the same flags as the rest of the host build. It has no dependency outside the C library: the JSON it reads and writes is small, and the repository already carries its own encoder. The server is built with no key and no `ARIEL_PUBKEY`, so its binary carries no secret. A build that needs anything else is a change of this decision. The gate stays the one command of [ADR-0015](0015-the-gate-is-one-command.md), and the server is covered by the host half.

4. **Protocol revision.** The server implements exactly one MCP protocol revision, **`2026-07-28`**, the latest revision published on the Model Context Protocol specification site when this ADR was written. `initialize` answers that revision. It never echoes a revision it does not implement, and it refuses a second `initialize` on the same stdio session. A client that speaks another revision decides for itself whether to continue, as the specification requires. The revision is named here and in `--list-tools`. Neither SPEC #1 nor SPEC #136 fixes one, so the choice is this ADR's, and a change of revision is a change of this decision.

5. **Transport and surface.** MCP over stdio, one JSON-RPC 2.0 message per line. The server supports `initialize`, `notifications/initialized`, `tools/list`, `tools/call` and `ping`, and nothing else. Tools are the only MCP surface: resources, prompts, sampling and elicitation are out of scope.

6. **Rejected: MCP served by the payload.** There is no MCP-over-HTTP on a console port. It would put JSON-RPC parsing inside the payload's stack budget ([ADR-0013](0013-the-connection-stack-is-a-budget.md)) and re-implement the gate for a second transport. The host process reaches the same console with the code that already exists.

7. **Rejected: signing inside the server.** The server never signs, under any flag. An owner who wants one-click destructive tools is asking to remove the model of [ADR-0009](0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md), which is a different decision and is not made here.

8. **What a new client must not add.** A new client, or a change to this server, must not add any of the following:
   - a flag, environment variable or config entry that passes a key or a key path to the server, or that makes it read one;
   - a tool, argument or code path that grants an approval or produces a signature;
   - a second console port, or any payload-side MCP or JSON-RPC code;
   - a dependency outside the C library, or a build that pins a key;
   - an `initialize` that answers a revision other than the one in decision 4.

## Consequences

- The client can ask for a destructive command, but it cannot approve one. The owner's signature is the only grant, as before.
- Adding a client costs no console code and no payload change, and no key leaves the owner's machine.
- The server's binary can be published without a secret, because it carries none.
- A new MCP revision is a deliberate change: it updates decision 4 and the `initialize` answer together.
- The server is not in the tree at the time of this ADR. Decisions 1 to 8 are the contract the server is built to. They are not a description of shipped behavior.

## Guard

None yet. This rule is a draft until a named guard test exists. The test to write with the server: `initialize` answers `2026-07-28` with `serverInfo.name` of `ariel`, a second `initialize` is refused, the server refuses to start when a key path is passed, and a `write` tool on a fresh agent returns `approval_required` with the challenge and not a grant.
