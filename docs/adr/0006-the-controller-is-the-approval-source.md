# ADR-0006: The owner's signature is the approval source on PS5

## Status

Accepted. Rewritten on 2026-10-23. The file name is historical: the first version of this decision made the controller the source, and the console run in [controller-spike-notes.md](../controller-spike-notes.md) overturned it.

## Context

An approval must come from a source the agent cannot reach from the network. An agent that could approve its own push, or forge an approval over TCP, would make the gate decoration.

The first version of this decision read that as the DualSense the owner holds, and left the spike to check one thing: whether a payload can read the pad while another app is in the foreground. The console answered on 2026-10-23.

- **The payload is not a registered pad client.** `scePadOpen` returns `0x809b0081` (`USER_NOT_LOGIN`), and `scePadReadState` of a handle that is valid inside the title returns `0x80920003`.
- **The foreground title can read the pad.** With `PPSA99177` in front, a read inside its `eboot.bin` returned `connected` 1 and `buttons 0x00004000` while Cross was held.
- **Borrowing that read is not viable.** `pt_call` single-steps the title. One run took a sample and then never returned; the console had to be rebooted.

The controller is therefore neither readable by the payload nor safe to borrow. The earlier wording — "the source is never reachable over the network" — was also too literal. What the agent must not be able to do is *forge* an approval. Relaying one is harmless.

What the console can still do is verify a signature: one public-key operation, no hardware, no title in the foreground.

## Decision

1. **The PS5 implementation of the platform port takes approvals as a signature by a key the owner holds**, verified inside the payload against a public key pinned in the build.
2. **"Unreachable from the network" applies to the key and the signing act, not the transport.** A signature may arrive over any channel, including one the agent controls, because it cannot be forged there. This replaces the earlier reading that the source itself never touches the network.
3. **The owner signs an action, not a hash.** The signer shows the canonical action — command, target, payload SHA-256, console identity, expiry — before the owner confirms. Approving an opaque digest is not approving an action.
4. **The signed message is domain-separated**: domain tag, console identity, canonical action bytes, nonce, issued-at, expiry. A signature for one console or one action does not verify for another.
5. **Nonces are CSPRNG, single-use and short-lived, and are persisted as consumed before the action runs**, so a reboot cannot replay one.
6. **Canonicalization is part of this decision, not an implementation detail.** One function turns an action into bytes and it is the only one. Ambiguity in paths, Unicode, option order or omitted fields is a defect in it, because it turns "the exact action" into a lie.
7. **The verifier sits behind the platform port**, like the source it replaces. Nothing above the port learns how an approval arrives.
8. **The host build accepts a test key that the PS5 build cannot be configured to accept.** The virtual controller stays host-only, for tests.
9. **Rejected as approval sources**: reading the pad in the payload and borrowing it from the foreground title (measured above); kernel-level HID reads and `SceShellUI` injection (more privileged surface and per-firmware maintenance than the gate is worth, and untested); a virtual controller (it creates synthetic input rather than expressing the owner's intent).
10. **This gate covers the agent port.** Any other path that can perform a destructive action is gated on its own terms, not by this decision.

## Consequences

- Stage 1 ships without a physical gesture. The owner needs a signer — a phone with a secure enclave or a hardware key — and one extra step per gated action.
- Losing the key is a recovery problem, and the recovery path must not become a bypass the agent can drive. It is not designed yet.
- The verifier runs in the same trust domain as the action. A compromised payload defeats the gate; this protects against a confused or over-eager agent, not a compromised console.
- The console suite can be specified against a host-side test key plus one real signing run.

## Guard

None yet. This rule is a draft until a named guard test exists.
