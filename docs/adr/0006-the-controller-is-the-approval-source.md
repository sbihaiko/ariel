# ADR-0006: The controller is the approval source on PS5

## Status

Accepted.

## Context

An approval must come from a source the agent cannot reach from the network. An agent that could approve its own push, or forge an approval over TCP, would make the gate decoration.

The specification's default is the controller the owner holds. On a console, the open question is whether a process started through the ELF loader can read the pad while another app is in the foreground. The [controller spike](../controller-spike.md) answers it on a real console with a separate payload that opens the pad and reports presses.

The console run has not happened yet. Holding the PS5 platform port back until it does would stall the whole stage. The approval source sits behind the platform port, so swapping it touches one implementation file.

## Decision

1. **The PS5 implementation of the platform port takes approvals from the controller the owner holds.** X grants, O denies, and only a press after the prompt appeared counts.
2. **The source sits behind the platform port.** Nothing above the port learns how an approval arrives.
3. **The spike run validates the choice.** If it shows that the controller cannot be read while another app is in the foreground, the source swaps for a fallback the agent cannot reach from the network, and this ADR is rewritten in that change. The fallback is designed before Stage 1 ships.
4. **The approval source is never reachable over the network.** A virtual controller exists only in the host build, for tests.

## Guard

None yet. This rule is a draft until a named guard test exists.
