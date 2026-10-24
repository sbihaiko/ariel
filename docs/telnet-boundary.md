# The telnet shell and the approval gate

The approval gate covers the agent port (2324) and nothing else. The telnet shell on port 2323 is the owner's escape hatch, and the gate does not cover it. This page says what protects the telnet shell and gives the manual check for that coverage. The decision is in [ADR-0006](adr/0006-the-controller-is-the-approval-source.md), decision 10: the gate covers the agent port, and any other path is gated on its own terms.

## What protects the telnet shell

Only the trusted-network rule. The shell listens on port 2323 on every interface of the console (`INADDR_ANY`, `shsrv.c`), asks for no token and no approval, and speaks plain text. Anyone who can reach the port can run any command the shell offers, including `rm`, `kill`, `mount`, `exec`, `chmod`, `mkdir`, `mv`, `touch` and `http2_get`, and can run an ELF found on the `PATH`. It can also read Ariel's token file and write to `/data`. There is no `reboot` command in the shell today.

So the owner must keep the console on a network they trust, or reach port 2323 only through an encrypted tunnel. The approval gate does not change that.

## What the gate does cover

The agent port offers only `payload push`, `payload commit`, `payload run --wait` and `payload list`. Every other command answers `unknown_command`. The only way to put new code on the console through that port is a push, which waits for an approval signed by the owner. The headless acceptance suite checks this in the scenario named "the agent port opens no system change outside the gate and the telnet shell stays out of scope" (`hostbuild/tests/acceptance.py`, run by `make -C hostbuild test`). The host build has no telnet shell, so that scenario cannot test it.

## Manual check: the telnet boundary

Run this once per release that touches the shell or the agent port, on a console with Ariel running. `$PS5_HOST` is the console's address and `$ARIEL_TOKEN` is the token shown on the console at first start.

1. Connect to the telnet shell with no token: `nc $PS5_HOST 2323`. Expect a prompt and no request for a token.
2. Run `mkdir /data/ariel-boundary-check`, then `ls /data`. Expect no approval prompt on the console, and the directory in the listing.
3. Run `rmdir /data/ariel-boundary-check`, then `exit`. Expect the directory gone and no approval prompt.
4. On the agent port, run `printf 'auth %s\nmkdir /data/ariel-boundary-check\n' "$ARIEL_TOKEN" | nc $PS5_HOST 2324`. Expect no directory. Before Stage 2 the reply is `unknown_command` and `exit 1`. From Stage 2, `mkdir` is a gated command on the agent port: the reply is `approval_required` and `exit 75`; do not sign the challenge.
5. From a computer that is not on the owner's trusted network, or with the console's network blocked, `nc $PS5_HOST 2323` must not connect. This step shows that the network, not Ariel, is the protection. Skip it if no such computer is at hand, and say so in the release notes.

A pass is steps 1 to 3 succeeding with no approval and step 4 refused. If step 2 asks for an approval, the telnet shell has been gated: update the README safety model and this page, because the boundary has moved.

## What happens to the telnet copies of commands the agent port gains

Stage 2 moves several destructive commands onto the agent port, gated. Their telnet copies stay as they are: ungated, with no token, as in upstream shsrv ([ADR-0008](adr/0008-the-telnet-shell-stays-outside-the-gate.md)). Gating them would make the escape hatch depend on the verifier, so a lost key would also lock the owner out of the console. That recovery path must be designed before any telnet command is gated: [#15](https://github.com/sbihaiko/ariel/issues/15).
