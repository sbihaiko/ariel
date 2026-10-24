# Key rotation and recovery

This page says what Ariel does when the owner's keys are rotated, leaked or lost. The decisions are in [ADR-0009](adr/0009-the-key-hierarchy-has-a-primary-and-a-recovery-key.md). Where the code and this page differ, the code is right and the page needs fixing.

## Keys

- **Primary key.** Signs every everyday approval and `key rotate`.
- **Recovery key.** Signs `key rotate-recovery` and `key adopt-anchor`. It never signs everyday approvals.
- **Anchor.** The two public keys pinned into the build with `ARIEL_PUBKEY` and `ARIEL_RECOVERY_PUBKEY`.
- **Keyring.** The protected file `keyring` on the console. It holds the active primary and recovery keys, at most 16 retired keys, the generation, and a fingerprint of the anchor it was built from.
- **Generation.** Starts at 0 and rises by one on each rotation or adoption. Every approval is bound to the generation it was issued under.

## Rotation

- `key rotate <hex>` is gated and must be signed by the current primary. It retires the old primary, makes the new one active and raises the generation. The keyring is written through a journal with the steps `prepared`, `committed`, `renamed` and `audited`, and the audit kind is `key_rotate`. The reply is `key_rotated <generation>`.
- `key rotate-recovery <hex>` is the same procedure for the recovery key, signed by the current recovery key. The audit kind is `key_rotate_recovery`.
- A new key is refused when it equals the active primary or recovery key, or a retired key. On the PS5 build the host test key is refused too.
- After a rotation, approvals made under the old generation no longer verify. A grant for one answers `signature_invalid`. An approval the owner had already granted under the old generation answers `approval_stale`, and the next request is issued under the new generation.
- The keyring keeps at most 16 retired keys. A rotation when the list is full fails with `key_failed`.

## Leak

A leaked key can sign the actions it is used for until it is retired, so rotate it from a trusted console as soon as the leak is known.

- **Leaked primary.** `key rotate` needs the primary's signature, so the owner rotates before the attacker does. If the attacker has already rotated to a key of their own, revoke the lineage from the generation of the leak (below).
- **Leaked recovery key.** Rotate it with `key rotate-recovery` before the attacker does. If the attacker has already rotated it, use the same rebuild and `key adopt-anchor` path as above.

### Revocation by lineage

A primary that leaked at generation N may have signed rotations to keys the attacker holds, so every primary from N on is suspect. `key revoke --since N <new-primary>`, signed by the current recovery key, takes the console back without a rebuild:

- `<new-primary>` becomes the primary at the next generation, and the current primary is retired.
- Every grant the grant ledger (`grants`) holds from generations N to the current one is suspended: an installed build, a pin approved with an install, an autoload entry. A suspended build stays in the store but answers `suspended` (exit 90) instead of running, a suspended autoload entry leaves the autoload file in the same journal transaction, and a suspended pin asks the owner again.
- Grants from before N stay active, including those of a key retired by a planned `key rotate`. Pins the allowlist set in advance were approved by no key and stay active.
- It passes while frozen and with every approval slot in use, and does not lift the freeze. Re-approving a build with the new primary restores its grant.
- The audit kinds are `key_revoke` and `grant_suspended`. See `docs/exit-codes.md` for the replies.

## Loss of the primary

The recovery key replaces a lost primary with `key revoke --since <current generation> <new-primary>`. It also suspends the grants of the current generation; re-approve the ones still wanted with the new primary. `key rotate` stays signed only by the primary, and `key rotate-recovery` only replaces the recovery key.

## Loss of the recovery key

With the primary still held, Ariel keeps working: approvals, `key rotate` and the rest run as before. Only `key rotate-recovery` is then impossible, because nothing can sign it.

To restore a recovery key:

1. Rebuild the payload with a new anchor, which sets a new primary and recovery key.
2. Install it on the console. This needs the ELF loader and the console, which the agent does not hold.
3. Run `key adopt-anchor`, signed by the new recovery key.

Adoption keeps the consumed nonces and the audit log. It moves the generation up by one, retires the old primary and recovery keys, and suspends every earlier grant, because each one was issued under the old generation.

Adoption needs room for two more retired keys. It is refused with `key_refused` when the list is full, when a new anchor key is already active or retired, or when the keyring file is missing or corrupt.

## Loss of both keys

Without the primary and the recovery key, no approval for the current keyring can be signed. The recovery is the same as for a lost recovery key: rebuild with a new anchor, install it on the console, and run `key adopt-anchor` signed by the new recovery key.

If the keyring file is also lost or corrupt, `key adopt-anchor` cannot run, because adoption needs a readable keyring. Ariel then refuses every approval, and the keyring must be restored from a copy. Failing that, the console is redeployed from a trusted build with the keyring and the state file both removed, which creates a new keyring at generation 0 from the build's anchor. Ariel cannot tell that redeploy from a first install, so it is only done with the console in hand.

## Failing closed

- **Recorded generation above 0, and the keyring is missing, corrupt or older than the state file.** Every approval is refused with `key_refused` and no challenge is issued. Ariel never falls back to the build's anchor, so a retired recovery key cannot come back.
- **The keyring is at a higher generation than the state file records.** The state file catches up to the keyring when Ariel starts.
- **Recorded generation 0, and the keyring is missing.** A keyring is made from the build's anchor, which is a first start.
- **Recorded generation 0, and the keyring is corrupt.** The store does not open, so Ariel does not serve the agent port.
- **Anchor mismatch.** The build's anchor differs from the one the keyring was built from. Every approval is refused until `key adopt-anchor` succeeds.
- **Rotation or adoption saved the keyring but not the state file.** The reply is `audit_failed`. The next start catches the state file up to the keyring.

## Trust boundary

- The guarantees hold only while the verifier on the console is intact. A compromised console can change any key or file, so a key change does not undo a compromise. ADR-0006 and ADR-0009 state the same limit.
- The telnet shell on port 2323 has no token and no approval, and the ELF loader on port 9021 loads and runs code. Both are reachable on the trusted network, see [telnet boundary](telnet-boundary.md). The agent's host must not be given that reach, because either one can write the keyring, the state file or the build without a signature.
- A suspected malicious execution on the console needs a trusted redeploy and a review of the audit log. Rotating the keys on a console that ran hostile code proves nothing about what that code did.
- A rollback of the whole of `/data` by someone who already holds the console is outside the guarantee. ADR-0009 names it as such.
