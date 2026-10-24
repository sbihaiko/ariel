# ADR-0009: The key hierarchy has a primary and a recovery key

## Context

ADR-0006 makes the owner's signature the approval source on PS5. It names the key as the one thing a compromised payload cannot forge, and it leaves losing that key as a recovery problem not yet designed.

A single key cannot serve both needs. The owner signs everyday approvals, so the key is used often and must be kept where the owner works. A key used that often is also more exposed, and it has to be replaceable without rebuilding the console. A second key is needed for the case where the everyday key is lost or must be retired, and it must not be on the agent's machine or used day to day.

## Decision

1. **Primary key.** An Ed25519 key that signs every everyday approval. Exactly one primary is active at a time.
2. **Recovery key.** A second Ed25519 key kept offline. It is never used for everyday approvals and never stored on the agent's machine. This ADR defines it; the procedure that uses it is defined later.
3. **Anchor.** The two public keys the build pins, as generation 0. The build refuses to start if the anchor it pins does not match the keyring it finds, except where the keyring is first created.
4. **Keyring.** A protected object of Ariel. It holds the active primary, the recovery key, the revoked keys, a generation counter, and the fingerprint of the anchor it was built from. Its name is `keyring`, and it sits with the other protected objects.
5. **Generation.** A counter that starts at 0 with the anchor and rises by one on each rotation. The canonical approval message carries the generation. A signature made for one generation does not verify in another.
6. **Rotation.** `key rotate <new primary>` is a gated action, signed by the current primary. It raises the generation, retires the old primary and activates the new one in one journal transaction, and writes an audit record.
7. **Distinct roles.** The primary and the recovery key must differ. A key is refused in any role it cannot hold: the zero key, a key equal to the other role's key, and, on PS5, the host test key.
8. **Retired keys.** A challenge or an unused approval made under a retired key stops verifying once the rotation completes. Consumed nonces stay consumed across restarts.
9. **Recovery rotation.** `key rotate-recovery <new recovery key>` is a gated action signed by the current recovery key only; the primary is never accepted as its signer. A target is refused when it equals the active primary, the current recovery key or a retired key. The rotation raises the generation, retires the old recovery key and activates the new one in one journal transaction, and writes an audit record.
10. **Crash steps.** A rotation of either role writes the keyring through a journal with four steps: `prepared`, `committed`, `renamed` and `audited`. A crash at `prepared` leaves the old keyring; the next start removes the new text and audits a rollback. A crash at `committed`, `renamed` or `audited` leaves the new keyring; the next start completes the rename if it is still pending and audits a rollforward. Exactly one keyring is active afterwards.
11. The verifier stays where ADR-0006 puts it. This ADR does not change ADR-0006.

## Trust boundary

- The guarantees in this ADR hold only while the verifier is intact. ADR-0006 already states that a compromised payload defeats the gate, and this ADR does not change that.
- A rollback of the whole of `/data` by someone who already holds the console is outside the guarantee. Such a person can restore an older keyring, an older nonce table and an older journal together, and the console cannot detect it.
- The recovery key protects the console against the loss of the primary. It does not protect the console against a compromised verifier.

## Consequences

- Losing the primary does not lose the console, because the recovery key can replace it (the replacement procedure is defined later).
- Rotating the primary does not need a new build. Every approval made under the old generation stops verifying at once.
- The owner has to keep two keys apart, one in daily use and one offline.
- Every key the console imports goes through the same pinning checks as the build key.

## Guard

None yet. This rule is a draft until a named guard test exists.
