# pq-ledger — threat model (honest)

A deterministic double-entry ledger. It is a **ledger**, not a bank, not a payment
network, not a key manager. It **owns no secrets**. These are the honest boundaries.

## What it guarantees (and tests)

- **Conservation.** Every posting is balanced (debits == credits); total of all
  balances is always zero. Enforced at construction and re-checkable via
  `assert_conservation()`.
- **No silent corruption.** Invalid postings raise typed errors and change no state:
  unbalanced, underflow (no negative balance unless an authorized credit line),
  unknown account, idempotency-key reuse with different content, unauthorized.
- **Determinism + replayability.** Integer minor units only (no floats); the
  hash-chained audit log is the source of truth; `replay()` / `from_audit_log()`
  reconstruct balances exactly and detect tampering.
- **Concurrency safety.** A re-entrant lock serializes all state-changing operations,
  so concurrent posts cannot interleave a check-then-commit into a double-spend.
- **Capability-gated.** Every mutation passes an `Authorizer` (the AuthGate seam).

## What it does NOT do / NOT guarantee (out of scope by design)

- **It is not AuthGate.** The `Authorizer` is a *stub seam* standing in for the real
  capability kernel. Real authorization (signed, attenuable, revocable capabilities)
  lives in AuthGate; swap the stub for the real verdict and nothing else changes.
- **No cryptography.** The audit log is hash-chained (tamper-*evident*), not signed.
  It detects modification of an existing chain; it does not by itself prove authorship
  or prevent a fully-trusted process from rewriting the whole log. Signing/PQC belongs
  in a crypto provider, not here.
- **Single-node, in-memory.** No durability, no distribution, no cross-node
  settlement/consensus, no Byzantine fault tolerance. A real deployment needs durable
  storage and (if multi-node) a settlement/consensus layer — neither is modelled here.
- **No money movement.** It records double-entry facts; it does not touch real funds,
  rails, or external systems.
- **Liveness / DoS, side channels, timing** — out of scope.

## Honest status

A correct, tested, single-node ledger core with the right invariants — the kind of
primitive a real settlement system is built *on*, not a settlement system itself.
Production use requires durability, the real AuthGate gate, and (for value) a
cryptographically-signed, possibly distributed, audit/settlement layer.
