# pq-ledger

A minimal, **deterministic, double-entry ledger**. It is the *ledger-correctness*
core of a small ecosystem of independent repos:

| Repo               | Single responsibility           |
| ------------------ | ------------------------------- |
| **pq-ledger**      | ledger correctness (this repo)  |
| AuthGate           | authorization                   |
| boundary-guard     | architecture / boundaries       |
| crypto-inventory   | crypto trust                    |

pq-ledger does exactly one thing well: it keeps a set of accounts and balanced
postings correct, replayable, and tamper-evident. Nothing else.

> Where authorization is concerned, pq-ledger holds **no authority**: its
> capability gate is a stub for the Decision OS pipeline (FDK legitimacy →
> AuthGate authority), which the host wires in. See "The AuthGate boundary stub"
> below.

## What it is

- **Double-entry.** Every posting is a set of lines; the sum of debits equals
  the sum of credits. Value is conserved: across the whole book, balances net
  to zero.
- **Integer money.** All amounts are non-negative **integers in minor units**
  (e.g. cents or sats). There are **no floats anywhere** — float arithmetic is
  non-deterministic across platforms and cannot be replayed bit-for-bit.
- **Deterministic + replayable.** All state is reconstructable from an
  append-only log. `replay()` re-derives every balance purely from the log and
  equals live state exactly.
- **Tamper-evident.** The audit log is **hash-chained**: each entry carries the
  hash of the previous entry. Editing, deleting, or reordering a committed
  entry breaks the chain and is detected by `verify()`.
- **Capability-gated.** Every state-changing operation passes an `Intent`
  through a callable `authorize(intent) -> bool`. Denied operations raise
  `AuthorizationError` and change no state.
- **Thread-safe.** A single re-entrant lock serializes all state-changing
  operations so concurrent postings cannot interleave into an inconsistent
  state or double-spend. (See the concurrency tests.)
- **Observable.** Structured JSON-line events for every posting/decision,
  simple in-memory metrics (postings / denials / rejected / duplicates), and a
  query API over the audit log.
- **Stdlib only.** Zero third-party dependencies. Requires Python >= 3.10.

## What it is NOT

- It is **not a bank.** No settlement, no clearing, no real money moves.
- It is **not key management, not crypto, not a payment processor.**
- It **owns no secrets.** No keys, no certs, no wallets, no PII storage by
  design. If you put secrets in a memo, that is on you, not the ledger.
- The capability gate here is a **STUB**. It stands in for the real AuthGate
  kernel and performs **no crypto**. In production the host wires the real
  AuthGate enforce-callable in place of `allow_all` / `deny_all`.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the honest list of what this does
**not** guarantee.

## The AuthGate boundary stub

```python
from pq_ledger import Intent

def authorize(intent: Intent) -> bool:
    # Stand-in for the real AuthGate kernel. NO crypto here.
    # Return True to allow, False to deny. Real policy lives in AuthGate.
    return intent.action != "post" or intent.debit_total <= 10_000
```

The ledger calls this on **every** state-changing op (`open_account`, `post`).
A falsy return raises `AuthorizationError` and leaves state untouched.

## Quick start

```python
from pq_ledger import Ledger, Posting, Line, allow_all

led = Ledger(authorize=allow_all)
led.open_account("mint", allow_overdraft=True)   # the only credit line
led.open_account("alice")

# Move 1000 minor units from mint to alice. Debit the receiver, credit source.
led.post(Posting("seed-1", (Line("alice", debit=1000), Line("mint", credit=1000))))

led.balance("alice")          # 1000
led.assert_conservation()     # True (whole book nets to zero)
led.replay() == led.balances()  # True  (log is the source of truth)
led.audit.verify()            # True  (hash chain intact)
```

### Idempotency

`post` is safe to retry. Re-posting the **same key** is a no-op that returns the
original result. Reusing a key with **different content** raises
`DuplicateIdempotencyKeyError`.

### Negative balances

An account may not go below zero **unless** it was opened with
`allow_overdraft=True` — an explicit, authorized credit line. Any other
underflow raises `InsufficientFundsError` and changes no state.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```

The suite (stdlib `unittest`, zero deps) covers the conservation invariant,
no-double-spend, idempotency dedupe, exact replay, capability denial,
concurrency, and an adversarial red-team file. CI runs it on Python
3.10–3.13.

## License

MIT, (c) 2026 Ali Pourrahim. See [LICENSE](LICENSE).
