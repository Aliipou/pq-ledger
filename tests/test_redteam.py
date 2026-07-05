"""Red-team tests: adversarial attempts to break the ledger.

Each test pins a specific attack and asserts the ledger defends against it:
  1. double-spend attempt
  2. replay of a committed posting (idempotency)
  3. balance underflow and overflow
  4. conservation-violating posting rejected
  5. audit-log tampering DETECTED by the hash chain

These are intentionally hostile. If any of these starts passing the attack,
the ledger's core guarantees are broken.
"""

import io
import unittest

from pq_ledger import (
    EventEmitter,
    InsufficientFundsError,
    Ledger,
    Line,
    Metrics,
    Posting,
    TamperError,
    UnbalancedPostingError,
    allow_all,
)
from pq_ledger.audit import AuditEntry
from pq_ledger.ledger import MAX_AMOUNT


def fresh_ledger():
    return Ledger(
        authorize=allow_all,
        emitter=EventEmitter(stream=io.StringIO(), enabled=True),
        metrics=Metrics(),
    )


class RedTeamDoubleSpend(unittest.TestCase):
    def test_double_spend_is_blocked(self):
        led = fresh_ledger()
        led.open_account("attacker")
        led.open_account("victim")
        led.open_account("mint", allow_overdraft=True)
        led.post(Posting("fund", (Line("attacker", debit=100), Line("mint", credit=100))))
        # Spend the 100 once.
        led.post(Posting("spend1", (Line("victim", debit=100), Line("attacker", credit=100))))
        self.assertEqual(led.balance("attacker"), 0)
        # Attempt to spend the same 100 again with a NEW key (true double-spend).
        with self.assertRaises(InsufficientFundsError):
            led.post(Posting("spend2", (Line("victim", debit=100), Line("attacker", credit=100))))
        self.assertEqual(led.balance("attacker"), 0)
        self.assertEqual(led.balance("victim"), 100)


class RedTeamReplay(unittest.TestCase):
    def test_replaying_a_posting_does_not_double_apply(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        # a is overdraft-allowed source (credited), b receives (debited).
        p = Posting("once", (Line("b", debit=50), Line("a", credit=50)))
        led.post(p)
        snapshot = led.balances()
        # Adversary re-submits the identical signed posting many times.
        for _ in range(100):
            led.post(p)
        self.assertEqual(led.balances(), snapshot)
        self.assertEqual(led.metrics.postings, 1)
        self.assertEqual(led.metrics.duplicates, 100)


class RedTeamUnderflowOverflow(unittest.TestCase):
    def test_underflow_blocked(self):
        led = fresh_ledger()
        led.open_account("a")  # no overdraft
        led.open_account("b", allow_overdraft=True)
        with self.assertRaises(InsufficientFundsError):
            led.post(Posting("u", (Line("b", debit=1), Line("a", credit=1))))
        self.assertEqual(led.balance("a"), 0)

    def test_overflow_blocked(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b", allow_overdraft=True)
        # A single line above MAX_AMOUNT is rejected at Line construction.
        with self.assertRaises(UnbalancedPostingError):
            Line("a", debit=MAX_AMOUNT + 1)
        # Accumulating past MAX_AMOUNT across postings is rejected at post time.
        # a is debited (grows positive), b is credited (grows negative).
        big = MAX_AMOUNT
        led.post(Posting("p1", (Line("a", debit=big), Line("b", credit=big))))
        with self.assertRaises(UnbalancedPostingError):
            led.post(Posting("p2", (Line("a", debit=big), Line("b", credit=big))))
        # State unchanged by the rejected overflow.
        self.assertEqual(led.balance("a"), big)


class RedTeamConservation(unittest.TestCase):
    def test_unbalanced_posting_cannot_be_constructed(self):
        # Conservation is enforced at the type boundary: you cannot even build
        # an unbalanced Posting, so it can never reach the ledger.
        with self.assertRaises(UnbalancedPostingError):
            Posting("bad", (Line("a", debit=100), Line("b", credit=99)))

    def test_value_is_conserved_across_book(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b", allow_overdraft=True)
        led.open_account("c")
        # a and b are credited (sources); c is debited (receives).
        led.post(Posting("x", (Line("c", debit=300),
                               Line("a", credit=100), Line("b", credit=200))))
        self.assertEqual(sum(led.balances().values()), 0)
        led.assert_conservation()


class RedTeamAuditTampering(unittest.TestCase):
    def _build(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b", allow_overdraft=True)
        led.post(Posting("p1", (Line("a", debit=100), Line("b", credit=100))))
        led.post(Posting("p2", (Line("b", debit=40), Line("a", credit=40))))
        return led

    def test_intact_log_verifies(self):
        led = self._build()
        self.assertTrue(led.audit.verify())

    def test_mutated_amount_detected(self):
        led = self._build()
        # Reach into the private entry list and forge an amount on entry 2.
        entries = led.audit._entries
        target = entries[2]  # the p1 posting
        forged_payload = dict(target.payload)
        forged_lines = [dict(ln) for ln in forged_payload["lines"]]
        forged_lines[0] = {**forged_lines[0], "debit": 999999}
        forged_payload["lines"] = forged_lines
        entries[2] = AuditEntry(
            seq=target.seq,
            prev_hash=target.prev_hash,
            entry_hash=target.entry_hash,  # attacker leaves old hash -> mismatch
            payload=forged_payload,
        )
        with self.assertRaises(TamperError):
            led.audit.verify()

    def test_recomputed_hash_still_breaks_chain(self):
        # Sophisticated attacker recomputes the tampered entry's own hash, but
        # cannot fix the FOLLOWING entry's prev_hash without rewriting it too.
        from pq_ledger.audit import compute_hash

        led = self._build()
        entries = led.audit._entries
        target = entries[2]
        forged_payload = dict(target.payload)
        forged_lines = [dict(ln) for ln in forged_payload["lines"]]
        forged_lines[0] = {**forged_lines[0], "debit": 999999}
        forged_payload["lines"] = forged_lines
        new_hash = compute_hash(target.seq, target.prev_hash, forged_payload)
        entries[2] = AuditEntry(
            seq=target.seq,
            prev_hash=target.prev_hash,
            entry_hash=new_hash,  # self-consistent...
            payload=forged_payload,
        )
        # ...but entry 3's prev_hash still points at the OLD hash -> chain break.
        with self.assertRaises(TamperError):
            led.audit.verify()

    def test_deleting_an_entry_detected(self):
        led = self._build()
        del led.audit._entries[1]
        # seq numbers now non-contiguous / prev_hash mismatch.
        with self.assertRaises(TamperError):
            led.audit.verify()

    def test_reordering_entries_detected(self):
        led = self._build()
        e = led.audit._entries
        e[2], e[3] = e[3], e[2]
        with self.assertRaises(TamperError):
            led.audit.verify()

    def test_replay_refuses_tampered_log(self):
        led = self._build()
        led.audit._entries[2].payload["lines"][0]["debit"] = 1
        with self.assertRaises(TamperError):
            led.replay()


if __name__ == "__main__":
    unittest.main()
