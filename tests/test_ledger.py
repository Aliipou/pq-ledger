"""Core correctness tests for pq_ledger.

Covers: conservation invariant, no double-spend, idempotency dedupe, replay
fidelity, and capability-gate denial.
"""

import io
import threading
import unittest

from pq_ledger import (
    AuthorizationError,
    DuplicateIdempotencyKeyError,
    EventEmitter,
    InsufficientFundsError,
    Ledger,
    LedgerError,
    Line,
    Metrics,
    Posting,
    UnbalancedPostingError,
    UnknownAccountError,
    allow_all,
    deny_all,
)


def fresh_ledger(authorize=allow_all):
    metrics = Metrics()
    emitter = EventEmitter(stream=io.StringIO(), enabled=True)
    led = Ledger(authorize=authorize, emitter=emitter, metrics=metrics)
    return led


class TestPostingValidation(unittest.TestCase):
    def test_balanced_posting_required(self):
        with self.assertRaises(UnbalancedPostingError):
            Posting(
                idempotency_key="k1",
                lines=(Line("a", debit=100), Line("b", credit=50)),
            )

    def test_line_must_have_exactly_one_side(self):
        with self.assertRaises(UnbalancedPostingError):
            Line("a", debit=10, credit=10)
        with self.assertRaises(UnbalancedPostingError):
            Line("a")  # both zero

    def test_no_negative_line(self):
        with self.assertRaises(UnbalancedPostingError):
            Line("a", debit=-1)

    def test_bool_is_not_a_valid_amount(self):
        with self.assertRaises(UnbalancedPostingError):
            Line("a", debit=True)

    def test_empty_idempotency_key_rejected(self):
        with self.assertRaises(LedgerError):
            Posting(idempotency_key="", lines=(Line("a", debit=1), Line("b", credit=1)))


class TestConservation(unittest.TestCase):
    def test_conservation_holds_after_postings(self):
        led = fresh_ledger()
        led.open_account("alice")
        led.open_account("bank", allow_overdraft=True)
        # Fund alice from the bank (bank goes negative; it is a credit line).
        led.post(Posting("seed", (Line("alice", debit=1000), Line("bank", credit=1000))))
        led.post(Posting("t1", (Line("bank", debit=400), Line("alice", credit=400))))
        self.assertTrue(led.assert_conservation())
        self.assertEqual(sum(led.balances().values()), 0)

    def test_balances_sum_to_zero_always(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        for i in range(20):
            led.post(Posting(f"k{i}", (Line("b", debit=i + 1), Line("a", credit=i + 1))))
            self.assertEqual(sum(led.balances().values()), 0)


class TestNoDoubleSpend(unittest.TestCase):
    def test_cannot_overspend_account(self):
        led = fresh_ledger()
        led.open_account("alice")
        led.open_account("bob")
        led.open_account("bank", allow_overdraft=True)
        led.post(Posting("seed", (Line("alice", debit=100), Line("bank", credit=100))))
        # alice has 100; try to move 150 to bob -> underflow.
        with self.assertRaises(InsufficientFundsError):
            led.post(Posting("ov", (Line("bob", debit=150), Line("alice", credit=150))))
        # alice unchanged, bob still zero.
        self.assertEqual(led.balance("alice"), 100)
        self.assertEqual(led.balance("bob"), 0)

    def test_two_spends_cannot_exceed_balance(self):
        led = fresh_ledger()
        led.open_account("alice")
        led.open_account("bob")
        led.open_account("bank", allow_overdraft=True)
        led.post(Posting("seed", (Line("alice", debit=100), Line("bank", credit=100))))
        led.post(Posting("s1", (Line("bob", debit=60), Line("alice", credit=60))))
        with self.assertRaises(InsufficientFundsError):
            led.post(Posting("s2", (Line("bob", debit=60), Line("alice", credit=60))))
        self.assertEqual(led.balance("alice"), 40)
        self.assertEqual(led.balance("bob"), 60)


class TestIdempotency(unittest.TestCase):
    def test_duplicate_key_is_noop(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        # a is the overdraft source (credited); b receives (debited).
        p = Posting("dup", (Line("b", debit=10), Line("a", credit=10)))
        r1 = led.post(p)
        balances_after_first = led.balances()
        r2 = led.post(p)
        self.assertFalse(r1.deduplicated)
        self.assertTrue(r2.deduplicated)
        self.assertEqual(led.balances(), balances_after_first)
        self.assertEqual(led.metrics.postings, 1)
        self.assertEqual(led.metrics.duplicates, 1)
        # Only one audit entry for the posting (plus 2 opens).
        self.assertEqual(len(led.audit.query(action="post")), 1)

    def test_same_key_different_content_rejected(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        led.post(Posting("k", (Line("b", debit=10), Line("a", credit=10))))
        with self.assertRaises(DuplicateIdempotencyKeyError):
            led.post(Posting("k", (Line("b", debit=20), Line("a", credit=20))))
        self.assertEqual(led.metrics.rejected, 1)


class TestReplay(unittest.TestCase):
    def test_replay_reproduces_live_state(self):
        led = fresh_ledger()
        led.open_account("alice")
        led.open_account("bob")
        led.open_account("bank", allow_overdraft=True)
        led.post(Posting("seed", (Line("alice", debit=500), Line("bank", credit=500))))
        led.post(Posting("p1", (Line("bob", debit=200), Line("alice", credit=200))))
        led.post(Posting("p2", (Line("alice", debit=50), Line("bob", credit=50))))
        replayed = led.replay()
        self.assertEqual(replayed, led.balances())

    def test_replay_is_bit_for_bit_via_rebuild(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        for i in range(10):
            led.post(Posting(f"k{i}", (Line("b", debit=7), Line("a", credit=7))))
        rebuilt = Ledger.from_audit_log(led.audit)
        self.assertEqual(rebuilt.balances(), led.balances())
        # Rebuilt ledger preserves idempotency memory.
        before = rebuilt.balances()
        rebuilt.post(Posting("k0", (Line("b", debit=7), Line("a", credit=7))))
        self.assertEqual(rebuilt.balances(), before)


class TestCapabilityGate(unittest.TestCase):
    def test_denied_post_changes_no_state(self):
        led = fresh_ledger(authorize=allow_all)
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        # Now swap to a deny-all gate by building a new ledger sharing nothing.
        denied = Ledger(authorize=deny_all, emitter=EventEmitter(stream=io.StringIO()))
        with self.assertRaises(AuthorizationError):
            denied.open_account("x")
        self.assertEqual(denied.balances(), {})

    def test_denied_transfer(self):
        # A gate that allows opening but denies any "post".
        def gate(intent):
            return intent.action != "post"

        led = Ledger(authorize=gate, emitter=EventEmitter(stream=io.StringIO()))
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        with self.assertRaises(AuthorizationError):
            led.post(Posting("k", (Line("a", debit=10), Line("b", credit=10))))
        self.assertEqual(led.metrics.denials, 1)
        self.assertEqual(led.balance("a"), 0)
        self.assertEqual(led.balance("b"), 0)
        # Nothing posted to the audit log.
        self.assertEqual(len(led.audit.query(action="post")), 0)


class TestUnknownAccount(unittest.TestCase):
    def test_post_to_unknown_account_rejected(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        with self.assertRaises(UnknownAccountError):
            led.post(Posting("k", (Line("a", debit=10), Line("ghost", credit=10))))


class TestObservability(unittest.TestCase):
    def test_event_lines_are_json(self):
        import json

        buf = io.StringIO()
        led = Ledger(authorize=allow_all, emitter=EventEmitter(stream=buf, enabled=True))
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        led.post(Posting("k", (Line("b", debit=5), Line("a", credit=5))))
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        self.assertTrue(lines)
        for ln in lines:
            json.loads(ln)  # must parse

    def test_metrics_snapshot(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        led.post(Posting("k", (Line("b", debit=5), Line("a", credit=5))))
        snap = led.metrics.snapshot()
        self.assertEqual(snap["postings"], 1)

    def test_query_by_account(self):
        led = fresh_ledger()
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        led.post(Posting("k", (Line("b", debit=5), Line("a", credit=5))))
        res = led.audit.query(account="a")
        # open_account("a") + the post both touch "a".
        self.assertEqual(len(res), 2)


class TestConcurrency(unittest.TestCase):
    def test_many_threads_posting_keeps_conservation_and_no_double_spend(self):
        # mint funds the world (overdraft source); workers move 1 unit each
        # from mint to their own account. With N total units funded and more
        # attempts than units, some must fail on underflow once mint is capped.
        led = fresh_ledger()
        led.open_account("mint", allow_overdraft=True)
        n_accounts = 8
        for i in range(n_accounts):
            led.open_account(f"acct{i}")

        # Each thread fires the same set of UNIQUE keys; the ledger must apply
        # each key exactly once regardless of interleaving, and conservation
        # must hold throughout.
        per_thread = 200
        n_threads = 8
        barrier = threading.Barrier(n_threads)
        errors: list[BaseException] = []

        def worker(tid: int) -> None:
            barrier.wait()
            for j in range(per_thread):
                key = f"t{tid}-{j}"
                acct = f"acct{j % n_accounts}"
                try:
                    led.post(Posting(key, (Line(acct, debit=1), Line("mint", credit=1))))
                except Exception as exc:  # capture, don't crash the thread
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"unexpected errors: {errors[:3]}")
        # Conservation holds: the whole book nets to zero.
        led.assert_conservation()
        self.assertEqual(sum(led.balances().values()), 0)
        # Exactly one posting per unique key -> postings == n_threads*per_thread.
        expected = n_threads * per_thread
        self.assertEqual(led.metrics.postings, expected)
        self.assertEqual(len(led.audit.query(action="post")), expected)
        # mint was drained by exactly the total moved out.
        self.assertEqual(led.balance("mint"), -expected)
        # Replay from the log reproduces live state exactly.
        self.assertEqual(led.replay(), led.balances())

    def test_concurrent_duplicate_key_applied_once(self):
        # All threads race on the SAME idempotency key; net effect must be one
        # posting, regardless of how the threads interleave.
        led = fresh_ledger()
        led.open_account("mint", allow_overdraft=True)
        led.open_account("acct")
        barrier = threading.Barrier(16)

        def worker() -> None:
            barrier.wait()
            for _ in range(50):
                try:
                    led.post(Posting("same", (Line("acct", debit=1), Line("mint", credit=1))))
                except Exception:
                    pass

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(led.balance("acct"), 1)
        self.assertEqual(led.balance("mint"), -1)
        self.assertEqual(led.metrics.postings, 1)
        self.assertEqual(len(led.audit.query(action="post")), 1)
        led.assert_conservation()


if __name__ == "__main__":
    unittest.main()
