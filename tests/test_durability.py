"""Durability tests: the file-backed, hash-chained audit log.

These close the red-team finding "the audit log is in-memory, so a crash loses
the source of truth." A file-backed AuditLog durably appends each entry (one
JSON line, flushed + fsynced) so an acknowledged write survives a process
crash. On reload the hash chain is re-verified, so a corrupted line is detected.

Covered here:
  1. crash-recovery: post, drop the object, reopen from the same file ->
     balances and applied idempotency keys match exactly.
  2. integrity-on-load: a corrupted/edited line is DETECTED (TamperError) on
     load.
  3. determinism: the reloaded state equals live state bit-for-bit.

The in-memory default path is exercised by the existing suites and stays
unchanged (no `path` is passed there).
"""

import io
import os
import tempfile
import unittest

from pq_ledger import (
    AuditLog,
    EventEmitter,
    Ledger,
    Line,
    Metrics,
    Posting,
    TamperError,
    allow_all,
)


def silent_kwargs():
    """Ledger kwargs with telemetry muted, like the other test suites."""
    return dict(
        authorize=allow_all,
        emitter=EventEmitter(stream=io.StringIO(), enabled=True),
        metrics=Metrics(),
    )


class TestFileBackedAppend(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.log")

    def tearDown(self):
        try:
            for name in os.listdir(self.dir):
                os.remove(os.path.join(self.dir, name))
            os.rmdir(self.dir)
        except OSError:
            pass

    def _seed(self, led):
        led.open_account("mint", allow_overdraft=True)
        led.open_account("alice")
        led.open_account("bob")
        led.post(Posting("seed", (Line("alice", debit=1000), Line("mint", credit=1000))))
        led.post(Posting("t1", (Line("bob", debit=400), Line("alice", credit=400))))
        led.post(Posting("t2", (Line("alice", debit=50), Line("bob", credit=50))))

    def test_in_memory_default_writes_no_file(self):
        # The default path is unchanged: no file is created or touched.
        led = Ledger(**silent_kwargs())
        self.assertIsNone(led.audit.path)
        self._seed(led)
        self.assertFalse(os.path.exists(self.path))

    def test_each_append_is_one_durable_json_line(self):
        log = AuditLog(path=self.path)
        led = Ledger(audit_log=log, **silent_kwargs())
        self._seed(led)
        # 3 opens + 3 posts = 6 lines, each parseable JSON with the chain fields.
        with open(self.path, encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 6)
        import json

        for i, ln in enumerate(lines):
            rec = json.loads(ln)
            self.assertEqual(rec["seq"], i)
            self.assertIn("prev_hash", rec)
            self.assertIn("entry_hash", rec)
            self.assertIn("payload", rec)

    def test_crash_recovery_balances_and_applied_keys_match(self):
        # Open a file-backed ledger, post several entries...
        log = AuditLog(path=self.path)
        led = Ledger(audit_log=log, **silent_kwargs())
        self._seed(led)
        live_balances = led.balances()
        live_applied = dict(led._applied)

        # ...drop the object (simulate a process crash: no graceful shutdown)...
        del led
        del log

        # ...reopen from the SAME file.
        recovered = Ledger.from_audit_file(self.path, **silent_kwargs())

        # Balances reconstructed bit-for-bit.
        self.assertEqual(recovered.balances(), live_balances)
        # Idempotency memory (applied keys + canonical content) matches exactly.
        self.assertEqual(recovered._applied, live_applied)
        # Conservation still holds and the chain still verifies.
        recovered.assert_conservation()
        self.assertTrue(recovered.audit.verify())

    def test_reopened_ledger_keeps_idempotency_and_appends_durably(self):
        log = AuditLog(path=self.path)
        led = Ledger(audit_log=log, **silent_kwargs())
        self._seed(led)
        del led
        del log

        recovered = Ledger.from_audit_file(self.path, **silent_kwargs())
        before = recovered.balances()
        # Re-posting a recovered key is a deduplicated no-op (memory survived).
        r = recovered.post(Posting("t1", (Line("bob", debit=400), Line("alice", credit=400))))
        self.assertTrue(r.deduplicated)
        self.assertEqual(recovered.balances(), before)

        # A NEW posting durably appends to the same file and survives a reload.
        recovered.post(Posting("t3", (Line("bob", debit=10), Line("alice", credit=10))))
        del recovered

        again = Ledger.from_audit_file(self.path, **silent_kwargs())
        self.assertEqual(again.balance("bob"), before["bob"] + 10)
        self.assertEqual(again.balance("alice"), before["alice"] - 10)

    def test_reload_equals_live_state_exactly(self):
        # Determinism: a live ledger and a ledger reloaded from its persisted
        # log must agree on balances AND on replay output, bit-for-bit.
        log = AuditLog(path=self.path)
        led = Ledger(audit_log=log, **silent_kwargs())
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        for i in range(25):
            led.post(Posting(f"k{i}", (Line("b", debit=i + 1), Line("a", credit=i + 1))))
        live = led.balances()
        live_replay = led.replay()

        reloaded = Ledger.from_audit_file(self.path, **silent_kwargs())
        self.assertEqual(reloaded.balances(), live)
        self.assertEqual(reloaded.replay(), live_replay)
        self.assertEqual(reloaded.replay(), reloaded.balances())


class TestIntegrityOnLoad(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.log")

    def tearDown(self):
        try:
            for name in os.listdir(self.dir):
                os.remove(os.path.join(self.dir, name))
            os.rmdir(self.dir)
        except OSError:
            pass

    def _populate(self):
        log = AuditLog(path=self.path)
        led = Ledger(audit_log=log, **silent_kwargs())
        led.open_account("a", allow_overdraft=True)
        led.open_account("b")
        led.post(Posting("p1", (Line("b", debit=100), Line("a", credit=100))))
        led.post(Posting("p2", (Line("a", debit=40), Line("b", credit=40))))
        log.close()

    def test_edited_line_detected_on_load(self):
        import json

        self._populate()
        with open(self.path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()

        # Forge an amount inside one posting line; leave its stored hash as-is.
        rec = json.loads(lines[2])  # the p1 posting
        rec["payload"]["lines"][0]["debit"] = 999999
        lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")

        # The tamper is DETECTED on load: verify fails -> TamperError.
        with self.assertRaises(TamperError):
            AuditLog.from_file(self.path)
        with self.assertRaises(TamperError):
            Ledger.from_audit_file(self.path, **silent_kwargs())

    def test_deleted_line_detected_on_load(self):
        self._populate()
        with open(self.path, encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        del lines[1]  # drop one entry -> seq/prev_hash break
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        with self.assertRaises(TamperError):
            AuditLog.from_file(self.path)

    def test_malformed_line_detected_on_load(self):
        self._populate()
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write("{not valid json\n")
        with self.assertRaises(TamperError):
            AuditLog.from_file(self.path)


if __name__ == "__main__":
    unittest.main()
