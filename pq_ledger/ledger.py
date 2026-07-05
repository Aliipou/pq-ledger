"""The deterministic double-entry ledger.

Design rules (enforced, not aspirational):

* Amounts are non-negative **integers** (minor units, e.g. cents/sats). No
  floats anywhere: float arithmetic is non-deterministic across platforms and
  cannot be replayed bit-for-bit.
* Every posting is **balanced**: ``sum(debits) == sum(credits)``. Conservation
  of value is the central invariant.
* Balances are computed as ``debits - credits`` per account. An account may not
  go negative unless it was opened as a credit-line (overdraft-allowed) account.
* **Idempotency keys** make ``post`` safe to retry: replaying the same key
  returns the original result and changes no state; reusing a key with
  different content is an error.
* Every state-changing operation is **capability-gated** through an AuthGate
  stub and recorded in an append-only, hash-chained audit log, so the full
  state is reconstructable via :meth:`Ledger.replay`.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .errors import (
    AuthorizationError,
    DuplicateIdempotencyKeyError,
    InsufficientFundsError,
    LedgerError,
    UnbalancedPostingError,
    UnknownAccountError,
)
from .gate import Authorizer, Intent, allow_all
from .observability import EventEmitter, Metrics

# Guard rail against silent integer overflow style bugs. Python ints are
# arbitrary precision, but a ledger should refuse absurd amounts rather than
# accept a fat-fingered/overflowing value. 2**63-1 mirrors a signed-64 ceiling.
MAX_AMOUNT = (1 << 63) - 1


@dataclass(frozen=True)
class Line:
    """One leg of a posting.

    Exactly one of ``debit``/``credit`` is non-zero and positive.
    """

    account: str
    debit: int = 0
    credit: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.debit, int) or not isinstance(self.credit, int):
            raise UnbalancedPostingError("line amounts must be integers (minor units)")
        if isinstance(self.debit, bool) or isinstance(self.credit, bool):
            raise UnbalancedPostingError("line amounts must be integers, not bool")
        if self.debit < 0 or self.credit < 0:
            raise UnbalancedPostingError("line amounts must be non-negative")
        if self.debit > MAX_AMOUNT or self.credit > MAX_AMOUNT:
            raise UnbalancedPostingError("line amount exceeds MAX_AMOUNT")
        if (self.debit == 0) == (self.credit == 0):
            raise UnbalancedPostingError(
                "each line must have exactly one of debit/credit non-zero"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"account": self.account, "debit": self.debit, "credit": self.credit}


@dataclass(frozen=True)
class Posting:
    """A balanced transaction: a set of lines whose debits equal its credits."""

    idempotency_key: str
    lines: tuple[Line, ...]
    memo: str = ""

    def __post_init__(self) -> None:
        if not self.idempotency_key:
            raise LedgerError("posting requires a non-empty idempotency_key")
        if not self.lines:
            raise UnbalancedPostingError("posting must have at least one line")
        if self.debit_total != self.credit_total:
            raise UnbalancedPostingError(
                f"unbalanced posting: debits={self.debit_total} credits={self.credit_total}"
            )

    @property
    def debit_total(self) -> int:
        return sum(line.debit for line in self.lines)

    @property
    def credit_total(self) -> int:
        return sum(line.credit for line in self.lines)

    @property
    def accounts(self) -> tuple[str, ...]:
        # Deterministic order: sorted, de-duplicated.
        return tuple(sorted({line.account for line in self.lines}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "memo": self.memo,
            "lines": [line.to_dict() for line in self.lines],
        }


@dataclass
class Account:
    """Account metadata. Balances live in the ledger, not here."""

    account_id: str
    allow_overdraft: bool = False


@dataclass(frozen=True)
class PostResult:
    """The outcome of a successful (or deduplicated) post."""

    idempotency_key: str
    seq: int
    deduplicated: bool
    balances: Mapping[str, int]


class Ledger:
    """A deterministic, replayable double-entry ledger."""

    def __init__(
        self,
        authorize: Authorizer | None = None,
        emitter: EventEmitter | None = None,
        metrics: Metrics | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._authorize: Authorizer = authorize if authorize is not None else allow_all
        self._emitter = emitter if emitter is not None else EventEmitter(enabled=False)
        self.metrics = metrics if metrics is not None else Metrics()
        self.audit = audit_log if audit_log is not None else AuditLog()

        self._accounts: dict[str, Account] = {}
        self._balances: dict[str, int] = {}
        # idempotency_key -> canonical posting dict (to detect content drift)
        self._applied: dict[str, dict[str, Any]] = {}

        # A single re-entrant lock serializes ALL state-changing operations so
        # concurrent threads cannot interleave a check-then-commit into an
        # inconsistent state. Reentrant so internal helpers can re-acquire.
        self._lock = threading.RLock()

    # -- read API -------------------------------------------------------------

    def balance(self, account_id: str) -> int:
        with self._lock:
            if account_id not in self._accounts:
                raise UnknownAccountError(account_id)
            return self._balances[account_id]

    def balances(self) -> dict[str, int]:
        """A copy of all account balances."""
        with self._lock:
            return dict(self._balances)

    def accounts(self) -> dict[str, Account]:
        with self._lock:
            return dict(self._accounts)

    # -- state-changing API (all capability-gated + audited) ------------------

    def open_account(self, account_id: str, *, allow_overdraft: bool = False) -> Account:
        """Open a new account. Gated and audited. Thread-safe."""
        with self._lock:
            return self._open_account_locked(account_id, allow_overdraft=allow_overdraft)

    def _open_account_locked(self, account_id: str, *, allow_overdraft: bool) -> Account:
        if account_id in self._accounts:
            raise LedgerError(f"account already exists: {account_id}")

        intent = Intent(
            action="open_account",
            accounts=(account_id,),
            metadata={"allow_overdraft": allow_overdraft},
        )
        if not self._authorize(intent):
            self.metrics.denials += 1
            self._emitter.emit("authorization_denied", action="open_account", account=account_id)
            raise AuthorizationError(f"open_account denied for {account_id}")

        account = Account(account_id=account_id, allow_overdraft=allow_overdraft)
        self._accounts[account_id] = account
        self._balances[account_id] = 0
        entry = self.audit.append(
            {
                "action": "open_account",
                "account_id": account_id,
                "allow_overdraft": allow_overdraft,
                "accounts": [account_id],
            }
        )
        self._emitter.emit(
            "account_opened",
            account=account_id,
            allow_overdraft=allow_overdraft,
            seq=entry.seq,
            audit_hash=entry.entry_hash,
        )
        return account

    def post(self, posting: Posting) -> PostResult:
        """Apply a balanced posting. Gated, idempotent, audited, thread-safe.

        The whole check-then-commit sequence runs under the ledger lock, so
        two threads posting concurrently cannot both pass the no-underflow
        check against the same stale balance and double-spend.
        """
        with self._lock:
            return self._post_locked(posting)

    def _post_locked(self, posting: Posting) -> PostResult:
        # 1. Idempotency: a previously-applied key is a no-op replay.
        prior = self._applied.get(posting.idempotency_key)
        if prior is not None:
            if prior != posting.to_dict():
                self.metrics.rejected += 1
                self._emitter.emit(
                    "idempotency_conflict",
                    idempotency_key=posting.idempotency_key,
                )
                raise DuplicateIdempotencyKeyError(
                    f"idempotency key reused with different content: {posting.idempotency_key}"
                )
            self.metrics.duplicates += 1
            self._emitter.emit(
                "posting_deduplicated", idempotency_key=posting.idempotency_key
            )
            return PostResult(
                idempotency_key=posting.idempotency_key,
                seq=self._seq_for_key(posting.idempotency_key),
                deduplicated=True,
                balances={a: self._balances[a] for a in posting.accounts},
            )

        # 2. Capability gate.
        intent = Intent(
            action="post",
            idempotency_key=posting.idempotency_key,
            debit_total=posting.debit_total,
            credit_total=posting.credit_total,
            accounts=posting.accounts,
            metadata={"memo": posting.memo},
        )
        if not self._authorize(intent):
            self.metrics.denials += 1
            self._emitter.emit(
                "authorization_denied",
                action="post",
                idempotency_key=posting.idempotency_key,
                accounts=list(posting.accounts),
            )
            raise AuthorizationError(f"post denied: {posting.idempotency_key}")

        # 3. Validate accounts exist and the posting is well-formed.
        #    (Posting.__post_init__ already guaranteed it is balanced.)
        for line in posting.lines:
            if line.account not in self._accounts:
                self.metrics.rejected += 1
                self._emitter.emit(
                    "posting_rejected",
                    reason="unknown_account",
                    account=line.account,
                    idempotency_key=posting.idempotency_key,
                )
                raise UnknownAccountError(line.account)

        # 4. Compute prospective balances and check the no-underflow invariant.
        prospective = dict(self._balances)
        for line in posting.lines:
            prospective[line.account] = prospective[line.account] + line.debit - line.credit
        for account_id, new_balance in prospective.items():
            if new_balance < 0 and not self._accounts[account_id].allow_overdraft:
                self.metrics.rejected += 1
                self._emitter.emit(
                    "posting_rejected",
                    reason="insufficient_funds",
                    account=account_id,
                    idempotency_key=posting.idempotency_key,
                )
                raise InsufficientFundsError(
                    f"posting would underflow account {account_id}: {new_balance}"
                )
            if abs(new_balance) > MAX_AMOUNT:
                self.metrics.rejected += 1
                self._emitter.emit(
                    "posting_rejected",
                    reason="overflow",
                    account=account_id,
                    idempotency_key=posting.idempotency_key,
                )
                raise UnbalancedPostingError(
                    f"posting would overflow account {account_id}: {new_balance}"
                )

        # 5. Commit: update balances, record idempotency, append to audit log.
        self._balances = prospective
        self._applied[posting.idempotency_key] = posting.to_dict()
        entry = self.audit.append({"action": "post", **posting.to_dict(),
                                   "accounts": list(posting.accounts)})
        self.metrics.postings += 1
        self._emitter.emit(
            "posting_committed",
            idempotency_key=posting.idempotency_key,
            seq=entry.seq,
            audit_hash=entry.entry_hash,
            debit_total=posting.debit_total,
            credit_total=posting.credit_total,
            balances={a: self._balances[a] for a in posting.accounts},
        )
        return PostResult(
            idempotency_key=posting.idempotency_key,
            seq=entry.seq,
            deduplicated=False,
            balances={a: self._balances[a] for a in posting.accounts},
        )

    # -- invariants -----------------------------------------------------------

    def assert_conservation(self) -> bool:
        """The sum of all balances must equal zero (value is conserved).

        In double-entry, every debit has a matching credit, so balances net to
        zero across the whole book.
        """
        with self._lock:
            total = sum(self._balances.values())
        if total != 0:
            raise LedgerError(f"conservation violated: total balance = {total}")
        return True

    # -- replay ---------------------------------------------------------------

    def replay(self) -> dict[str, int]:
        """Re-derive ALL balances purely from the audit log.

        This reads only the log, applies the same rules with an
        always-allow gate (the log records already-authorized facts), and
        returns the reconstructed balances. The caller can compare these to
        :meth:`balances` for a bit-for-bit equality check.
        """
        # Verify integrity first: replaying a tampered log is meaningless.
        self.audit.verify()
        return self._replay_entries(self.audit.entries())

    @staticmethod
    def _replay_entries(entries: Iterable[Any]) -> dict[str, int]:
        balances: dict[str, int] = {}
        accounts: dict[str, bool] = {}  # account_id -> allow_overdraft
        for entry in entries:
            p = entry.payload
            action = p.get("action")
            if action == "open_account":
                acct = p["account_id"]
                accounts[acct] = bool(p.get("allow_overdraft", False))
                balances.setdefault(acct, 0)
            elif action == "post":
                for line in p["lines"]:
                    acct = line["account"]
                    balances[acct] = balances.get(acct, 0) + line["debit"] - line["credit"]
            else:  # pragma: no cover - defensive
                raise LedgerError(f"unknown audit action during replay: {action}")
        return balances

    @classmethod
    def from_audit_log(cls, audit_log: AuditLog, **kwargs: Any) -> Ledger:
        """Rebuild a fully-populated Ledger from an existing audit log.

        Useful for cold-start recovery: hydrate live state from the log alone.
        Extra keyword arguments (``authorize``, ``emitter``, ``metrics``) are
        forwarded to the constructor so the rebuilt ledger can be re-wired.
        """
        audit_log.verify()
        ledger = cls(audit_log=audit_log, **kwargs)
        for entry in audit_log.entries():
            p = entry.payload
            action = p.get("action")
            if action == "open_account":
                acct = p["account_id"]
                ledger._accounts[acct] = Account(
                    account_id=acct, allow_overdraft=bool(p.get("allow_overdraft", False))
                )
                ledger._balances.setdefault(acct, 0)
            elif action == "post":
                for line in p["lines"]:
                    a = line["account"]
                    ledger._balances[a] = ledger._balances.get(a, 0) + line["debit"] - line["credit"]
                ledger._applied[p["idempotency_key"]] = {
                    "idempotency_key": p["idempotency_key"],
                    "memo": p.get("memo", ""),
                    "lines": [
                        {"account": ln["account"], "debit": ln["debit"], "credit": ln["credit"]}
                        for ln in p["lines"]
                    ],
                }
        return ledger

    @classmethod
    def from_audit_file(cls, path: str, **kwargs: Any) -> Ledger:
        """Rebuild a fully-populated Ledger from a persisted audit file.

        Crash-recovery cold start: load the durable, file-backed audit log from
        ``path`` (verifying its hash chain on load), reconstruct balances and
        idempotency memory bit-for-bit, and return a Ledger that continues to
        durably append to the SAME file. This mirrors :meth:`from_audit_log`;
        the reload equals the pre-crash live state exactly.
        """
        audit_log = AuditLog.from_file(path)
        return cls.from_audit_log(audit_log, **kwargs)

    # -- internals ------------------------------------------------------------

    def _seq_for_key(self, idempotency_key: str) -> int:
        for entry in self.audit:
            if entry.payload.get("idempotency_key") == idempotency_key:
                return entry.seq
        return -1
