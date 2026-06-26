"""pq_ledger: a minimal, deterministic, double-entry ledger.

This package is the "Post-Quantum Economy" core of an ecosystem of
independent repos. Its single responsibility is *ledger correctness*.

It is NOT a bank, NOT key management, NOT crypto, NOT a payment processor.
It owns no secrets (no keys, certs, wallets). See THREAT_MODEL.md.

Public surface:
    Ledger              -- the double-entry ledger
    Posting, Line       -- a balanced transaction and its legs
    AuditLog            -- append-only, hash-chained, tamper-evident log
    AuthorizationError  -- raised when the capability gate denies an intent
    LedgerError, ...    -- domain errors
    allow_all, deny_all -- trivial capability-gate stubs
"""

from .errors import (
    LedgerError,
    AuthorizationError,
    UnbalancedPostingError,
    InsufficientFundsError,
    DuplicateIdempotencyKeyError,
    TamperError,
    UnknownAccountError,
)
from .audit import AuditLog, AuditEntry
from .ledger import Ledger, Posting, Line, Account
from .gate import allow_all, deny_all, Intent
from .observability import Metrics, EventEmitter

__all__ = [
    "Ledger",
    "Posting",
    "Line",
    "Account",
    "AuditLog",
    "AuditEntry",
    "Intent",
    "allow_all",
    "deny_all",
    "Metrics",
    "EventEmitter",
    "LedgerError",
    "AuthorizationError",
    "UnbalancedPostingError",
    "InsufficientFundsError",
    "DuplicateIdempotencyKeyError",
    "TamperError",
    "UnknownAccountError",
]

__version__ = "0.1.0"
