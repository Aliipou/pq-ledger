"""Domain errors for pq_ledger.

All errors derive from LedgerError so callers can catch the whole family.
These are *value* errors about ledger semantics, never about secrets.
"""


class LedgerError(Exception):
    """Base class for all ledger errors."""


class AuthorizationError(LedgerError):
    """The capability gate denied the intent.

    Raised by state-changing operations when ``authorize(intent)`` returns
    a falsy value. The gate is an AuthGate-boundary STUB: it stands in for
    the real authorization kernel and performs no crypto here.
    """


class UnbalancedPostingError(LedgerError):
    """A posting's debit total does not equal its credit total."""


class InsufficientFundsError(LedgerError):
    """A posting would drive an account below zero without an explicit
    credit-line allowance (i.e. an attempted underflow)."""


class DuplicateIdempotencyKeyError(LedgerError):
    """A posting reused an idempotency key already committed.

    This is intentionally distinct from silent dedupe: ``post`` returns the
    prior result for a duplicate key, but if the *content* differs from the
    original posting under the same key, this error is raised instead.
    """


class TamperError(LedgerError):
    """The audit log hash chain failed verification (tamper-evident)."""


class UnknownAccountError(LedgerError):
    """A posting referenced an account that was never opened."""
