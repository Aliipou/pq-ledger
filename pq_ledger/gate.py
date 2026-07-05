"""Capability-gate boundary STUB.

Every state-changing ledger operation passes an :class:`Intent` to a callable
``authorize(intent) -> bool``. That callable represents AuthGate, the real
authorization kernel in the sibling repo.

This module deliberately contains NO crypto, NO key material, NO policy. It
only defines the *shape* of the boundary and ships two trivial stubs so the
ledger is exercisable and testable in isolation. In production the host wires
the real AuthGate enforce-callable in place of these stubs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Intent:
    """A request to perform a state-changing operation.

    Attributes:
        action: e.g. ``"post"`` or ``"open_account"``.
        idempotency_key: the key of the operation, if any.
        debit_total: sum of debit lines (for postings).
        credit_total: sum of credit lines (for postings).
        accounts: the account ids touched by the operation.
        metadata: free-form, non-secret context for policy decisions.
    """

    action: str
    idempotency_key: str | None = None
    debit_total: int = 0
    credit_total: int = 0
    accounts: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


# An Authorizer is any callable taking an Intent and returning truthy/falsy.
Authorizer = Callable[[Intent], bool]


def allow_all(intent: Intent) -> bool:
    """Permissive stub: authorizes every intent. For tests/dev only."""
    return True


def deny_all(intent: Intent) -> bool:
    """Restrictive stub: denies every intent. For tests/dev only."""
    return False
