"""Append-only, hash-chained, tamper-evident audit log.

Each entry stores the hash of the previous entry, forming a chain. Any
mutation of a committed entry breaks every hash from that point forward, which
:meth:`AuditLog.verify` detects.

Determinism: the hash is computed over a *canonical* JSON serialization of the
entry payload (sorted keys, no whitespace, integer amounts). Given the same
sequence of payloads, the same chain is produced bit-for-bit on any machine.

This is tamper-EVIDENCE, not tamper-PROOFING. See THREAT_MODEL.md: an attacker
who can rewrite the whole log can recompute a fresh consistent chain. The chain
detects partial/blind edits, not a full re-forge by a writer with full access.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any, Iterator, Mapping

from .errors import TamperError

# Genesis previous-hash for the first entry. A fixed constant so the chain is
# reproducible across processes and machines.
GENESIS_PREV_HASH = "0" * 64


def _canonical(payload: Mapping[str, Any]) -> bytes:
    """Deterministic byte serialization of a payload."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_hash(seq: int, prev_hash: str, payload: Mapping[str, Any]) -> str:
    """Compute the chained hash for an entry.

    The hash binds the sequence number, the previous hash, and the canonical
    payload, so reordering or editing any of them is detectable.
    """
    h = hashlib.sha256()
    h.update(str(seq).encode("ascii"))
    h.update(b"\x00")
    h.update(prev_hash.encode("ascii"))
    h.update(b"\x00")
    h.update(_canonical(payload))
    return h.hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    """One committed, immutable log record."""

    seq: int
    prev_hash: str
    entry_hash: str
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # payload is already a plain dict; copy to avoid aliasing.
        d["payload"] = dict(self.payload)
        return d


class AuditLog:
    """An ordered, append-only chain of :class:`AuditEntry`."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    # -- append-only mutation -------------------------------------------------

    def append(self, payload: Mapping[str, Any]) -> AuditEntry:
        """Append a payload, computing and linking its chained hash."""
        seq = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH
        # Freeze a defensive copy so later caller mutation can't desync the hash.
        frozen = dict(payload)
        entry_hash = compute_hash(seq, prev_hash, frozen)
        entry = AuditEntry(seq=seq, prev_hash=prev_hash, entry_hash=entry_hash, payload=frozen)
        self._entries.append(entry)
        return entry

    # -- read / query ---------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(self._entries)

    @property
    def head_hash(self) -> str:
        """Hash of the latest entry, or genesis if empty."""
        return self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH

    def entries(self) -> list[AuditEntry]:
        """A shallow copy of all entries in order."""
        return list(self._entries)

    def query(
        self,
        *,
        action: str | None = None,
        account: str | None = None,
        idempotency_key: str | None = None,
    ) -> list[AuditEntry]:
        """Filter the log by common payload fields. All filters AND together."""
        out: list[AuditEntry] = []
        for e in self._entries:
            p = e.payload
            if action is not None and p.get("action") != action:
                continue
            if idempotency_key is not None and p.get("idempotency_key") != idempotency_key:
                continue
            if account is not None:
                accts = p.get("accounts") or []
                if account not in accts:
                    continue
            out.append(e)
        return out

    # -- integrity ------------------------------------------------------------

    def verify(self) -> bool:
        """Recompute the whole chain and confirm it is intact.

        Raises:
            TamperError: with the failing seq if any link is inconsistent.
        Returns:
            True if the entire chain verifies.
        """
        prev_hash = GENESIS_PREV_HASH
        for i, e in enumerate(self._entries):
            if e.seq != i:
                raise TamperError(f"seq mismatch at index {i}: stored seq={e.seq}")
            if e.prev_hash != prev_hash:
                raise TamperError(f"broken chain at seq {e.seq}: prev_hash does not match")
            expected = compute_hash(e.seq, e.prev_hash, e.payload)
            if expected != e.entry_hash:
                raise TamperError(f"payload tampered at seq {e.seq}: hash mismatch")
            prev_hash = e.entry_hash
        return True
