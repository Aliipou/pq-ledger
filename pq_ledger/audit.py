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

Durability
----------
By default the log is purely in-memory. When constructed with a ``path`` it is
*also* persisted: every appended entry is written as one canonical JSON line and
flushed + ``fsync``-ed to disk before :meth:`append` returns, so a process crash
loses nothing that was acknowledged. :meth:`AuditLog.from_file` reloads the log
and verifies the hash chain on load. This adds durability only; it owns no
secrets and performs no signing (still tamper-evident, not tamper-proof; see
THREAT_MODEL.md).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass
from typing import Any

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
    """An ordered, append-only chain of :class:`AuditEntry`.

    In-memory by default. When ``path`` is given the chain is *also* durably
    persisted: each appended entry is written as one canonical JSON line and
    flushed + ``fsync``-ed before :meth:`append` returns, so an acknowledged
    append survives a process crash. The in-memory default keeps existing
    behaviour unchanged.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._path: str | None = os.fspath(path) if path is not None else None
        self._fh = None  # lazily-opened append handle when file-backed
        if self._path is not None:
            # Open for append; create if absent. Line-buffered text mode; we
            # explicitly flush + fsync per append for durability.
            self._fh = open(self._path, "a", encoding="utf-8", newline="\n")

    # -- durability -----------------------------------------------------------

    @property
    def path(self) -> str | None:
        """The backing file path, or None for a pure in-memory log."""
        return self._path

    def _persist(self, entry: AuditEntry) -> None:
        """Durably append one entry as a single canonical JSON line.

        The line is the entry's full record (seq, prev_hash, entry_hash,
        payload) so a reload can reconstruct AND re-verify the chain. Flushed
        and fsynced before returning so a crash cannot lose an acked append.
        """
        if self._fh is None:
            return
        line = json.dumps(
            entry.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        self._fh.write(line + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        """Close the backing file handle, if any. Idempotent.

        Durability does not depend on this: every append is already flushed and
        fsynced. ``close`` just releases the OS handle for a graceful shutdown;
        an ungraceful crash loses nothing acknowledged.
        """
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- append-only mutation -------------------------------------------------

    def append(self, payload: Mapping[str, Any]) -> AuditEntry:
        """Append a payload, computing and linking its chained hash.

        When file-backed, the entry is durably written (flush + fsync) to disk
        before this returns.
        """
        seq = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH
        # Freeze a defensive copy so later caller mutation can't desync the hash.
        frozen = dict(payload)
        entry_hash = compute_hash(seq, prev_hash, frozen)
        entry = AuditEntry(seq=seq, prev_hash=prev_hash, entry_hash=entry_hash, payload=frozen)
        self._persist(entry)
        self._entries.append(entry)
        return entry

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> AuditLog:
        """Load a file-backed log from ``path`` and verify its hash chain.

        Reads each JSON line back into an :class:`AuditEntry`, rebuilds the
        in-memory chain, runs :meth:`verify` (so a corrupted/edited line is
        DETECTED here, raising :class:`TamperError`), and returns a log that is
        ready to durably append further entries to the same file.
        """
        log = cls.__new__(cls)
        log._entries = []
        log._path = os.fspath(path)
        log._fh = None

        with open(log._path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh):
                line = raw.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise TamperError(f"malformed audit line {lineno}: {exc}") from exc
                try:
                    entry = AuditEntry(
                        seq=record["seq"],
                        prev_hash=record["prev_hash"],
                        entry_hash=record["entry_hash"],
                        payload=record["payload"],
                    )
                except (KeyError, TypeError) as exc:
                    raise TamperError(f"malformed audit record at line {lineno}: {exc}") from exc
                log._entries.append(entry)

        # Verify BEFORE accepting the log or opening it for further appends.
        log.verify()

        # Re-open for append now that the loaded chain is trusted.
        log._fh = open(log._path, "a", encoding="utf-8", newline="\n")
        return log

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
