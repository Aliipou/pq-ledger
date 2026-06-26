"""Observability: structured JSON-line events + in-memory metrics.

Stdlib only. The :class:`EventEmitter` writes one JSON object per line (the
"JSON Lines" convention) to any text stream, defaulting to stdout. The
:class:`Metrics` object holds simple monotonic counters.

These are intentionally separate from the audit log: the audit log is the
*source of truth* (hash-chained, replayable); events and metrics are
*telemetry* (lossy, side-channel, safe to drop). Never reconstruct state from
telemetry.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, TextIO


@dataclass
class Metrics:
    """Simple in-memory counters for ledger activity."""

    postings: int = 0
    denials: int = 0
    rejected: int = 0
    duplicates: int = 0

    def snapshot(self) -> dict[str, int]:
        """A plain-dict copy of the current counters."""
        return {
            "postings": self.postings,
            "denials": self.denials,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
        }


class EventEmitter:
    """Emits structured events as JSON lines.

    Args:
        stream: any writable text stream (default ``sys.stdout``).
        enabled: when False, events are silently dropped (useful in tests).
    """

    def __init__(self, stream: TextIO | None = None, enabled: bool = True) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self.enabled = enabled

    def emit(self, event: str, **fields: Any) -> None:
        """Write one event line. Field values must be JSON-serializable."""
        if not self.enabled:
            return
        record = {"event": event, **fields}
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self._stream.write(line + "\n")
        self._stream.flush()
