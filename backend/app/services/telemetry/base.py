"""
Provider-agnostic telemetry ingestion contract.

A TelemetrySource is responsible for exactly one thing: returning raw honeypot
event dicts plus the set of source keys they came from. Everything downstream —
parsing, ML categorisation, deduplication, DB writes — is shared and lives in
UnifiedTelemetryService, unchanged.

Sources report their own readiness via is_configured(), so the pipeline never
has to know whether it needs AWS credentials or a local directory.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Set, Tuple


class TelemetrySource(ABC):
    """Yields raw honeypot events from some backing store."""

    #: Short source name, used in log lines.
    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool:
        """True when this source has everything it needs to run."""

    @abstractmethod
    def fetch(
        self, processed_state_by_key: Dict[str, datetime]
    ) -> Tuple[List[dict], Set[str]]:
        """
        Return (raw event dicts, set of source keys touched).

        `processed_state_by_key` maps a previously-seen key to the time it was
        last processed. Implementations must skip keys whose content has not
        changed since then, which is what makes ingestion idempotent across
        restarts.

        This call is synchronous and may block on I/O; the pipeline runs it in
        a worker thread.
        """

    def describe(self) -> str:
        """Human-readable description for logs and status endpoints."""
        return self.name
