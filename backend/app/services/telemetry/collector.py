"""
Local telemetry collector.

The ingestion pipeline for INFRA_PROVIDER=local. One cycle is:

    tail sensor logs      (LocalDirectorySource.fetch_with_cursors)
        -> normalize      (telemetry.normalize)
        -> persist        (NormalizedEventModel + RawEventModel)
        -> publish        (event_bus -> SSE -> dashboard)
        -> save cursors   (IngestCursor)

Cursors are committed in the same transaction as the events. If the process
dies mid-cycle the transaction rolls back and the same bytes are re-read next
time; the content-hash primary key on normalized_events then absorbs the
repeat. Committing cursors separately would risk the opposite — advancing past
events that were never stored, silently losing them.

The S3 path (INFRA_PROVIDER=aws) still runs through UnifiedTelemetryService in
aws_telemetry_service.py. Both now share this module's normalization, so the
two no longer drift.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Dict, List

from sqlalchemy import insert, select
from sqlalchemy.dialects.mysql import insert as mysql_insert

from app.db.database import AsyncSessionLocal
from app.models.all_models import IngestCursor, NormalizedEventModel, RawEventModel
from app.services.event_bus import event_bus
from app.services.telemetry.local_source import FileCursor, LocalDirectorySource
from app.services.telemetry.normalize import NormalizedEvent, normalize

logger = logging.getLogger(__name__)

# How often to look for new telemetry. The demo in the README depends on an
# attack appearing "within seconds", so this is deliberately short — tailing a
# handful of local files is cheap. Override with COLLECTOR_INTERVAL_SECONDS.
DEFAULT_INTERVAL_SECONDS = 2.0

# Backoff after an unexpected error, so a persistent failure (bad permissions,
# corrupt DB) does not spin the loop at full speed.
ERROR_BACKOFF_SECONDS = 15.0

# Risk scores for the legacy RawEventModel.risk_score column, which the
# existing dashboard endpoints already read. Keyed by normalized severity.
SEVERITY_RISK_SCORE = {
    "CRITICAL": 95.0,
    "HIGH": 80.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "INFO": 10.0,
}


def _interval_seconds() -> float:
    """Poll interval, overridable for tests and busy deployments."""
    try:
        return max(0.2, float(os.getenv("COLLECTOR_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS)))
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_SECONDS


def to_normalized_row(event: NormalizedEvent) -> dict:
    """NormalizedEvent -> column values for normalized_events."""
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "ingested_at": datetime.utcnow(),
        "sensor": event.sensor,
        "sensor_event_type": event.sensor_event_type,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "username": event.username,
        "password": event.password,
        "authentication_result": event.authentication_result,
        "command": event.command,
        "payload": event.payload,
        "session_id": event.session_id,
        "severity": event.severity,
        "raw_event": event.raw_event,
        # The ORM attribute is `event_metadata` (column name "metadata") —
        # keying this "metadata" instead resolves against
        # NormalizedEventModel.metadata, which is the declarative base's own
        # MetaData object, not the column, and blows up inside SQLAlchemy's
        # ORM-mode bulk insert with an unrelated-looking AttributeError.
        "event_metadata": event.metadata,
    }


def to_raw_event_row(event: NormalizedEvent) -> RawEventModel:
    """
    NormalizedEvent -> RawEventModel.

    RawEventModel predates normalization and still backs the existing
    dashboard, analytics, geo and events endpoints. Writing both keeps those
    pages working untouched while new code reads normalized_events.

    Note this preserves the *sensor's* event type rather than overwriting it
    with a derived category, which the previous inline parser did — that lost
    the original eventid everywhere except the raw payload blob.
    """
    return RawEventModel(
        id=event.event_id,
        timestamp=event.timestamp,
        attacker_ip=event.source_ip,
        target_port=event.destination_port or 0,
        protocol=event.protocol,
        honeypot_type=event.sensor.capitalize(),
        session_id=event.session_id or event.event_id,
        event_type=event.sensor_event_type,
        commands=event.command,
        risk_score=SEVERITY_RISK_SCORE.get(event.severity, 10.0),
        raw_payload=event.raw_event,
        sync_status="LOCAL",
        # Reuse the content hash as the uniqueness signature. The old
        # ip:port:timestamp form collapsed distinct same-second events.
        signature=event.event_id,
    )


class LocalCollector:
    """Polls the telemetry directory and ingests whatever is new."""

    def __init__(self, source: LocalDirectorySource = None, publish: bool = True):
        self.source = source or LocalDirectorySource()
        self.publish = publish
        self.is_running = False

        # Observability, surfaced by /api/v1/live/collector.
        self.cycles = 0
        self.events_ingested = 0
        self.events_skipped = 0
        self.last_cycle_at: datetime = None
        self.last_run_at: datetime = None
        self.last_error: str = None

    async def _load_cursors(self, db) -> Dict[str, FileCursor]:
        """Read stored file positions into the source's cursor shape."""
        result = await db.execute(select(IngestCursor))
        return {
            row.source_key: FileCursor(
                source_key=row.source_key,
                inode=row.inode or "",
                size_bytes=row.size_bytes or 0,
                byte_offset=row.byte_offset or 0,
            )
            for row in result.scalars().all()
        }

    async def _save_cursors(self, db, cursors: Dict[str, FileCursor], counts: Dict[str, int]) -> None:
        """Upsert file positions. Same transaction as the events they cover."""
        for key, cursor in cursors.items():
            statement = mysql_insert(IngestCursor).values(
                source_key=key,
                inode=cursor.inode,
                size_bytes=cursor.size_bytes,
                byte_offset=cursor.byte_offset,
                events_ingested=counts.get(key, 0),
                processed_at=datetime.utcnow(),
            )
            # ON DUPLICATE KEY UPDATE — the cursor row is created on first sight
            # of a file and updated on every cycle thereafter. The MySQL dialect
            # exposes the would-be-inserted row as `statement.inserted`.
            statement = statement.on_duplicate_key_update(
                inode=statement.inserted.inode,
                size_bytes=statement.inserted.size_bytes,
                byte_offset=statement.inserted.byte_offset,
                events_ingested=IngestCursor.events_ingested
                + statement.inserted.events_ingested,
                processed_at=statement.inserted.processed_at,
            )
            await db.execute(statement)

    async def _persist(self, db, events: List[NormalizedEvent]) -> int:
        """
        Insert normalized and raw rows, ignoring events already stored.

        INSERT IGNORE makes re-ingestion a no-op at the database level (a row
        whose primary key already exists is skipped), so a re-read after a
        crash cannot create duplicates.
        """
        if not events:
            return 0

        rows = [to_normalized_row(event) for event in events]
        statement = insert(NormalizedEventModel).values(rows).prefix_with("IGNORE")
        await db.execute(statement)

        # Mirror into the legacy table the existing dashboard reads.
        raw_rows = [
            {
                "id": event.event_id,
                "timestamp": event.timestamp,
                "attacker_ip": event.source_ip,
                "target_port": event.destination_port or 0,
                "protocol": event.protocol,
                "honeypot_type": event.sensor.capitalize(),
                "session_id": event.session_id or event.event_id,
                "event_type": event.sensor_event_type,
                "commands": event.command,
                "risk_score": SEVERITY_RISK_SCORE.get(event.severity, 10.0),
                "raw_payload": event.raw_event,
                "sync_status": "LOCAL",
                "signature": event.event_id,
            }
            for event in events
        ]
        raw_statement = insert(RawEventModel).values(raw_rows).prefix_with("IGNORE")
        await db.execute(raw_statement)

        return len(rows)

    async def run_once(self) -> int:
        """
        One ingest cycle. Returns the number of events stored.

        Split out from the loop so tests can drive a single deterministic cycle
        without touching asyncio scheduling.
        """
        self.last_run_at = datetime.utcnow()
        async with AsyncSessionLocal() as db:
            cursors = await self._load_cursors(db)

            # File I/O in a thread so the event loop stays responsive.
            raw_events, updated_cursors = await asyncio.to_thread(
                self.source.fetch_with_cursors, cursors
            )

            if not raw_events and not updated_cursors:
                return 0

            normalized: List[NormalizedEvent] = []
            skipped = 0
            for raw in raw_events:
                event = normalize(raw)
                if event is None:
                    skipped += 1
                    continue
                normalized.append(event)

            self.events_skipped += skipped

            # Deduplicate within the batch: the same line can legitimately
            # appear twice in one cycle across rotated files, and a multi-row
            # INSERT that repeats a primary key is rejected outright.
            seen = set()
            unique: List[NormalizedEvent] = []
            for event in normalized:
                if event.event_id in seen:
                    continue
                seen.add(event.event_id)
                unique.append(event)

            per_file_counts = {key: 0 for key in updated_cursors}

            stored = await self._persist(db, unique)
            await self._save_cursors(db, updated_cursors, per_file_counts)

            try:
                await db.commit()
            except Exception as exc:
                await db.rollback()
                self.last_error = str(exc)
                logger.error(f"Collector commit failed, cycle rolled back: {exc}")
                return 0

            self.events_ingested += stored
            self.last_cycle_at = datetime.utcnow()

            # Publish only after a successful commit, so the dashboard never
            # shows an event that is not in the database.
            if self.publish and unique:
                event_bus.publish_many(event.to_dict() for event in unique)

            if unique:
                logger.info(
                    f"Collector ingested {len(unique)} event(s) from "
                    f"{len(updated_cursors)} file(s)."
                )

            return stored

    async def run_forever(self) -> None:
        """Poll until cancelled."""
        self.is_running = True
        interval = _interval_seconds()
        logger.info(
            f"Local telemetry collector started "
            f"(source: {self.source.describe()}, interval: {interval}s)"
        )

        while self.is_running:
            try:
                await self.run_once()
                self.cycles += 1
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                # Normal shutdown path — re-raise so the task actually stops.
                raise
            except Exception as exc:
                self.last_error = str(exc)
                logger.error(f"Collector cycle failed: {exc}")
                await asyncio.sleep(ERROR_BACKOFF_SECONDS)

    def status(self) -> dict:
        """Health snapshot for the sensors/collector API."""
        return {
            "running": self.is_running,
            "source": self.source.describe(),
            "interval_seconds": _interval_seconds(),
            "cycles": self.cycles,
            "events_ingested": self.events_ingested,
            "events_skipped": self.events_skipped,
            "last_cycle_at": self.last_cycle_at.isoformat() if self.last_cycle_at else None,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_error": self.last_error,
            "subscribers": event_bus.subscriber_count,
            "dropped_to_slow_clients": event_bus.dropped_count,
        }


# Module-level singleton, started from main.py's lifespan.
local_collector = LocalCollector()
