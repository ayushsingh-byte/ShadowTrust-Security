"""
Local filesystem telemetry source.

Watches a directory of honeypot logs and feeds them into the same pipeline the
S3 source feeds. Requires no cloud account and no credentials.

Reading strategy
----------------
Honeypot logs are append-only. This source therefore *tails* each file from a
stored byte offset rather than re-reading it whole:

* A file is read from ``byte_offset`` to EOF; the offset then advances.
* If the inode changes, or the file is smaller than the recorded offset, the
  file was rotated or truncated, so the offset resets to 0.
* A trailing partial line (the sensor was mid-write) is left unconsumed so it
  is read intact on the next cycle.

The previous implementation re-read the entire file whenever its mtime
advanced, re-emitting every historical line each cycle. Dedup downstream then
had to discard thousands of repeats, and did so with an ``ip:port:timestamp``
signature that collapsed genuinely distinct events occurring in the same
second from the same host. Offsets remove the duplicates at the source.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Set, Tuple

from app.services.telemetry.base import TelemetrySource

logger = logging.getLogger(__name__)

# Cap on files touched per cycle, so one pass cannot stall the poll loop.
MAX_FILES_PER_CYCLE = 250

# Cap on bytes read from a single file per cycle. A honeypot under heavy attack
# can append faster than we ingest; this bounds memory per cycle and lets the
# next cycle pick up exactly where this one stopped.
MAX_BYTES_PER_FILE = 8 * 1024 * 1024

VALID_SUFFIXES = (".json", ".log", ".jsonl")


@dataclass
class FileCursor:
    """Read position for one telemetry file."""

    source_key: str
    inode: str = ""
    size_bytes: int = 0
    byte_offset: int = 0
    # Last-modified time seen when the file was read; not persisted. The
    # collector uses it to measure write-to-publish latency.
    mtime: float = 0.0


class LocalDirectorySource(TelemetrySource):
    """Reads honeypot events from a directory on the local filesystem."""

    name = "local"

    def __init__(self, directory: str = None):
        self.directory = os.path.abspath(
            directory or os.getenv("TELEMETRY_DIR", "./telemetry")
        )

    def is_configured(self) -> bool:
        """
        The local source is ready as soon as its directory exists.

        The directory is created on first use so a fresh checkout works with no
        manual setup.
        """
        if os.path.isdir(self.directory):
            return True
        try:
            os.makedirs(self.directory, exist_ok=True)
            logger.info(f"Created telemetry directory: {self.directory}")
            return True
        except Exception as exc:
            logger.error(f"Cannot create telemetry directory {self.directory}: {exc}")
            return False

    def describe(self) -> str:
        return f"local directory {self.directory}"

    def _iter_files(self) -> List[Tuple[str, str, os.stat_result]]:
        """Yield (sync_key, absolute_path, stat) for every candidate log file."""
        found: List[Tuple[str, str, os.stat_result]] = []
        for root, _dirs, files in os.walk(self.directory):
            for filename in files:
                if not filename.endswith(VALID_SUFFIXES):
                    continue
                abs_path = os.path.join(root, filename)
                try:
                    stat = os.stat(abs_path)
                except OSError:
                    continue
                # The relative path is the sync key, so moving the watch root
                # does not orphan previously-recorded state.
                key = os.path.relpath(abs_path, self.directory)
                found.append((key, abs_path, stat))
        return found

    @staticmethod
    def _resolve_offset(cursor: FileCursor, stat: os.stat_result) -> int:
        """
        Where to start reading, accounting for rotation and truncation.

        A changed inode means the path now points at a different file (log
        rotation). A size below the recorded offset means the file was
        truncated in place. Either way the stored offset is meaningless and
        reading must restart from the beginning, or new content is skipped.
        """
        current_inode = str(stat.st_ino)
        if cursor.inode and cursor.inode != current_inode:
            logger.info(
                f"Telemetry file rotated ({cursor.source_key}); restarting from offset 0."
            )
            return 0
        if stat.st_size < cursor.byte_offset:
            logger.info(
                f"Telemetry file truncated ({cursor.source_key}); restarting from offset 0."
            )
            return 0
        return cursor.byte_offset

    def fetch_with_cursors(
        self, cursors: Dict[str, FileCursor]
    ) -> Tuple[List[dict], Dict[str, FileCursor]]:
        """
        Read new bytes from every changed file.

        Args:
            cursors: current read positions, keyed by relative path.

        Returns:
            (parsed events, updated cursors for files that were read)
        """
        if not self.is_configured():
            return [], {}

        all_files = self._iter_files()
        if not all_files:
            return [], {}

        # Oldest first, so events are ingested in roughly chronological order.
        all_files.sort(key=lambda entry: entry[2].st_mtime)

        parsed_events: List[dict] = []
        updated: Dict[str, FileCursor] = {}

        for key, abs_path, stat in all_files[:MAX_FILES_PER_CYCLE]:
            cursor = cursors.get(key) or FileCursor(source_key=key)
            start = self._resolve_offset(cursor, stat)

            # Nothing appended since last cycle.
            if start >= stat.st_size:
                continue

            try:
                with open(abs_path, "rb") as handle:
                    handle.seek(start)
                    chunk = handle.read(MAX_BYTES_PER_FILE)
            except Exception as read_err:
                logger.warning(f"Could not read {abs_path}: {read_err}")
                continue

            if not chunk:
                continue

            consumed = len(chunk)

            # If the read stopped mid-line, leave the remainder for next cycle
            # so a half-written JSON object is never parsed as garbage.
            last_newline = chunk.rfind(b"\n")
            if last_newline == -1:
                # No complete line yet. Wait rather than consuming a fragment,
                # unless the fragment alone already exceeds the per-cycle cap —
                # in which case the line is pathological and skipping it is the
                # only way to make progress.
                if consumed < MAX_BYTES_PER_FILE:
                    continue
                logger.warning(
                    f"Oversized line without newline in {key}; skipping {consumed} bytes."
                )
                updated[key] = FileCursor(
                    source_key=key,
                    inode=str(stat.st_ino),
                    size_bytes=stat.st_size,
                    byte_offset=start + consumed,
                    mtime=stat.st_mtime,
                )
                continue

            usable = chunk[: last_newline + 1]
            consumed = len(usable)

            # Honeypot logs are newline-delimited JSON, one event per line —
            # the same shape the S3 source parses.
            for line in usable.decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        parsed_events.append(event)
                except Exception:
                    # A single malformed line should not stop the file.
                    continue

            updated[key] = FileCursor(
                source_key=key,
                inode=str(stat.st_ino),
                size_bytes=stat.st_size,
                byte_offset=start + consumed,
                mtime=stat.st_mtime,
            )

        return parsed_events, updated

    def fetch(
        self, processed_state_by_key: Dict[str, datetime]
    ) -> Tuple[List[dict], Set[str]]:
        """
        Legacy mtime-based interface, kept so the S3 code path and any existing
        caller keep working unchanged.

        New code should call fetch_with_cursors, which reads each line exactly
        once. This wrapper cannot do that — it has no offsets to work from —
        so it still re-reads whole files.
        """
        if not self.is_configured():
            return [], set()

        all_files = self._iter_files()
        if not all_files:
            return [], set()

        all_files.sort(key=lambda entry: entry[2].st_mtime, reverse=True)

        candidates: List[Tuple[str, str]] = []
        for key, abs_path, stat in all_files:
            mtime = datetime.utcfromtimestamp(stat.st_mtime)
            processed_at = processed_state_by_key.get(key)
            if processed_at is None:
                candidates.append((key, abs_path))
                continue
            try:
                if processed_at.tzinfo is not None:
                    processed_at = processed_at.replace(tzinfo=None)
                if mtime > processed_at:
                    candidates.append((key, abs_path))
            except Exception:
                candidates.append((key, abs_path))

        parsed_events: List[dict] = []
        touched_keys: Set[str] = set()

        for key, abs_path in candidates[:MAX_FILES_PER_CYCLE]:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()
                touched_keys.add(key)
            except Exception as read_err:
                logger.warning(f"Could not read {abs_path}: {read_err}")
                continue

            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        parsed_events.append(event)
                except Exception:
                    continue

        return parsed_events, touched_keys
