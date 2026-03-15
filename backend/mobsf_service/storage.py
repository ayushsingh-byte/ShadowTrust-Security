import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import DB_PATH, DATA_DIR, UPLOAD_DIR


DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_storage() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                hash TEXT PRIMARY KEY,
                file_name TEXT,
                scan_type TEXT,
                original_filename TEXT,
                app_name TEXT,
                package_name TEXT,
                version_name TEXT,
                score INTEGER DEFAULT 0,
                timestamp TEXT,
                raw_report TEXT
            )
            """
        )


def save_upload_context(scan_hash: str, file_name: str, scan_type: str, original_filename: str) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (hash, file_name, scan_type, original_filename, timestamp)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                file_name = excluded.file_name,
                scan_type = excluded.scan_type,
                original_filename = excluded.original_filename,
                timestamp = excluded.timestamp
            """,
            (scan_hash, file_name, scan_type, original_filename, datetime.now(timezone.utc).isoformat()),
        )


def get_scan_context(scan_hash: str):
    with _connect() as conn:
        row = conn.execute(
            "SELECT hash, file_name, scan_type, original_filename, app_name, package_name, version_name, score, timestamp, raw_report FROM scans WHERE hash = ?",
            (scan_hash,),
        ).fetchone()
    return dict(row) if row else None


def save_report(scan_hash: str, report: dict, score: int) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            UPDATE scans
            SET app_name = ?,
                package_name = ?,
                version_name = ?,
                score = ?,
                timestamp = ?,
                raw_report = ?
            WHERE hash = ?
            """,
            (
                report.get("app_name") or report.get("file_name") or "Unknown App",
                report.get("package_name") or "unknown",
                report.get("version_name") or report.get("version") or "N/A",
                int(score),
                timestamp,
                json.dumps(report),
                scan_hash,
            ),
        )


def list_history(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT hash, app_name, package_name, version_name, score, timestamp, original_filename
            FROM scans
            WHERE raw_report IS NOT NULL
            ORDER BY datetime(timestamp) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
