"""
Local honeynet pipeline, end to end: raw sensor file -> collector -> DB -> bus.

test_local_telemetry.py already covers the source layer (tailing, offsets,
rotation) against normalize()'s output directly. Nothing in that file ever
drove a value through _persist()'s actual INSERT, which is exactly the gap
that let a column-name typo (`"metadata"` instead of `"event_metadata"` in
to_normalized_row) reach a running collector: every cycle silently ingested
zero events and recorded the AttributeError as last_error, because
insert(<ORM class>).values(...) resolves each dict key against the mapped
class, and `metadata` resolves to the declarative base's own MetaData object
rather than the column.

These tests run the collector against a real MariaDB schema (`shadowtrust_test`,
created by the `db` container on first boot) so that class of bug fails a test
instead of only surfacing at demo time. They are skipped with an explanatory
message if that database is unreachable — bring it up with
`docker compose up -d db`.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.db.database import Base
from app.models.all_models import IngestCursor, NormalizedEventModel, RawEventModel

# Set by conftest.py (defaults to the shadowtrust_test schema on local MariaDB).
TEST_DATABASE_URL = os.environ["DATABASE_URL"]
from app.services.event_bus import event_bus
from app.services.telemetry import collector as collector_module
from app.services.telemetry.collector import LocalCollector, to_normalized_row
from app.services.telemetry.normalize import normalize

COWRIE_LOGIN = {
    "eventid": "cowrie.login.success",
    "timestamp": "2026-01-01T10:00:02.158Z",
    "session": "3af27f802dc5",
    "src_ip": "203.0.113.5",
    "src_port": 54953,
    "dst_ip": "10.0.0.5",
    "dst_port": 2222,
    "sensor": "cowrie",
    "protocol": "ssh",
    "username": "root",
    "password": "hunter2",
    "message": "login attempt succeeded",
}

COWRIE_COMMAND = {
    "eventid": "cowrie.command.input",
    "timestamp": "2026-01-01T10:00:03.159Z",
    "session": "3af27f802dc5",
    "src_ip": "203.0.113.5",
    "src_port": 54953,
    "dst_ip": "10.0.0.5",
    "dst_port": 2222,
    "sensor": "cowrie",
    "protocol": "ssh",
    "input": "whoami",
    "message": "CMD: whoami",
}

MALFORMED_LINE = "{not valid json\n"


def write_ndjson(path, events):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


# The tests below drive async code through several separate calls per test
# (schema reset, one or more run_once(), then a fetch). aiomysql binds its
# connections to the running event loop, so every one of those calls has to
# happen on the *same* loop — `asyncio.run()` per call (which spins up and
# tears down a fresh loop each time) breaks the pool. `temp_db` owns one loop
# for the whole test and `run()` drives everything on it.
_TEST_LOOP: asyncio.AbstractEventLoop | None = None


@pytest.fixture
def temp_db(monkeypatch):
    """
    Give each test a freshly-created set of tables in the MariaDB test schema,
    all on a single dedicated event loop.

    Patches collector_module.AsyncSessionLocal directly rather than
    app.db.database.AsyncSessionLocal: collector.py imported that name at
    module load time (`from app.db.database import AsyncSessionLocal`), so
    the binding this test needs to change lives in collector_module's
    namespace, not the original module's.

    Skips (rather than errors) when the database is unreachable so
    `make test` degrades gracefully without `docker compose up -d db`.
    """
    global _TEST_LOOP

    loop = asyncio.new_event_loop()
    # NullPool: never hand a connection from one test's loop to the next.
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)

    async def _reset_schema():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    try:
        loop.run_until_complete(_reset_schema())
    except Exception as exc:  # OperationalError, connection refused, unknown db…
        loop.run_until_complete(engine.dispose())
        loop.close()
        pytest.skip(
            f"MariaDB test database not reachable at {TEST_DATABASE_URL!r} "
            f"({exc.__class__.__name__}). Run `docker compose up -d db` first."
        )

    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(collector_module, "AsyncSessionLocal", session_factory)
    _TEST_LOOP = loop

    yield session_factory

    async def _drop():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    loop.run_until_complete(_drop())
    loop.run_until_complete(engine.dispose())
    loop.close()
    _TEST_LOOP = None


def run(coro):
    """Drive a coroutine on the current test's dedicated loop."""
    assert _TEST_LOOP is not None, "run() used outside the temp_db fixture"
    return _TEST_LOOP.run_until_complete(coro)


async def _fetch_all(session_factory, model):
    async with session_factory() as db:
        return (await db.execute(select(model))).scalars().all()


class TestRowShapeMatchesModel:
    """Cheap guard against the exact bug class that motivated this file."""

    def test_normalized_row_keys_are_real_orm_attributes(self):
        event = normalize(COWRIE_LOGIN)
        row = to_normalized_row(event)

        mapper = NormalizedEventModel.__mapper__
        valid_attrs = {prop.key for prop in mapper.attrs}

        bogus = set(row.keys()) - valid_attrs
        assert not bogus, (
            f"to_normalized_row produced key(s) {bogus} that are not mapped "
            f"columns on NormalizedEventModel — insert(<ORM class>).values(...) "
            f"will resolve each of these against the class itself, and a "
            f"name that collides with a non-column attribute (e.g. "
            f"'metadata', which shadows the declarative base's own "
            f"MetaData) fails with an unrelated-looking AttributeError "
            f"instead of a clean KeyError."
        )

        # And the reverse: every non-nullable column the model defines is
        # actually populated, so a future column addition doesn't silently
        # ship as NULL.
        required = {
            prop.key for prop in mapper.attrs
            if getattr(prop, "columns", None) and not prop.columns[0].nullable
            and not prop.columns[0].primary_key
        }
        missing = required - set(row.keys())
        assert not missing, f"to_normalized_row is missing required column(s) {missing}"


class TestCollectorPersistsToDatabase:
    """The real path: sensor file -> run_once() -> normalized_events row."""

    def test_single_event_is_stored_with_correct_fields(self, tmp_path, temp_db, monkeypatch):
        sensor_dir = tmp_path / "telemetry"
        write_ndjson(str(sensor_dir / "cowrie" / "cowrie.json"), [COWRIE_LOGIN])
        monkeypatch.setenv("TELEMETRY_DIR", str(sensor_dir))

        collector = LocalCollector()
        stored = run(collector.run_once())
        assert stored == 1

        rows = run(_fetch_all(temp_db, NormalizedEventModel))
        assert len(rows) == 1
        row = rows[0]
        assert row.sensor == "cowrie"
        assert row.source_ip == "203.0.113.5"
        assert row.username == "root"
        assert row.authentication_result == "SUCCESS"
        assert row.session_id == "3af27f802dc5"
        # This is the field the original bug never reached: event_metadata is
        # a JSON column, so persisting it exercises the exact code path that
        # raised AttributeError before the fix.
        assert row.event_metadata is not None
        assert row.event_metadata.get("detected_sensor") == "cowrie"

    def test_mirrors_into_legacy_raw_events_table(self, tmp_path, temp_db, monkeypatch):
        """The pre-existing dashboard/geo/analytics endpoints read raw_events,
        not normalized_events — both must be written from one ingest cycle."""
        sensor_dir = tmp_path / "telemetry"
        write_ndjson(str(sensor_dir / "cowrie" / "cowrie.json"), [COWRIE_LOGIN])
        monkeypatch.setenv("TELEMETRY_DIR", str(sensor_dir))

        run(LocalCollector().run_once())

        raw_rows = run(_fetch_all(temp_db, RawEventModel))
        assert len(raw_rows) == 1
        assert raw_rows[0].attacker_ip == "203.0.113.5"
        assert raw_rows[0].honeypot_type == "Cowrie"

    def test_multiple_events_across_a_session_all_land(self, tmp_path, temp_db, monkeypatch):
        sensor_dir = tmp_path / "telemetry"
        write_ndjson(
            str(sensor_dir / "cowrie" / "cowrie.json"),
            [COWRIE_LOGIN, COWRIE_COMMAND],
        )
        monkeypatch.setenv("TELEMETRY_DIR", str(sensor_dir))

        stored = run(LocalCollector().run_once())
        assert stored == 2

        rows = run(_fetch_all(temp_db, NormalizedEventModel))
        commands = [r.command for r in rows if r.command]
        assert commands == ["whoami"]

    def test_malformed_line_is_skipped_not_fatal(self, tmp_path, temp_db, monkeypatch):
        sensor_dir = tmp_path / "telemetry"
        path = sensor_dir / "cowrie" / "cowrie.json"
        os.makedirs(path.parent, exist_ok=True)
        with open(path, "w") as handle:
            handle.write(MALFORMED_LINE)
            handle.write(json.dumps(COWRIE_LOGIN) + "\n")
        monkeypatch.setenv("TELEMETRY_DIR", str(sensor_dir))

        stored = run(LocalCollector().run_once())
        assert stored == 1

        rows = run(_fetch_all(temp_db, NormalizedEventModel))
        assert len(rows) == 1


class TestIdempotentReingestion:
    """A crash-and-restart must not duplicate rows or double-count stats."""

    def test_second_cycle_with_no_new_data_stores_nothing(self, tmp_path, temp_db, monkeypatch):
        sensor_dir = tmp_path / "telemetry"
        write_ndjson(str(sensor_dir / "cowrie" / "cowrie.json"), [COWRIE_LOGIN])
        monkeypatch.setenv("TELEMETRY_DIR", str(sensor_dir))

        collector = LocalCollector()
        first = run(collector.run_once())
        second = run(collector.run_once())

        assert first == 1
        assert second == 0
        rows = run(_fetch_all(temp_db, NormalizedEventModel))
        assert len(rows) == 1

    def test_cursor_advances_so_appended_lines_are_the_only_new_reads(
        self, tmp_path, temp_db, monkeypatch
    ):
        sensor_dir = tmp_path / "telemetry"
        path = str(sensor_dir / "cowrie" / "cowrie.json")
        write_ndjson(path, [COWRIE_LOGIN])
        monkeypatch.setenv("TELEMETRY_DIR", str(sensor_dir))

        collector = LocalCollector()
        run(collector.run_once())

        with open(path, "a") as handle:
            handle.write(json.dumps(COWRIE_COMMAND) + "\n")

        second = run(collector.run_once())
        assert second == 1

        rows = run(_fetch_all(temp_db, NormalizedEventModel))
        assert len(rows) == 2

        cursors = run(_fetch_all(temp_db, IngestCursor))
        assert len(cursors) == 1
        assert cursors[0].byte_offset > 0


class TestEventBusPublication:
    """The SSE stream reads this bus — a stored event that never publishes
    means the DB is correct but the live dashboard stays silent."""

    def test_stored_event_is_published_to_subscribers(self, tmp_path, temp_db, monkeypatch):
        sensor_dir = tmp_path / "telemetry"
        write_ndjson(str(sensor_dir / "cowrie" / "cowrie.json"), [COWRIE_LOGIN])
        monkeypatch.setenv("TELEMETRY_DIR", str(sensor_dir))

        async def scenario():
            subscription = event_bus.subscribe()
            try:
                # subscribe() returns an async generator that does not
                # register its queue in event_bus._subscribers until it
                # actually starts running — i.e. until something awaits its
                # first __anext__(). Schedule that as a task and yield control
                # once so it reaches its internal `await queue.get()` and is
                # registered *before* the collector publishes, exactly as the
                # SSE endpoint's own subscribe-then-await-in-a-loop ordering
                # guarantees for a real client already connected when an
                # event happens.
                next_event = asyncio.create_task(subscription.__anext__())
                await asyncio.sleep(0)

                collector = LocalCollector()
                stored = await collector.run_once()
                assert stored == 1

                published = await asyncio.wait_for(next_event, timeout=2)
                assert published["source_ip"] == "203.0.113.5"
                assert published["sensor"] == "cowrie"
            finally:
                await subscription.aclose()

        run(scenario())
