"""Shared pytest fixtures for the provider/telemetry test suite."""

import os
import sys
from pathlib import Path

import pytest

# The backend package is rooted at backend/, so `app.*` imports resolve.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# The app's Settings model requires SECRET_KEY. Provide a throwaway value so
# importing application modules never depends on a developer's .env.
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-for-anything")

# Tests run against a dedicated schema on the same MariaDB the app uses. The
# `db` container creates `shadowtrust_test` on first boot
# (database/init/01-test-db.sql). Override with TEST_DATABASE_URL if your
# MariaDB lives elsewhere.
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "mysql+aiomysql://shadowtrust:shadowtrust@127.0.0.1:3307/shadowtrust_test",
)
# Point the app's own engine at the test schema too, so anything that imports
# app.db.database picks up the test database rather than the real one.
os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)


@pytest.fixture(autouse=True)
def clean_provider_env(monkeypatch):
    """
    Every test starts with no provider configuration.

    Prevents a developer's real INFRA_PROVIDER/AWS settings from leaking into
    assertions about defaults.
    """
    for var in (
        "INFRA_PROVIDER",
        "TELEMETRY_SOURCE",
        "TELEMETRY_DIR",
        "LAB_DOCKER_NETWORK",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


# ── Shared DB fixture for the SOC-layer tests ──────────────────────────────
import asyncio as _asyncio

import pytest as _pytest
from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession, create_async_engine as _cae
from sqlalchemy.orm import sessionmaker as _sm
from sqlalchemy.pool import NullPool as _NullPool

_SOC_LOOP = None


@_pytest.fixture
def soc_db(monkeypatch):
    """
    Fresh SOC-layer tables in the MariaDB test schema on one dedicated loop.
    Yields (run, session_factory) where run(coro) drives a coroutine on the loop.
    Skips when the DB is unreachable.
    """
    global _SOC_LOOP
    from app.db.database import Base

    loop = _asyncio.new_event_loop()
    engine = _cae(os.environ["DATABASE_URL"], poolclass=_NullPool)

    async def _reset():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    try:
        loop.run_until_complete(_reset())
    except Exception as exc:
        loop.run_until_complete(engine.dispose())
        loop.close()
        _pytest.skip(f"MariaDB test DB unreachable ({exc.__class__.__name__}); run `docker compose up -d db`")

    factory = _sm(engine, class_=_AsyncSession, expire_on_commit=False)
    _SOC_LOOP = loop

    def run(coro):
        return loop.run_until_complete(coro)

    yield run, factory

    async def _drop():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    loop.run_until_complete(_drop())
    loop.run_until_complete(engine.dispose())
    loop.close()
    _SOC_LOOP = None
