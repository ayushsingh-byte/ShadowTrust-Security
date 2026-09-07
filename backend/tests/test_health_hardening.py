"""Health / dev-route hardening (task 12)."""

import asyncio

import pytest

from app.api.v1 import dependencies as deps
from app import health_page


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_dev_bypass_fail_closed(monkeypatch):
    monkeypatch.delenv("DEV_BYPASS", raising=False)
    assert deps.dev_bypass_enabled() is False

    monkeypatch.setenv("DEV_BYPASS", "1")
    monkeypatch.setenv("INFRA_PROVIDER", "local")
    assert deps.dev_bypass_enabled() is True

    monkeypatch.setenv("INFRA_PROVIDER", "aws")
    assert deps.dev_bypass_enabled() is False   # never in a non-local deployment


def test_safe_view_strips_all_secrets():
    full = {
        "generated_at": "now",
        "backend": {"status": "up", "uptime_seconds": 5, "infra_provider": "local"},
        "database": {"status": "up", "server_version": "11", "schemas": ["shadowtrust"],
                     "url": "db:3306/shadowtrust",
                     "row_counts": {"users": 1}},
        "services": [{"name": "MariaDB", "status": "up", "link": "mysql://localhost:3307",
                      "note": "guacadmin / guacadmin"}],
        "sensors": [],
        "containers": {"available": True, "containers": [{"name": "x"}]},
        "collector": {"running": True, "cycles": 3, "last_run_at": "t", "events_ingested": 9,
                      "last_error": None, "source": "local dir /secret/path"},
        "generators": [{"cmd": "ssh -p 2222 root@localhost"}],
        "credentials": {"database": {"password": "shadowtrust_root"}},
        "event_total": 5,
    }
    safe = health_page._safe_view(full)
    blob = repr(safe)
    for secret in ("guacadmin", "shadowtrust_root", "ssh -p 2222", "/secret/path",
                   "db:3306/shadowtrust", "credentials", "generators"):
        assert secret not in blob, f"leaked: {secret}"
    # but the useful safe bits survive
    assert safe["collector"]["running"] is True
    assert safe["services"][0]["name"] == "MariaDB"
    assert safe["event_total"] == 5
    assert "row_counts" not in safe["database"]


def test_diagnostics_endpoint_is_registered_and_guarded():
    import inspect
    from app.api.v1.endpoints import diagnostics
    src = inspect.getsource(diagnostics)
    assert 'require_role(["ADMIN"])' in src
    assert "/diagnostics" in src


def test_health_disabled_by_default(monkeypatch):
    monkeypatch.delenv("HEALTH_PAGE", raising=False)
    assert _run(health_page.health_page()).status_code == 404
    assert _run(health_page.health_data()).status_code == 404


def test_health_when_enabled_has_no_secrets(monkeypatch):
    monkeypatch.setenv("HEALTH_PAGE", "1")
    body = _run(health_page.health_page()).body.decode()
    for secret in ("guacadmin", "ChangeMe123", "attack_scenarios.sh"):
        assert secret not in body
