"""Timeline builder + evidence chain-of-custody against the test schema."""

from datetime import datetime, timedelta

from sqlalchemy import select

from app.models.all_models import (
    Detection,
    Evidence,
    Incident,
    IncidentEvent,
    NormalizedEventModel,
)
from app.services import detection_engine
from app.services.evidence_service import add_analyst_evidence, verify_evidence
from app.services.timeline_builder import build_timeline


def _seed_brute(factory, run, ip="198.51.100.7"):
    now = datetime.utcnow()
    async def _s():
        async with factory() as db:
            for i in range(7):
                db.add(NormalizedEventModel(
                    event_id=f"t-{i}", timestamp=now - timedelta(seconds=40 - i),
                    ingested_at=now, sensor="cowrie",
                    sensor_event_type="cowrie.login.failed", source_ip=ip,
                    destination_port=2222, protocol="ssh", severity="MEDIUM",
                    authentication_result="FAILURE", raw_event="{}", event_metadata={},
                ))
            await db.commit()
            await detection_engine.run_cycle(db)
    run(_s())


def test_timeline_is_ordered_and_every_entry_has_a_reason(soc_db):
    run, factory = soc_db
    _seed_brute(factory, run)

    async def _tl():
        async with factory() as db:
            inc = (await db.execute(select(Incident))).scalars().first()
            return await build_timeline(db, inc, include_splunk=False)
    tl = run(_tl())

    assert len(tl) >= 5
    stamps = [e["timestamp"] for e in tl if e["timestamp"]]
    assert stamps == sorted(stamps)                       # chronological
    assert all(e["reason"] for e in tl)                   # explainable
    assert any(e["source"] == "detection" for e in tl)    # detection is in the chain
    assert any(e["source"] == "honeypot" for e in tl)


def test_analyst_note_evidence_and_integrity(soc_db):
    run, factory = soc_db
    _seed_brute(factory, run)

    async def _add():
        async with factory() as db:
            inc = (await db.execute(select(Incident))).scalars().first()
            ev = await add_analyst_evidence(
                db, inc, etype="analyst_note", source="analyst",
                text="Confirmed brute force from a CN ASN.", added_by="a@x",
            )
            await db.commit()
            await db.refresh(ev)
            return verify_evidence(ev), ev.content_hash
    result, stored = run(_add())
    assert stored is not None
    assert result["verified"] is True
    assert result["stored_hash"] == result["recomputed_hash"]


def test_evidence_sample_endpoint_is_admin_and_clearance_gated():
    import inspect
    from app.api.v1.endpoints import evidence
    src = inspect.getsource(evidence.download_sample)
    assert 'require_role(["ADMIN"])' in src
    assert "require_clearance(3)" in src
    assert "attachment; filename" in src
