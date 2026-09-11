from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router

import asyncio
from contextlib import asynccontextmanager

import os

from app.db.database import engine, init_db
from app.services.sync_manager import SyncManager
from app.services.session_engine import SessionEngine
from app.services.aws_telemetry_service import telemetry_engine
from app.services.telemetry.collector import local_collector
from app.services import detection_engine
from app.services import analysis_shell


def _infra_provider() -> str:
    """Which infrastructure mode this process is running in."""
    return os.getenv("INFRA_PROVIDER", "local").strip().lower()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing Database...")
    await init_db()

    from app.services import container_status
    from app.services.event_bus import event_bus

    # Start background tasks
    tasks = [
        asyncio.create_task(background_sync_loop()),
        asyncio.create_task(background_session_loop()),
        asyncio.create_task(background_detection_loop()),
        asyncio.create_task(background_analysis_reaper()),
        # Sensor container CPU/memory/network, pushed to dashboards on the "metrics" channel.
        asyncio.create_task(container_status.run_metrics_sampler(
            lambda snapshot: event_bus.publish(snapshot, channel="metrics"))),
    ]

    # Newly committed telemetry wakes the detection engine immediately.
    local_collector.add_listener(lambda _count: detection_wakeup.set())

    # Telemetry ingestion. Local mode runs the cursor-based collector, woken by
    # inotify the moment a sensor writes, so the dashboard updates while an
    # attack is happening. AWS mode keeps the original 30-second S3 poller.
    # Running both would double-ingest every event.
    if _infra_provider() == "aws":
        print("Telemetry: S3 pipeline (INFRA_PROVIDER=aws)")
        tasks.append(asyncio.create_task(telemetry_engine.run_pipeline()))
    else:
        print("Telemetry: local collector (INFRA_PROVIDER=local)")
        tasks.append(asyncio.create_task(local_collector.run_forever()))

    yield

    # Clean up on shutdown
    telemetry_engine.is_running = False
    local_collector.is_running = False
    for task in tasks:
        task.cancel()
    # Give cancelled tasks a moment to unwind so their `finally` blocks run
    # (the collector holds a DB session) instead of being dropped mid-flight.
    await asyncio.gather(*tasks, return_exceptions=True)

    # Close the connection pool while the event loop is still running, so
    # aiomysql connections aren't left for the garbage collector to reap
    # after the loop is gone ("Event loop is closed" on shutdown).
    await engine.dispose()

async def background_sync_loop():
    while True:
        try:
            await SyncManager.run_sync_cycle()
        except Exception as e:
            print(f"Background Sync Error: {e}")
        await asyncio.sleep(10) # Run every 10 seconds

async def background_session_loop():
    while True:
        try:
            await SessionEngine.process_unmapped_events()
        except Exception as e:
            print(f"Session Engine Error: {e}")
        await asyncio.sleep(60) # Run every 60 seconds


async def background_analysis_reaper():
    """Analysis Lab housekeeping — reap idle/expired sandboxes and poll each
    running sandbox for new outbound connection attempts."""
    from app.db.database import AsyncSessionLocal as _ASL
    from sqlalchemy import select as _select
    from app.models.all_models import AnalysisSession as _AS

    seen: dict = {}
    await asyncio.sleep(15)
    while True:
        try:
            async with _ASL() as db:
                await analysis_shell.reap_stale(db)
                running = (await db.execute(
                    _select(_AS).where(_AS.status == "running")
                )).scalars().all()
                for s in running:
                    await analysis_shell.poll_connections(db, s, seen.setdefault(s.session_id, set()))
                for sid in list(seen):
                    if sid not in {r.session_id for r in running}:
                        seen.pop(sid, None)
        except Exception as e:  # noqa: BLE001
            print(f"Analysis Reaper Error: {e}")
        await asyncio.sleep(30)


# Set whenever the collector commits new telemetry, so detections run within about a
# second of ingest; DETECTION_ENGINE_INTERVAL_SECONDS is only a fallback tick.
detection_wakeup = asyncio.Event()
DETECTION_DEBOUNCE_SECONDS = 0.5


async def background_detection_loop():
    """Detection + correlation engine — turns normalized events into detections
    and incidents. Extends the existing risk/sync layer, never replaces it."""
    from datetime import datetime
    from app.services.event_bus import event_bus

    try:
        interval = max(5.0, float(os.getenv("DETECTION_ENGINE_INTERVAL_SECONDS", "20")))
    except (TypeError, ValueError):
        interval = 20.0
    while True:
        try:
            summary = await detection_engine.run_cycle()
            if summary and (summary.get("detections") or summary.get("incidents")):
                event_bus.publish(
                    {**summary, "completed_at": datetime.utcnow().isoformat() + "Z"},
                    channel="detection",
                )
        except Exception as e:  # noqa: BLE001
            print(f"Detection Engine Error: {e}")
        try:
            await asyncio.wait_for(detection_wakeup.wait(), timeout=interval)
            # Coalesce a burst of ingests into one detection pass.
            await asyncio.sleep(DETECTION_DEBOUNCE_SECONDS)
        except asyncio.TimeoutError:
            pass
        detection_wakeup.clear()

app = FastAPI(
    title="Shadow Trust AI Honeypot",
    description="AI Powered Threat Intelligence Platform",
    version="2.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS.
#
# The dashboard is served from nginx on a different port than the API, so the
# browser treats API calls as cross-origin and the allowlist has to name the
# dashboard's origin explicitly.
#
# `allow_origins=["*"]` together with `allow_credentials=True` is not a valid
# combination — browsers reject a wildcard on a credentialed request, so the
# previous configuration silently failed the calls it was meant to permit.
# CORS_ORIGINS is a comma-separated list; the defaults cover the local
# dashboard on both loopback spellings.
_DEFAULT_ORIGINS = (
    "http://localhost:5500,http://127.0.0.1:5500,"
    "http://localhost:8000,http://127.0.0.1:8000"
)
_cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

from app.api.v1.endpoints.attacks_api import router as attacks_router
from app.api.v1.endpoints.honeypots_api import router as honeypots_router

app.include_router(attacks_router, prefix="/api/attacks", tags=["attacks"])
app.include_router(honeypots_router, prefix="/api/honeypots", tags=["honeypots"])

# Local operator status page — GET /health (unauthenticated, prints credentials;
# see app/health_page.py). Disable with HEALTH_PAGE=0.
from app.health_page import router as health_router

app.include_router(health_router, tags=["health"])

@app.get("/")
def root():
    return {"message": "Welcome to SOC-Honeynet API", "status": "running"}
