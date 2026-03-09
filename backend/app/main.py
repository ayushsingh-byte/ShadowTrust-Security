from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router

import asyncio
from contextlib import asynccontextmanager

from app.db.sqlite_db import init_db
from app.services.sync_manager import SyncManager
from app.services.session_engine import SessionEngine
from app.services.aws_telemetry_service import telemetry_engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing Database...")
    await init_db()
    
    # Start background tasks
    sync_task = asyncio.create_task(background_sync_loop())
    session_engine_task = asyncio.create_task(background_session_loop())
    telemetry_task = asyncio.create_task(telemetry_engine.run_pipeline())
    
    yield
    
    # Clean up on shutdown
    sync_task.cancel()
    session_engine_task.cancel()
    telemetry_engine.is_running = False
    telemetry_task.cancel()

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

app = FastAPI(
    title="Shadow Trust AI Honeypot",
    description="AI Powered Threat Intelligence Platform",
    version="2.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS — allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

from app.api.v1.endpoints.attacks_api import router as attacks_router
from app.api.v1.endpoints.honeypots_api import router as honeypots_router

app.include_router(attacks_router, prefix="/api/attacks", tags=["attacks"])
app.include_router(honeypots_router, prefix="/api/honeypots", tags=["honeypots"])

@app.get("/")
def root():
    return {"message": "Welcome to SOC-Honeynet API", "status": "running"}
