from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router

import asyncio
from contextlib import asynccontextmanager

from app.db.sqlite_db import init_db
from app.services.sync_manager import SyncManager
from app.services.session_engine import SessionEngine

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing Database...")
    await init_db()
    
    # Start background tasks
    sync_task = asyncio.create_task(background_sync_loop())
    session_engine_task = asyncio.create_task(background_session_loop())
    
    yield
    
    # Clean up on shutdown
    sync_task.cancel()
    session_engine_task.cancel()

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

# CORS PROPERLY CONFIGURED
origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:5500",
    "http://localhost:5501",
    "http://localhost:5502",
    "http://localhost:5503",
    "http://localhost:5504",
    "http://localhost:5505",
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "http://127.0.0.1:5502",
    "http://127.0.0.1:5503",
    "http://127.0.0.1:5504",
    "http://127.0.0.1:5505",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Welcome to SOC-Honeynet API", "status": "running"}

app.include_router(api_router, prefix=settings.API_V1_STR)
