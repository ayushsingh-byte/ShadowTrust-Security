from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router

app = FastAPI(
    title="SentinelHive AI Honeypot",
    description="AI Powered Threat Intelligence Platform",
    version="2.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# CORS PROPERLY CONFIGURED
origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:5500",
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Welcome to SOC-Honeynet API", "status": "running"}

app.include_router(api_router, prefix=settings.API_V1_STR)
