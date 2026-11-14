
from fastapi import FastAPI

app = FastAPI(
    title="SENTINAL IDS",
    description="AI Intrusion Defense System - Phase 1",
    version="0.1.0"
)


@app.get("/")
async def root():
    return {
        "system": "SENTINAL",
        "message": "Intrusion Detection System is running",
        "phase": "Phase 1"
    }


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "system": "SENTINAL",
        "backend": "FastAPI"
    }
