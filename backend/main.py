
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.database import Base, engine, get_db
from backend.database.models import SecurityEvent
from backend.api.schemas import (
    SecurityEventCreate,
    SecurityEventResponse
)


# Create database tables when the application starts.
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="SENTINAL IDS",
    description="AI Intrusion Defense System - Phase 1",
    version="0.1.0",
    lifespan=lifespan
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


@app.post(
    "/api/events",
    response_model=SecurityEventResponse,
    status_code=201
)
def create_event(
    event: SecurityEventCreate,
    db: Session = Depends(get_db)
):
    try:
        new_event = SecurityEvent(**event.model_dump())

        db.add(new_event)
        db.commit()
        db.refresh(new_event)

        return new_event

    except Exception as error:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not save security event."
        )


@app.get("/api/events", response_model=list[SecurityEventResponse])
def get_events(db: Session = Depends(get_db)):
    return (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.id.desc())
        .all()
    )
