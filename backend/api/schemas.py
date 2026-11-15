
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class SecurityEventCreate(BaseModel):
    event_type: str

    source_ip: str | None = None
    destination_ip: str | None = None

    protocol: str | None = None

    threat_score: int = 0
    severity: str = "LOW"

    detection_method: str | None = None

    description: str

    response_action: str = "NONE"
    response_status: str = "NOT_APPLICABLE"


class SecurityEventResponse(SecurityEventCreate):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
