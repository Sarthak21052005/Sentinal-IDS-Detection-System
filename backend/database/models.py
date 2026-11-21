
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func

from backend.database.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    event_type = Column(String(100), nullable=False, index=True)

    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)

    protocol = Column(String(20), nullable=True)

    threat_score = Column(Integer, default=0, nullable=False)
    severity = Column(String(20), default="LOW", nullable=False, index=True)

    detection_method = Column(String(100), nullable=True)

    description = Column(Text, nullable=False)

    response_action = Column(String(100), default="NONE")
    response_status = Column(String(100), default="NOT_APPLICABLE")
