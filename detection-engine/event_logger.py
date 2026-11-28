
from backend.database.database import SessionLocal
from backend.database.models import SecurityEvent


def save_security_event(event_data):
    """
    Save a detected security event to the SENTINAL SQLite database.

    Args:
        event_data (dict): Normalized security event information.

    Returns:
        int: ID of the newly created database event.
    """

    db = SessionLocal()

    try:
        security_event = SecurityEvent(
            event_type=event_data["event_type"],
            source_ip=event_data.get("source_ip"),
            destination_ip=event_data.get("destination_ip"),
            protocol=event_data.get("protocol"),
            threat_score=event_data.get("threat_score", 0),
            severity=event_data.get("severity", "LOW"),
            detection_method=event_data.get("detection_method"),
            description=event_data["description"],
            response_action=event_data.get("response_action", "NONE"),
            response_status=event_data.get(
                "response_status",
                "NOT_APPLICABLE"
            )
        )

        db.add(security_event)
        db.commit()
        db.refresh(security_event)

        return security_event.id

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
