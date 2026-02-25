from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import Event  # make sure this import exists

def top_attackers(db: Session, window_hours: int = 24, limit: int = 5) -> dict:
    end = datetime.utcnow()
    start = end - timedelta(hours=window_hours)

    base = (
        db.query(Event)
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= start,
            Event.ts < end,
            Event.ip.isnot(None),
        )
    )

    top_ips = (
        base.with_entities(Event.ip, func.count(Event.id).label("count"))
        .group_by(Event.ip)
        .order_by(func.count(Event.id).desc())
        .limit(limit)
        .all()
    )

    return {
        "window_hours": window_hours,
        "top_attackers": [{"ip": ip, "failed_attempts": count} for ip, count in top_ips],
    }