from __future__ import annotations

from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import Event

def _risk_level(failed_attempts: int) -> str:
    # tweak thresholds however you like
    if failed_attempts >= 20:
        return "CRITICAL"
    if failed_attempts >= 10:
        return "HIGH"
    if failed_attempts >= 5:
        return "MEDIUM"
    return "LOW"


def top_attackers(db: Session, window_hours: int = 24, limit: int = 5) -> dict:
    from app.db.models import Event  # <-- move here

    end = datetime.utcnow()
    start = end - timedelta(hours=window_hours)

    window_q = (
        db.query(Event)
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= start,
            Event.ts < end,
            Event.ip.isnot(None),
        )
    )
    ...

    # 1 query: totals (cheap aggregates)
    totals = (
        db.query(
            func.count(Event.id).label("total_failed"),
            func.count(func.distinct(Event.ip)).label("unique_ips"),
        )
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= start,
            Event.ts < end,
            Event.ip.isnot(None),
        )
        .one()
    )

    # 1 query: top attackers
    top_ips = (
        window_q.with_entities(Event.ip, func.count(Event.id).label("count"))
        .group_by(Event.ip)
        .order_by(func.count(Event.id).desc())
        .limit(limit)
        .all()
    )

    total_failed = int(totals.total_failed or 0)
    unique_ips = int(totals.unique_ips or 0)

    return {
        "window_hours": window_hours,
        "total_failed_attempts": total_failed,
        "unique_ips": unique_ips,
        "top_attackers": [
            {
                "ip": ip,
                "failed_attempts": int(count),
                "risk_level": _risk_level(int(count)),
            }
            for ip, count in top_ips
        ],
    }