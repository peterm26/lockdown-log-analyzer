from __future__ import annotations

from datetime import datetime, timezone, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import Event

def _window_counts(db: Session, start: datetime, end: datetime):
    base = (
        db.query(Event)
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= start,
            Event.ts < end,
        )
    )

    total_failed = base.count()

    unique_ips = (
        db.query(func.count(func.distinct(Event.ip)))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= start,
            Event.ts < end,
            Event.ip.isnot(None),
        )
        .scalar() or 0
    )

    ip_counts = (
        db.query(Event.ip, func.count(Event.id).label("count"))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= start,
            Event.ts < end,
            Event.ip.isnot(None),
        )
        .group_by(Event.ip)
        .all()
    )

    high_risk_ips = sum(1 for _, c in ip_counts if c >= 10)

    # risk score (simple formula we used prior)
    risk_score = round((total_failed *.5) + (int(unique_ips) * 2) + (high_risk_ips * 5), 2)
    
    attack_rate_per_hour = round(total_failed/max(((end-start).total_seconds() / 3600), 1), 2)

    return {
        "total_failed_attempts": total_failed,
        "unique_ips": int(unique_ips),
        "high_risk_ips": high_risk_ips,
        "attack_rate_per_hour": float(attack_rate_per_hour),
        "risk_score": float(risk_score),
    }

def _pct_change(curr: float, prev: float) -> float | None:
        if prev == 0:
            return None if curr != 0 else 0.0
        return round (((curr - prev) / prev) * 100.0, 2)
    
def ssh_trends(db: Session, window_hours: int = 24) -> dict:
        now = datetime.now(timezone.utc)

        curr_end = now
        curr_start = curr_end - timedelta(hours=window_hours)

        prev_end = curr_start
        prev_start = prev_end - timedelta(hours=window_hours)

        curr = _window_counts(db, curr_start, curr_end)
        prev = _window_counts(db, prev_start, prev_end)

        deltas = {
            k: {
                "current": curr[k],
                "previous": prev[k],
                "pct_change": _pct_change(float(curr[k]), float(prev[k])),
            }
            for k in curr.keys()
        }

        return {
            "window_hours": window_hours,
            "current_window": {
                "start": curr_start.isoformat(), "end": curr_end.isoformat()},
            "previous_window": {
                "start": prev_start.isoformat(), "end": prev_end.isoformat()},
                "metrics": deltas,
            }

