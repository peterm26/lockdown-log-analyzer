from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.models import Event


def ssh_business_kpis(db: Session, window_hours: int = 24):
    # Compute business KPIs related to SSH failed login attempts over a time window
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=window_hours)

    base = (
        db.query(Event)
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts < window_end,
        )
    )

    total_failed = base.count()

    unique_ips = (
        db.query(func.count(func.distinct(Event.ip)))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts < window_end,
            Event.ip.isnot(None),
        )
        .scalar() or 0
    )

    # attacks per hour
    attack_rate = total_failed / max(window_hours, 1)

    # IP counts
    ip_counts = (
        db.query(Event.ip, func.count(Event.id).label("count"))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts < window_end,
            Event.ip.isnot(None),
        )
        .group_by(Event.ip)
        .all()
    )
    high_risk_ips = sum(1 for _, c in ip_counts if c >= 10)

    # peak hour (UTC)
    peak_hour_row = (
        db.query(func.strftime("%H", Event.ts).label("hour"), func.count(Event.id).label("count"))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts < window_end,
        )
        .group_by("hour")
        .order_by(func.count(Event.id).desc())
        .first()
    )
    peak_hour = int(peak_hour_row[0]) if peak_hour_row else None

    # simple numeric risk score (easy to explain)
    risk_score = round((total_failed * 0.5) + (int(unique_ips) * 2) + (high_risk_ips * 5), 2)

    return {
        "window_hours": window_hours,
        "total_failed_attempts": total_failed,
        "unique_ips": int(unique_ips),
        "attack_rate_per_hour": round(attack_rate, 2),
        "high_risk_ips": high_risk_ips,
        "risk_score": risk_score,
        "peak_attack_hour_utc": peak_hour,
    }