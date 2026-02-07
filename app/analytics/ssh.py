from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.models import Event


def ssh_summary(
    db: Session,
    window_hours: int = 24,
    top_n: int = 10,
    thresholds: list[int] = [3, 5, 10],
):
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(hours=window_hours)

    base_q = (
        db.query(Event)
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts <= window_end,
        )
    )

    total_failed = base_q.count()

    unique_ips = (
        db.query(func.count(func.distinct(Event.ip)))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts <= window_end,
            Event.ip.isnot(None),
        )
        .scalar()
    )

    # Top IPs
    top_ips_rows = (
        db.query(Event.ip, func.count(Event.id).label("count"))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts <= window_end,
            Event.ip.isnot(None),
        )
        .group_by(Event.ip)
        .order_by(func.count(Event.id).desc())
        .limit(top_n)
        .all()
    )
    top_ips = [{"ip": ip, "count": c} for ip, c in top_ips_rows]

    # By hour (UTC)
    # SQLite: strftime('%H', ts) returns hour 00-23 as string.
    hour_rows = (
        db.query(func.strftime("%H", Event.ts).label("hour"), func.count(Event.id).label("count"))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts <= window_end,
        )
        .group_by("hour")
        .order_by(func.count(Event.id).desc())
        .all()
    )
    by_hour = [{"hour": int(h), "count": c} for h, c in hour_rows if h is not None]

    # Alerts by threshold (how many IPs would trigger)
    # We compute counts per IP, then count how many meet each threshold.
    ip_counts_rows = (
        db.query(Event.ip, func.count(Event.id).label("count"))
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts <= window_end,
            Event.ip.isnot(None),
        )
        .group_by(Event.ip)
        .all()
    )
    ip_counts = [c for _, c in ip_counts_rows]
    alerts_by_threshold = {str(t): sum(1 for c in ip_counts if c >= t) for t in thresholds}

    return {
        "window": {
            "hours": window_hours,
            "start": window_start.isoformat(),
            "end": window_end.isoformat(),
        },
        "total_failed_attempts": total_failed,
        "unique_ips": int(unique_ips or 0),
        "top_ips": top_ips,
        "by_hour_utc": by_hour,
        "alerts_by_threshold": alerts_by_threshold,
    }