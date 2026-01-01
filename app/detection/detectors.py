from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.db.models import Event


# -------------------------
# Detection: SSH brute force
# -------------------------
def detect_ssh_bruteforce(db: Session, threshold: int = 5, window_minutes: int = 2):
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(minutes=window_minutes)

    events = (
        db.query(Event)
        .filter(
            Event.event_type == "ssh_failed_password",
            Event.ts >= window_start,
            Event.ts <= window_end,
        )
        .all()
    )

    counts = {}
    for e in events:
        if e.ip:
            counts[e.ip] = counts.get(e.ip, 0) + 1

    detected = []
    for ip, c in counts.items():
        if c >= threshold:
            detected.append({
                "ip": ip,
                "count": c,
                "threshold": threshold,
                "window_minutes": window_minutes,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
            })

    detected.sort(key=lambda d: d["count"], reverse=True)
    return detected