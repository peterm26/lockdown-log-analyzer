from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import Event
from app.detection.detectors import detect_ssh_bruteforce
from app.ingest.parser import parse_ssh_line

router = APIRouter()


# -------------------------
# Health
# -------------------------
@router.get("/")
def root():
    return {"status": "ok", "app": "lockdown-log-analyzer"}


# -------------------------
# Dev helper: insert one event
# -------------------------
@router.post("/test-event")
def create_test_event(db: Session = Depends(get_db)):
    try:
        e = Event(
            source="ssh",
            event_type="ssh_failed_password",
            ip="203.0.113.10",
            username="root",
            status="failed",
            raw="Failed password for root from 203.0.113.10 port 5555 ssh2",
        )
        db.add(e)
        db.commit()
        db.refresh(e)
        return {"inserted_id": e.id}
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {str(e)}")


# -------------------------
# List events
# -------------------------
@router.get("/events")
def list_events(
    limit: int = Query(20, ge=1, le=500),
    db: Session = Depends(get_db),
):
    rows = db.query(Event).order_by(Event.ts.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat() if r.ts else None,
            "source": r.source,
            "event_type": r.event_type,
            "ip": r.ip,
            "username": r.username,
            "status": r.status,
            "raw": r.raw,
        }
        for r in rows
    ]


# -------------------------
# Ingest: SSH auth.log -> events
# -------------------------
@router.post("/ingest/ssh")
def ingest_ssh_logs(
    db: Session = Depends(get_db),
    filename: str = "auth.log",
    max_lines: Optional[int] = Query(None, ge=1, le=200000),
):
    """
    Reads data/<filename>, parses SSH failed-password lines,
    inserts normalized Event rows.
    """
    log_path = Path(__file__).resolve().parents[2] / "data" / filename
    if not log_path.exists():
        raise HTTPException(status_code=404, detail=f"{filename} not found in data/")

    inserted = 0
    skipped = 0

    try:
        with log_path.open("r", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if max_lines is not None and i > max_lines:
                    break

                parsed = parse_ssh_line(line)
                if not parsed:
                    skipped += 1
                    continue

                db.add(Event(**parsed))
                inserted += 1

        db.commit()
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    return {
        "inserted": inserted,
        "skipped": skipped,
        "file": str(log_path.name),
        "source": "ssh",
    }


# -------------------------
# Detection: SSH brute force
# -------------------------
@router.get("/alerts/ssh-bruteforce")
def list_ssh_bruteforce_alerts(
    db: Session = Depends(get_db),
    threshold: int = Query(5, ge=1, le=500),
    window_minutes: int = Query(2, ge=1, le=120),
):
    detections = detect_ssh_bruteforce(
        db,
        threshold=threshold,
        window_minutes=window_minutes,
    )
    return {"detections": detections, "count": len(detections)}