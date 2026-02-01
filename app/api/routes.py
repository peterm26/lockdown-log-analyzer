from typing import Optional
from pathlib import Path
import hashlib
from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.detection.detectors import detect_ssh_bruteforce
from app.db.database import get_db
from app.db.models import Event
from app.ingest.parser import parse_ssh_line

from app.analytics.ssh import ssh_summary

from app.analytics.kpis import ssh_business_kpis

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
def create_test_event(
    db: Session = Depends(get_db),
    repeat: bool = Query(False),
):
    try:
        raw_line = "Failed password for root from 203.0.113.10 port 5555 ssh2"
        ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc) if repeat else datetime.now(timezone.utc)

        fp_src = (
            f"{ts.isoformat()}|ssh|ssh_failed_password|"
            f"203.0.113.10|root|failed|{raw_line.strip()}"
        )
        fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

        e = Event(
            ts=ts,
            source="ssh",
            event_type="ssh_failed_password",
            ip="203.0.113.10",
            username="root",
            status="failed",
            raw=raw_line,
            fingerprint=fingerprint,
        )
        db.add(e)
        db.commit()
        db.refresh(e)
        return {"inserted_id": e.id, "repeat": repeat}
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Duplicate test event (fingerprint already exists)")
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
    # Security: Prevent path traversal attacks
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    data_dir = Path(__file__).resolve().parents[2] / "data"
    log_path = data_dir / filename
    
    # Ensure the resolved path is still within data directory
    try:
        log_path.resolve().relative_to(data_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    if not log_path.exists():
        raise HTTPException(status_code=404, detail=f"{filename} not found in data/")

    inserted = 0
    skipped = 0
    duplicates = 0

    try:
        with log_path.open("r", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if max_lines is not None and i > max_lines:
                    break

                parsed = parse_ssh_line(line)
                if not parsed:
                    skipped += 1
                    continue

                try:
                    db.add(Event(**parsed))
                    db.flush()  # forces UNIQUE fingerprint check now
                    inserted += 1
                except IntegrityError:
                    db.rollback()  # clears failed insert state
                    duplicates += 1

        db.commit()

    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    return {
        "inserted": inserted,
        "duplicates": duplicates,
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

# -------------------------
# Analytics: SSH summary
# -------------------------
@router.get("/analytics/ssh-summary")
def analytics_ssh_summary(
    db: Session = Depends(get_db),
    window_hours: int = Query(24, ge=1, le=168),
    top_n: int = Query(10, ge=1, le=50),
):
    return ssh_summary(db, window_hours=window_hours, top_n=top_n)

# -------------------------
# Analytics: SSH business KPIs
# -------------------------
@router.get("/analytics/ssh-kpis")
def analytics_ssh_kpis(
    db: Session = Depends(get_db),
    window_hours: int = Query(24, ge=1, le=168),
):
    return ssh_business_kpis(db, window_hours=window_hours)