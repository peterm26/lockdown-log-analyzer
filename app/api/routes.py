from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Event

router = APIRouter()

@router.get("/")
def root():
    return {"status": "ok", "app": "lockdown-log-analyzer"}

@router.post("/test-event")
def create_test_event(db: Session = Depends(get_db)):
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

@router.get("/events")
def list_events(limit: int = 20, db: Session = Depends(get_db)):
    rows = db.query(Event).order_by(Event.ts.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "source": r.source,
            "event_type": r.event_type,
            "ip": r.ip,
            "username": r.username,
            "status": r.status,
            "raw": r.raw,
        }
        for r in rows
    ]