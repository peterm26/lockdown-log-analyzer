from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.db.database import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)

    # Make sure this is timezone-aware UTC when created
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    source = Column(String(32), index=True)
    event_type = Column(String(64), index=True)
    ip = Column(String(64), index=True, nullable=True)
    username = Column(String(128), index=True, nullable=True)
    status = Column(String(32), nullable=True)
    raw = Column(Text, nullable=False)

    # ✅ Dedup key (must be present if your parser returns it)
    fingerprint = Column(String(64), unique=True, index=True, nullable=False)