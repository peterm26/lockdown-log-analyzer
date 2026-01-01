from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.db.database import Base

#the Event model is the security event log entry.
class Event(Base):
    """security event log entry."""
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    source = Column(String(32), index=True)           # "ssh", "nginx"
    event_type = Column(String(64), index=True)       # "ssh_failed_password"
    ip = Column(String(64), index=True, nullable=True)
    username = Column(String(128), index=True, nullable=True)
    status = Column(String(32), nullable=True)        # "failed", "success"
    raw = Column(Text, nullable=False)