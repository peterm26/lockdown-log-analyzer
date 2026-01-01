from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker, declarative_base

#the engine is the connection to the database, sessionmaker creates isolated transaction scopes,
# get_db is the dependency for the database session.

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "sentinel.db" #where the database lives
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine( #create the engine
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)

# Enable WAL mode for better concurrent access
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)#create the session
Base = declarative_base()#create the base


def get_db() -> Generator[Session, None, None]:
    """database session dependency for fastapi."""
    db = SessionLocal()#create the session
    try:
        yield db#yield the session
    finally:
        db.close()#close the session
