from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.api.routes import router

from app.db.database import engine, Base
from app.db import models  # IMPORTANT: registers Event model

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(title="Lockdown Log Analyzer", lifespan=lifespan)
app.include_router(router)