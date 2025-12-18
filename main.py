from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(title="Lockdown Log Analyzer")
app.include_router(router)

