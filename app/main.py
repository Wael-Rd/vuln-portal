import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.database import init_db, engine
from app.routers import api as api_router
from app.routers import web as web_router
from app.auth import router as auth_router
from app.ingestion.ingest import ingest_once

app = FastAPI(title=settings.app_name)

# Sessions
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

# Static and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
app.state.templates = templates

# Routers
app.include_router(auth_router)
app.include_router(api_router.router)
app.include_router(web_router.router)


@app.on_event("startup")
async def on_startup():
    init_db()

    # Optionally run an immediate ingestion on startup (in background)
    async def startup_ingest():
        from sqlmodel import Session
        with Session(engine) as session:
            await ingest_once(session)

    asyncio.create_task(startup_ingest())

    if settings.scheduler_enabled:
        scheduler = AsyncIOScheduler(timezone=settings.timezone)
        scheduler.add_job(
            func=lambda: _scheduled_ingestion(),
            trigger=IntervalTrigger(minutes=settings.ingest_interval_minutes),
            id="ingest",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        scheduler.start()
        app.state.scheduler = scheduler


async def _scheduled_ingestion():
    from sqlmodel import Session
    with Session(engine) as session:
        await ingest_once(session)


@app.get("/healthz")
def health():
    return {"status": "ok", "app": settings.app_name}