"""
Cybersecurity Platform — SQLAlchemy Async Database Layer

Supports:
  - SQLite  (default, zero setup)     → sqlite+aiosqlite:///./logs/cybersecurity.db
  - PostgreSQL (production)           → postgresql+asyncpg://user:pass@host/db

DATABASE_URL is read from .env.  Switch databases by changing one line — no code changes.

Usage in routes:
    from core.database import get_db
    from sqlalchemy.ext.asyncio import AsyncSession

    @router.get("/")
    async def example(db: AsyncSession = Depends(get_db)):
        result = await db.execute(select(ThreatLog))
        ...
"""

import os
from typing import AsyncGenerator

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import event, text

from core.models import Base
from utils.logger import setup_logger

load_dotenv()
logger = setup_logger("database")

# ── Connection URL ────────────────────────────────────────────────────
# SQLite default  → works out of the box, no server needed
# PostgreSQL      → set DATABASE_URL in .env
_RAW_URL: str = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./logs/cybersecurity.db",
)

# Auto-convert bare postgres:// / postgresql:// URLs to async driver
def _make_async_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url

DATABASE_URL = _make_async_url(_RAW_URL)
IS_SQLITE    = DATABASE_URL.startswith("sqlite")

# ── Engine ────────────────────────────────────────────────────────────
_connect_args = {"check_same_thread": False} if IS_SQLITE else {}

engine = create_async_engine(
    DATABASE_URL,
    echo=False,                  # set True to log all SQL (debug only)
    pool_pre_ping=True,          # reconnect on stale connections
    connect_args=_connect_args,
    # PostgreSQL pool settings (ignored by SQLite)
    **({} if IS_SQLITE else {"pool_size": 5, "max_overflow": 10}),
)

# ── Session factory ───────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,      # keep objects usable after commit
    autoflush=False,
    autocommit=False,
)


# ── FastAPI dependency ────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yields an async DB session per request.
    Commits on success, rolls back on exception, always closes.

    Usage:
        @router.get("/")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Init — create all tables ──────────────────────────────────────────
async def init_db():
    """
    Create all tables defined in core/models.py and auth/models.py.
    Safe to call on every startup (checkfirst=True).
    """
    # Ensure logs/ directory exists for SQLite
    if IS_SQLITE:
        os.makedirs("logs", exist_ok=True)

    # Import auth models so they register on Base.metadata before create_all
    import auth.models  # noqa: F401

    async with engine.begin() as conn:
        if IS_SQLITE:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA foreign_keys=ON"))
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))

    db_label = DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL
    logger.info(f"✅ Database ready [{('SQLite' if IS_SQLITE else 'PostgreSQL')}]: {db_label}")


# ── Teardown ──────────────────────────────────────────────────────────
async def close_db():
    """Dispose the engine connection pool on app shutdown."""
    await engine.dispose()
    logger.info("🔌 Database connection pool closed")
