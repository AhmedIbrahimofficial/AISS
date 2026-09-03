"""AISS Platform — SQLAlchemy Async Database Layer

Supports:
  - SQLite  (default, zero setup)  → sqlite+aiosqlite:///./logs/cybersecurity.db
  - MySQL   (production)           → mysql+aiomysql://user:pass@host/db
  - PostgreSQL                     → postgresql+asyncpg://user:pass@host/db

DATABASE_URL is read from .env.  Switch databases by changing one line.
"""

import os
from typing import AsyncGenerator

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text

from core.models import Base
from utils.logger import setup_logger

load_dotenv()
logger = setup_logger("database")

# ── Connection URL ────────────────────────────────────────────────────
_RAW_URL: str = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./logs/cybersecurity.db",
)


def _make_async_url(url: str) -> str:
    """Ensure the URL uses an async driver."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("mysql://"):
        return url.replace("mysql://", "mysql+aiomysql://", 1)
    return url


DATABASE_URL = _make_async_url(_RAW_URL)
IS_SQLITE    = DATABASE_URL.startswith("sqlite")
IS_MYSQL     = DATABASE_URL.startswith("mysql")
IS_POSTGRES  = DATABASE_URL.startswith("postgresql")

# ── Engine ────────────────────────────────────────────────────────────
_connect_args = {"check_same_thread": False} if IS_SQLITE else {}

_pool_kwargs: dict = {}
if not IS_SQLITE:
    _pool_kwargs = {
        "pool_size":    5,
        "max_overflow": 10,
        "pool_recycle": 1800,
        # pool_pre_ping disabled for aiomysql — it doesn't support ping(reconnect)
        # connections are recycled every 30 min via pool_recycle instead
    }

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    connect_args=_connect_args,
    **_pool_kwargs,
)

# ── Session factory ───────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ── FastAPI dependency ────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
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
    """Create all ORM tables + the raw threats table. Safe to re-run."""
    if IS_SQLITE:
        os.makedirs("logs", exist_ok=True)

    # Register auth models on Base.metadata before create_all
    import auth.models  # noqa: F401
    import agents.models  # noqa: F401
    # Register module models so their tables are created
    try:
        import modules.network_discovery.models.discovery_models  # noqa: F401
    except Exception:
        pass

    async with engine.begin() as conn:
        if IS_SQLITE:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA foreign_keys=ON"))

        if IS_MYSQL:
            # Ensure utf8mb4 for full Unicode support
            await conn.execute(text(
                "ALTER DATABASE `aiss_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            ))

        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))
        # Raw threats table — DDL differs by backend
        if IS_MYSQL:
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS threats (
                    id                 VARCHAR(36)  NOT NULL PRIMARY KEY,
                    type               VARCHAR(64)  NOT NULL,
                    description        TEXT         NOT NULL,
                    severity           VARCHAR(16)  NOT NULL,
                    source             VARCHAR(255) NULL,
                    module             VARCHAR(64)  NULL,
                    status             VARCHAR(16)  NOT NULL DEFAULT 'active',
                    detected_at        VARCHAR(32)  NULL,
                    resolved_at        VARCHAR(32)  NULL,
                    resolution_note    TEXT         NULL,
                    metadata           LONGTEXT     NULL,
                    ai_analysis        LONGTEXT     NULL,
                    recommended_action TEXT         NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """))
        elif IS_POSTGRES:
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS threats (
                    id                 TEXT PRIMARY KEY,
                    type               TEXT NOT NULL,
                    description        TEXT NOT NULL,
                    severity           TEXT NOT NULL,
                    source             TEXT,
                    module             TEXT,
                    status             TEXT NOT NULL DEFAULT 'active',
                    detected_at        TEXT,
                    resolved_at        TEXT,
                    resolution_note    TEXT,
                    metadata           TEXT,
                    ai_analysis        TEXT,
                    recommended_action TEXT
                )
            """))
        else:
            # SQLite
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS threats (
                    id                 TEXT PRIMARY KEY,
                    type               TEXT NOT NULL,
                    description        TEXT NOT NULL,
                    severity           TEXT NOT NULL,
                    source             TEXT,
                    module             TEXT,
                    status             TEXT NOT NULL DEFAULT 'active',
                    detected_at        TEXT,
                    resolved_at        TEXT,
                    resolution_note    TEXT,
                    metadata           TEXT,
                    ai_analysis        TEXT,
                    recommended_action TEXT
                )
            """))

    db_type  = "MySQL" if IS_MYSQL else ("PostgreSQL" if IS_POSTGRES else "SQLite")
    db_label = DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL
    logger.info(f"✅ Database ready [{db_type}]: {db_label}")

    # ── SQLite: auto-add missing columns (handles schema evolution without Alembic) ──
    if IS_SQLITE:
        await _sqlite_add_missing_columns()

    # ── Seed default admin user (only if no users exist) ─────────────
    await _seed_default_admin()


async def _sqlite_add_missing_columns():
    """
    SQLite does not support ALTER TABLE ADD COLUMN IF NOT EXISTS in older versions.
    This function inspects each table and adds any missing columns defined in the ORM models.
    Runs only on SQLite. Safe to run multiple times (idempotent).
    """
    import inspect
    from sqlalchemy import inspect as sa_inspect, text

    # Columns we know need adding for auth_users (oauth migration)
    _AUTH_COLUMNS = [
        ("auth_users", "oauth_provider",       "TEXT"),
        ("auth_users", "oauth_subject",        "TEXT"),
        ("auth_users", "avatar_url",           "TEXT"),
        ("auth_users", "must_change_password", "BOOLEAN DEFAULT 0"),
    ]

    try:
        async with engine.begin() as conn:
            for table, column, col_type in _AUTH_COLUMNS:
                # Check if column exists
                result = await conn.execute(text(f"PRAGMA table_info({table})"))
                existing_cols = [row[1] for row in result.fetchall()]
                if column not in existing_cols:
                    await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                    logger.info(f"✅ SQLite migration: added column {table}.{column}")
    except Exception as e:
        logger.warning(f"SQLite column migration skipped: {e}")


async def _seed_default_admin():
    """Create a default admin account on first startup if none exists."""
    try:
        from sqlalchemy import select
        from auth.models import AuthUser
        from auth.utils.password import hash_password

        async with AsyncSessionLocal() as db:
            existing = await db.scalar(select(AuthUser).limit(1))
            if existing:
                return  # users already exist

            admin = AuthUser(
                username             = "admin",
                email                = "admin@aiss-platform.com",
                hashed_password      = hash_password("Admin123!"),
                is_verified          = True,
                is_active            = True,
                role                 = "admin",
                must_change_password = True,
            )
            db.add(admin)
            await db.commit()
            logger.info("✅ Default admin created — email: admin@aiss-platform.com  password: Admin123!")
            logger.info("⚠️  CHANGE THIS PASSWORD after first login!")
    except Exception as e:
        logger.warning(f"Admin seed skipped: {e}")


# ── Teardown ──────────────────────────────────────────────────────────
async def close_db():
    await engine.dispose()
    logger.info("🔌 Database connection pool closed")
