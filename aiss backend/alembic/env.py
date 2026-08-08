"""Alembic migration environment for AISS.

Supports both sync (SQLite default) and async (MySQL/PostgreSQL) databases.
DATABASE_URL is read from .env — same variable used by the app.
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

# ── Path setup ────────────────────────────────────────────────────────
# Ensure the project root is on sys.path so models can be imported
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# ── Load .env ─────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(_project_root, ".env"))
except ImportError:
    pass

# ── Import ORM metadata ───────────────────────────────────────────────
from core.models import Base   # noqa: E402 — must be after path setup
import auth.models              # noqa: F401 — register auth tables on Base
try:
    import modules.network_discovery.models.discovery_models  # noqa: F401
except Exception:
    pass

target_metadata = Base.metadata

# ── Alembic config ────────────────────────────────────────────────────
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override sqlalchemy.url from env if DATABASE_URL is set
_db_url = os.environ.get("DATABASE_URL", "sqlite:///./logs/cybersecurity.db")
# Alembic needs sync driver URLs
_sync_url = (
    _db_url
    .replace("sqlite+aiosqlite://", "sqlite:///")
    .replace("mysql+aiomysql://",   "mysql+pymysql://")
    .replace("postgresql+asyncpg://", "postgresql://")
    .replace("postgres+asyncpg://",   "postgresql://")
)
config.set_main_option("sqlalchemy.url", _sync_url)


# ── Offline mode ──────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL script)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online mode ───────────────────────────────────────────────────────
def run_migrations_online() -> None:
    """Run migrations against a live DB connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
