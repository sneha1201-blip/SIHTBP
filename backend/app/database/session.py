"""Database Session and Engine Management for AICTE Forensic Intelligence Platform.

Provides a unified SQLAlchemy 2.0 asyncio layer supporting:
1. Default zero-setup local SQLite 3 (`aiosqlite`) with WAL mode and foreign key enforcement.
2. Enterprise PostgreSQL 16 (`asyncpg`) with production connection pooling.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# Define base paths
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
STORAGE_DIR = PROJECT_ROOT / "storage"
DEFAULT_SQLITE_PATH = STORAGE_DIR / "forensic_platform.db"


class Base(AsyncAttrs, DeclarativeBase):
    """Declarative Base class for all ORM models with async attribute support."""
    pass


def resolve_database_url() -> str:
    """Resolve and normalize the database connection URL.

    Defaults to SQLite 3 (via aiosqlite) for instant local hackathon execution,
    while seamlessly adapting to PostgreSQL 16 (via asyncpg) when DATABASE_URL is set.
    """
    url = os.getenv("DATABASE_URL", "").strip()

    if not url:
        # Zero-setup local SQLite 3 database path
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        sqlite_file = DEFAULT_SQLITE_PATH.resolve().as_posix()
        return f"sqlite+aiosqlite:///{sqlite_file}"

    # Normalize PostgreSQL URL schemes
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    # Normalize SQLite URL schemes
    if url.startswith("sqlite://") and not url.startswith("sqlite+aiosqlite://"):
        url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)

    return url


DATABASE_URL = resolve_database_url()
IS_SQLITE = DATABASE_URL.startswith("sqlite")

# Configure engine arguments based on dialect
engine_kwargs = {
    "echo": os.getenv("SQL_ECHO", "false").lower() in ("true", "1", "yes"),
    "future": True,
}

if IS_SQLITE:
    # SQLite-specific optimization arguments
    engine_kwargs["connect_args"] = {
        "timeout": 60.0,
        "check_same_thread": False,
    }
else:
    # PostgreSQL enterprise production connection pooling
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "20")),
        "pool_pre_ping": True,
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "3600")),
    })

# Global Async Engine
engine: AsyncEngine = create_async_engine(DATABASE_URL, **engine_kwargs)


# Attach SQLite PRAGMAs for foreign keys, WAL mode, and sync optimization
if IS_SQLITE:
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            # Enforce foreign key constraints
            cursor.execute("PRAGMA foreign_keys = ON;")
            # Enable Write-Ahead Logging for high-concurrency read/write operations
            cursor.execute("PRAGMA journal_mode = WAL;")
            # Set synchronous to NORMAL for balanced safety & disk I/O performance
            cursor.execute("PRAGMA synchronous = NORMAL;")
            # Increase busy timeout to 60 seconds to prevent file locking contention
            cursor.execute("PRAGMA busy_timeout = 60000;")
        except Exception:
            pass
        finally:
            cursor.close()


# Async sessionmaker factory
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Context manager yielding an AsyncSession with automatic commit/rollback."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI-compatible dependency providing an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_all_tables() -> None:
    """Create all registered database tables if they do not already exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_all_tables() -> None:
    """Drop all tables defined in Base.metadata (useful for clean test environments)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def reset_database() -> None:
    """Drop and recreate all database tables."""
    await drop_all_tables()
    await create_all_tables()


async def close_database() -> None:
    """Properly dispose of database connection pools during application shutdown."""
    await engine.dispose()

