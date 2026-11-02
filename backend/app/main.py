"""FastAPI Application Entry Point for AICTE Forensic Intelligence Platform.

SIH Problem Statement ID: 26106
"AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.database.session import close_database, create_all_tables
from backend.app.database.vault import get_vault_dir

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aicte_forensics_api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for database initialization and graceful shutdown."""
    logger.info("Initializing AICTE Cyber Security Platform (SIH ID: %s)...", settings.SIH_PROBLEM_ID)
    # Ensure evidence vault directory exists
    vault_dir = get_vault_dir()
    logger.info("Evidence vault initialized at: %s", vault_dir)

    # Verify and create all database tables
    await create_all_tables()
    logger.info("Database schemas verified.")

    yield

    logger.info("Disposing database connections during shutdown...")
    await close_database()
    logger.info("Application shutdown complete.")


def create_application() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.PROJECT_VERSION,
        description=(
            "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform "
            "engineered for the AICTE Cyber Security Cell (SIH Problem Statement ID: 26106). "
            "Features protocol inspection (SPF/DKIM/DMARC), reverse hop-traversal, Tor/OSINT detection, "
            "AI BEC content analysis, and Section 63 BSA 2023 court-admissible PDF generation."
        ),
        lifespan=lifespan,
    )

    # Configure CORS explicitly for Next.js frontend access
    explicit_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    application.add_middleware(
        CORSMiddleware,
        allow_origins=explicit_origins,
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition", "X-Evidence-SHA256", "X-Statutory-Authority"],
    )

    # Master v1 Router
    application.include_router(api_router, prefix=settings.API_V1_STR)

    @application.get("/", tags=["Health & Status"])
    async def root():
        return {
            "platform": settings.PROJECT_NAME,
            "version": settings.PROJECT_VERSION,
            "problem_statement_id": settings.SIH_PROBLEM_ID,
            "status": "OPERATIONAL",
            "statutory_compliance": "Section 63 Bharatiya Sakshya Adhiniyam, 2023",
            "docs_url": "/docs",
        }

    @application.get(f"{settings.API_V1_STR}/health", tags=["Health & Status"])
    async def health_check():
        return {
            "status": "HEALTHY",
            "vault_dir": str(settings.VAULT_DIR_PATH),
            "database_engine": "SQLite 3 (WAL)" if "sqlite" in settings.DATABASE_URL else "PostgreSQL 16",
            "scoring_formula": "Score = 0.25*Auth + 0.20*Header + 0.20*NLP + 0.15*URL + 0.10*OSINT + 0.10*Attach",
        }

    return application


app = create_application()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)

