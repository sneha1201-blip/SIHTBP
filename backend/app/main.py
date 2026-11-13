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

    # Seed foundational RBAC accounts
    from backend.app.database.init_db import seed_default_users
    from backend.app.database.session import async_session_factory

    async with async_session_factory() as session:
        await seed_default_users(session)
    logger.info("Foundational RBAC user accounts verified.")

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

    # 1. Request ID and Security Headers Middleware
    @application.middleware("http")
    async def security_and_tracing_middleware(request, call_next):
        import time
        import uuid

        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Attach Tracing and Security Headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-MS"] = str(duration_ms)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
            "connect-src 'self' http://localhost:* http://127.0.0.1:* ws: wss:; frame-ancestors 'none';"
        )

        return response

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

    @application.get("/health", tags=["Health & Status"])
    @application.get(f"{settings.API_V1_STR}/health", tags=["Health & Status"])
    async def health_check():
        return {
            "status": "HEALTHY",
            "vault_dir": str(settings.VAULT_DIR_PATH),
            "database_engine": "SQLite 3 (WAL)" if "sqlite" in settings.DATABASE_URL else "PostgreSQL 16",
            "scoring_formula": "Score = 0.25*Auth + 0.20*Header + 0.20*NLP + 0.15*URL + 0.10*OSINT + 0.10*Attach",
        }

    @application.get("/ready", tags=["Health & Status"])
    async def readiness_probe():
        """Readiness probe checking database connectivity, vault write access, and model loading."""
        from fastapi import status as http_status
        from fastapi.responses import JSONResponse
        from sqlalchemy import text

        from backend.app.ai.nlp_engine import get_or_load_model
        from backend.app.database.session import async_session_factory

        errors = []
        # 1. DB connectivity
        try:
            async with async_session_factory() as session:
                await session.execute(text("SELECT 1"))
        except Exception as exc:
            errors.append(f"Database unavailable: {exc}")

        # 2. Vault write access
        try:
            vault_dir = get_vault_dir()
            test_file = vault_dir / ".ready_check"
            test_file.write_bytes(b"READY")
            if test_file.exists():
                test_file.unlink()
        except Exception as exc:
            errors.append(f"Vault storage unwriteable: {exc}")

        # 3. Model pipeline loaded
        try:
            model = get_or_load_model()
            if not hasattr(model, "predict"):
                errors.append("AI threat model pipeline not loaded")
        except Exception as exc:
            errors.append(f"AI model initialization failed: {exc}")

        if errors:
            return JSONResponse(
                status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "NOT_READY", "errors": errors},
            )

        return {"status": "READY", "checks": {"database": "UP", "vault": "UP", "ai_model": "UP"}}

    @application.get("/metrics", tags=["Health & Status"])
    async def prometheus_metrics():
        """Prometheus metrics endpoint reporting system and forensic telemetry."""
        from fastapi.responses import PlainTextResponse
        from sqlalchemy import func, select

        from backend.app.database.models import Email, EvidenceAuditLog
        from backend.app.database.session import async_session_factory

        async with async_session_factory() as session:
            email_count = (await session.execute(select(func.count()).select_from(Email))).scalar() or 0
            audit_count = (await session.execute(select(func.count()).select_from(EvidenceAuditLog))).scalar() or 0

        vault_files_count = len(list(get_vault_dir().glob("*.raw")))

        metrics_text = f"""# HELP forensic_emails_total Total ingested forensic emails
# TYPE forensic_emails_total counter
forensic_emails_total {email_count}

# HELP forensic_audit_records_total Total chained audit log records
# TYPE forensic_audit_records_total counter
forensic_audit_records_total {audit_count}

# HELP forensic_vault_files_total Total physical raw evidence files stored in WORM vault
# TYPE forensic_vault_files_total gauge
forensic_vault_files_total {vault_files_count}

# HELP forensic_platform_info Build and version metadata
# TYPE forensic_platform_info gauge
forensic_platform_info{{version="{settings.PROJECT_VERSION}",problem_id="{settings.SIH_PROBLEM_ID}"}} 1
"""
        return PlainTextResponse(content=metrics_text, media_type="text/plain; version=0.0.4")

    return application


app = create_application()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
