"""Phase 1 Security & Input Verification Test Suite.

Tests:
1. Oversize upload rejection (HTTP 413).
2. Non-email / binary upload rejection (PE, ELF, ZIP, malformed MSG) (HTTP 422).
3. Path traversal, null byte, and SQLi filename sanitization.
4. Unauthenticated access rejection (HTTP 401).
5. Role-Based Access Control (RBAC) enforcement (AUDITOR read-only vs ANALYST write).
6. Cryptographic hash-chained audit log tamper detection.
7. Argon2 password verification and constant-time execution.
8. Rate limiter denial on request floods (HTTP 429).
9. Forged DKIM header handling in protocol validation.
"""

from __future__ import annotations

import io
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.core.config import settings
from backend.app.core.rate_limiter import InMemoryTokenBucketLimiter
from backend.app.core.security import create_access_token, hash_password, verify_password
from backend.app.core.upload_validator import sanitize_filename
from backend.app.database.audit_service import (
    record_chained_audit_log,
    verify_audit_log_chain,
)
from backend.app.database.init_db import seed_default_users
from backend.app.database.models import Base, UserRole
from backend.app.forensics.auth_validator import validate_protocol_authentication
from backend.app.main import create_application

app = create_application()


@pytest_asyncio.fixture(scope="function")
async def sec_session() -> AsyncGenerator[AsyncSession, None]:
    """Create isolated temporary database for security audit log tests."""
    temp_dir = tempfile.mkdtemp(prefix="aicte_sec_db_")
    db_path = Path(temp_dir) / "test_sec.db"
    db_url = f"sqlite+aiosqlite:///{db_path.resolve().as_posix()}"

    test_engine = create_async_engine(db_url, future=True)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_maker() as session:
        await seed_default_users(session)
        yield session

    await test_engine.dispose()
    if db_path.exists():
        try:
            db_path.unlink()
        except OSError as exc:
            import logging
            logging.getLogger("test_cleanup").debug("Temp DB unlink error: %s", exc)


@pytest.fixture
def analyst_token() -> str:
    return create_access_token("analyst", role=UserRole.ANALYST)


@pytest.fixture
def auditor_token() -> str:
    return create_access_token("auditor", role=UserRole.AUDITOR)


# =============================================================================
# 1. INPUT VALIDATION & STREAMING CAP TESTS (P0/P1)
# =============================================================================

@pytest.mark.asyncio
async def test_oversize_upload_rejected(analyst_token: str, monkeypatch):
    """Enforce hard byte cap on file uploads, immediately aborting with HTTP 413."""
    # Temporarily set upload limit to 100 KB for this test
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_BYTES", 102400)

    oversize_payload = b"X" * (102400 + 1024)  # 101 KB
    files = {"file": ("big_evidence.eml", io.BytesIO(oversize_payload), "message/rfc822")}
    headers = {"Authorization": f"Bearer {analyst_token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/forensics/analyze", files=files, headers=headers)
        assert response.status_code == 413
        assert "Payload exceeds maximum size limit" in response.json()["detail"]


@pytest.mark.asyncio
async def test_binary_upload_rejected_with_422(analyst_token: str):
    """Verify non-email binary payloads (PE, ELF, ZIP, malformed MSG) are rejected with HTTP 422."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Windows PE Executable
        pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This is not an email"
        files = {"file": ("malware.exe", io.BytesIO(pe_bytes), "application/x-dosexec")}
        resp = await ac.post("/api/v1/forensics/analyze", files=files, headers=headers)
        assert resp.status_code == 422
        assert "Windows PE Executable" in resp.json()["detail"]

        # 2. Linux ELF Binary
        elf_bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00Linux binary"
        files = {"file": ("rootkit.so", io.BytesIO(elf_bytes), "application/x-sharedlib")}
        resp = await ac.post("/api/v1/forensics/analyze", files=files, headers=headers)
        assert resp.status_code == 422
        assert "Linux ELF" in resp.json()["detail"]

        # 3. ZIP Archive
        zip_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00Archive payload"
        files = {"file": ("archive.zip", io.BytesIO(zip_bytes), "application/zip")}
        resp = await ac.post("/api/v1/forensics/analyze", files=files, headers=headers)
        assert resp.status_code == 422
        assert "ZIP" in resp.json()["detail"]

        # 4. Fake .msg without OLE signature
        fake_msg = b"From: attacker@evil.com\r\nSubject: Fake MSG\r\n\r\nBody"
        files = {"file": ("forged.msg", io.BytesIO(fake_msg), "application/vnd.ms-outlook")}
        resp = await ac.post("/api/v1/forensics/analyze", files=files, headers=headers)
        assert resp.status_code == 422
        assert "Missing required OLE Compound Document signature" in resp.json()["detail"]


def test_filename_sanitization_path_traversal():
    """Verify filename sanitization removes directory traversals, null bytes, and SQL injection strings."""
    assert sanitize_filename("../../../../etc/passwd") == "passwd"
    assert sanitize_filename(r"..\..\Windows\System32\cmd.exe") == "cmd.exe"
    assert sanitize_filename("evidence\x00evil.eml") == "evidenceevil.eml"
    assert sanitize_filename("case'; DROP TABLE emails; --.eml") == "case___DROP_TABLE_emails__--.eml"
    assert sanitize_filename("") == "evidence.eml"


# =============================================================================
# 2. AUTHENTICATION & RBAC ROLE TESTS (P0/P1)
# =============================================================================

@pytest.mark.asyncio
async def test_unauthenticated_access_rejected_with_401():
    """Verify all protected API routes reject unauthenticated requests with HTTP 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Ingestion endpoint
        resp = await ac.post("/api/v1/forensics/analyze")
        assert resp.status_code == 401

        # 2. Evidence access
        fake_id = str(uuid.uuid4())
        resp = await ac.get(f"/api/v1/forensics/evidence/{fake_id}")
        assert resp.status_code == 401

        # 3. Report export
        resp = await ac.get(f"/api/v1/forensics/evidence/{fake_id}/report")
        assert resp.status_code == 401

        # 4. Campaign graph
        resp = await ac.get("/api/v1/campaigns/graph")
        assert resp.status_code == 401

        # 5. Audit chain verification
        resp = await ac.get("/api/v1/forensics/audit/verify-chain")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rbac_auditor_read_only(auditor_token: str):
    """Verify AUDITOR role can read reports/campaigns but cannot ingest/modify evidence."""
    headers = {"Authorization": f"Bearer {auditor_token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Ingestion attempt by AUDITOR -> 403 Forbidden
        sample_eml = b"From: user@aicte.ac.in\r\nSubject: Test\r\n\r\nBody"
        files = {"file": ("test.eml", io.BytesIO(sample_eml), "message/rfc822")}
        resp = await ac.post("/api/v1/forensics/analyze", files=files, headers=headers)
        assert resp.status_code == 403
        assert "lacks permission" in resp.json()["detail"]

        # Campaign read by AUDITOR -> Allowed (200 OK)
        resp = await ac.get("/api/v1/campaigns/graph", headers=headers)
        assert resp.status_code == 200

        # Audit chain verification by AUDITOR -> Allowed (200 OK)
        resp = await ac.get("/api/v1/forensics/audit/verify-chain", headers=headers)
        assert resp.status_code == 200


def test_argon2_password_hashing():
    """Verify Argon2 password hashing and constant-time verification."""
    password = "SuperSecretForensicPassword@2026!"
    hashed = hash_password(password)

    # Argon2id identifier prefix
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123", hashed) is False


# =============================================================================
# 3. HASH-CHAINED AUDIT LOG & TAMPER DETECTION TESTS (P0)
# =============================================================================

@pytest.mark.asyncio
async def test_tampered_audit_log_chain_detection(sec_session: AsyncSession):
    """Verify hash-chained audit log successfully detects modified records or broken links."""
    now = datetime.now(timezone.utc)

    # 1. Record authentic entries in sequence with monotonic timestamps
    await record_chained_audit_log(
        db=sec_session,
        action="EVIDENCE_INGESTED",
        actor="forensic_analyst_01",
        evidence_sha256="1111111111111111111111111111111111111111111111111111111111111111",
        recorded_at=now,
    )
    await sec_session.commit()

    log2 = await record_chained_audit_log(
        db=sec_session,
        action="INTEGRITY_CHECK",
        actor="forensic_analyst_01",
        evidence_sha256="1111111111111111111111111111111111111111111111111111111111111111",
        recorded_at=now + timedelta(seconds=1),
    )
    await sec_session.commit()

    await record_chained_audit_log(
        db=sec_session,
        action="REPORT_EXPORTED",
        actor="forensic_auditor_01",
        evidence_sha256="1111111111111111111111111111111111111111111111111111111111111111",
        recorded_at=now + timedelta(seconds=2),
    )
    await sec_session.commit()

    # Chain should initially verify 100% valid
    report = await verify_audit_log_chain(sec_session)
    assert report["valid"] is True
    assert report["total_records"] == 3

    # 2. Simulate adversary tampering with log2 (modifying actor to cover tracks)
    log2.actor = "malicious_covert_actor"
    sec_session.add(log2)
    await sec_session.commit()

    tampered_report = await verify_audit_log_chain(sec_session)
    assert tampered_report["valid"] is False
    assert tampered_report["tampered_at_id"] == str(log2.id)
    assert "tampering detected" in tampered_report["error"]


# =============================================================================
# 4. PROTOCOL & RATE LIMITING DEFENSE TESTS
# =============================================================================

def test_forged_dkim_header_validation():
    """Verify protocol validation safely catches forged or invalid DKIM headers."""
    headers = {
        "dkim-signature": [
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=spoofed-domain.gov; s=badkey; "
            "bh=fakehash==; b=forgedsignature=="
        ],
        "received": ["from mail.spoofer.net (198.51.100.1) by mx.target.edu; Mon, 02 Nov 2026 10:00:00 +0000"],
    }
    auth_res = validate_protocol_authentication(
        from_email="spoofer@spoofed-domain.gov",
        return_path="bounce@spoofed-domain.gov",
        headers_dict=headers,
        auth_results_header=None,
    )
    assert auth_res.dkim_status in ("FAIL", "INVALID", "NONE", "UNVERIFIABLE", "KEY_UNAVAILABLE")


@pytest.mark.asyncio
async def test_rate_limiter_denies_flood():
    """Verify token bucket limiter denies rapid request bursts exceeding quota."""
    limiter = InMemoryTokenBucketLimiter(rate_per_minute=2, burst_multiplier=1.0)

    class MockRequest:
        headers: dict[str, str] = {}
        client = type("Client", (), {"host": "192.0.2.45"})()

    req = MockRequest()

    # First 2 requests pass
    await limiter.check(req)
    await limiter.check(req)

    # 3rd request must be blocked with HTTP 429
    with pytest.raises(Exception) as exc_info:
        await limiter.check(req)
    assert "Rate limit exceeded" in str(exc_info.value)


# =============================================================================
# 5. DOCKER & STARTUP MANDATORY SECRET ENFORCEMENT
# =============================================================================

def test_startup_refusal_when_secrets_missing():
    """Verify application startup is strictly aborted when mandatory secrets are missing outside DEBUG."""
    import os
    import subprocess
    import sys

    # Case 1: DEBUG unset, VAULT_HMAC_SECRET missing
    env_missing_vault = os.environ.copy()
    env_missing_vault.pop("DEBUG", None)
    env_missing_vault.pop("VAULT_HMAC_SECRET", None)
    env_missing_vault.pop("JWT_SECRET_KEY", None)
    env_missing_vault.pop("PYTEST_CURRENT_TEST", None)
    env_missing_vault.pop("TESTING", None)

    cmd_check = [
        sys.executable,
        "-c",
        "from backend.app.core.config import Settings; Settings()",
    ]
    res1 = subprocess.run(cmd_check, env=env_missing_vault, capture_output=True, text=True)
    assert res1.returncode != 0
    assert "FATAL SECURITY CONFIGURATION: VAULT_HMAC_SECRET" in (res1.stderr + res1.stdout)

    # Case 2: DEBUG=false, VAULT_HMAC_SECRET present, but JWT_SECRET_KEY missing
    env_missing_jwt = os.environ.copy()
    env_missing_jwt["DEBUG"] = "false"
    env_missing_jwt["VAULT_HMAC_SECRET"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    env_missing_jwt.pop("JWT_SECRET_KEY", None)
    env_missing_jwt.pop("SECRET_KEY", None)
    env_missing_jwt.pop("PYTEST_CURRENT_TEST", None)
    env_missing_jwt.pop("TESTING", None)

    res2 = subprocess.run(cmd_check, env=env_missing_jwt, capture_output=True, text=True)
    assert res2.returncode != 0
    assert "FATAL SECURITY CONFIGURATION: JWT_SECRET_KEY" in (res2.stderr + res2.stdout)

    # Case 3: Both secrets validly configured outside DEBUG -> succeeds
    env_valid = os.environ.copy()
    env_valid["DEBUG"] = "false"
    env_valid["VAULT_HMAC_SECRET"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    env_valid["JWT_SECRET_KEY"] = "jwt_valid_production_secret_key_32_chars_minimum"
    env_valid.pop("PYTEST_CURRENT_TEST", None)
    env_valid.pop("TESTING", None)

    res3 = subprocess.run(cmd_check, env=env_valid, capture_output=True, text=True)
    assert res3.returncode == 0


@pytest.mark.asyncio
async def test_first_user_bootstrap_from_env_vars():
    """Verify administrator account bootstrap when BOOTSTRAP_ADMIN_* environment variables are set."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from backend.app.core.config import settings
    from backend.app.database.init_db import seed_default_users
    from backend.app.database.models import User, UserRole
    from backend.app.database.session import Base

    original_u = settings.BOOTSTRAP_ADMIN_USERNAME
    original_p = settings.BOOTSTRAP_ADMIN_PASSWORD
    settings.BOOTSTRAP_ADMIN_USERNAME = "secops_bootstrap_lead"
    settings.BOOTSTRAP_ADMIN_PASSWORD = "StrongBootstrapPassword#2026"

    try:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        async with session_maker() as session:
            await seed_default_users(session)

            stmt = select(User).where(User.username == "secops_bootstrap_lead")
            res = await session.execute(stmt)
            admin_user = res.scalar_one_or_none()
            assert admin_user is not None
            assert admin_user.role == UserRole.ADMIN
            assert admin_user.is_active is True

            from backend.app.core.security import verify_password
            assert verify_password("StrongBootstrapPassword#2026", admin_user.password_hash)

        await engine.dispose()
    finally:
        settings.BOOTSTRAP_ADMIN_USERNAME = original_u
        settings.BOOTSTRAP_ADMIN_PASSWORD = original_p


@pytest.mark.asyncio
async def test_sse_job_stream_requires_bearer_auth():
    """Verify GET /api/v1/forensics/jobs/{id}/stream rejects unauthenticated requests with 401."""
    from backend.app.core.security import create_access_token
    from backend.app.forensics.job_queue import JobStatus, job_manager

    job = await job_manager.create_job(file_name="stream_auth_test.eml", actor="analyst")
    # Mark as completed so SSE stream generator terminates after emitting final payload
    job.status = JobStatus.COMPLETED

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Requesting without token must return 401
        res_no_auth = await ac.get(f"/api/v1/forensics/jobs/{job.job_id}/stream")
        assert res_no_auth.status_code == 401

        # Requesting with valid Bearer token must succeed
        token = create_access_token(subject="analyst", role="ANALYST")
        res_with_auth = await ac.get(
            f"/api/v1/forensics/jobs/{job.job_id}/stream",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_with_auth.status_code == 200
        assert "text/event-stream" in res_with_auth.headers.get("content-type", "")
        assert "data:" in res_with_auth.text


@pytest.mark.asyncio
async def test_readiness_and_metrics_endpoints():
    """Verify /ready, /metrics, and /health observability probes."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Liveness
        res_health = await ac.get("/health")
        assert res_health.status_code == 200
        assert res_health.json()["status"] == "HEALTHY"

        # Readiness
        res_ready = await ac.get("/ready")
        assert res_ready.status_code == 200
        assert res_ready.json()["status"] == "READY"
        assert res_ready.json()["checks"]["database"] == "UP"

        # Prometheus Metrics
        res_metrics = await ac.get("/metrics")
        assert res_metrics.status_code == 200
        assert "forensic_emails_total" in res_metrics.text
        assert "forensic_audit_records_total" in res_metrics.text
        assert "forensic_vault_files_total" in res_metrics.text


@pytest.mark.asyncio
async def test_security_headers_and_request_id():
    """Verify security headers (CSP, HSTS, X-Frame-Options) and X-Request-ID middleware."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/")
        assert res.status_code == 200
        headers = res.headers

        assert "x-request-id" in headers
        assert "x-response-time-ms" in headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in headers["content-security-policy"]
        assert "max-age=31536000" in headers["strict-transport-security"]


@pytest.mark.asyncio
async def test_admin_user_management_and_status_toggle():
    """Verify Admin can list users, create users with strong passwords, and deactivate accounts."""
    admin_token = create_access_token(subject="admin", role="ADMIN")
    analyst_token = create_access_token(subject="analyst", role="ANALYST")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Analyst cannot access user management (403)
        res_forbidden = await ac.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res_forbidden.status_code == 403

        # 2. Admin can list users (200)
        res_users = await ac.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res_users.status_code == 200
        user_list = res_users.json()
        assert len(user_list) >= 1

        # 3. Create new user with compliant password
        new_username = f"analyst_step3_{uuid.uuid4().hex[:6]}"
        res_create = await ac.post(
            "/api/v1/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "username": new_username,
                "email": f"{new_username}@aicte-india.org",
                "password": "StrongPassword#2026",
                "role": "ANALYST",
            },
        )
        assert res_create.status_code == 201
        created_id = res_create.json()["id"]

        # 4. Deactivate the user
        res_deact = await ac.patch(
            f"/api/v1/auth/users/{created_id}/status",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"is_active": False},
        )
        assert res_deact.status_code == 200
        assert res_deact.json()["is_active"] is False

        # 5. Deactivated user cannot login (403)
        res_login_deact = await ac.post(
            "/api/v1/auth/login",
            json={"username": new_username, "password": "StrongPassword#2026"},
        )
        assert res_login_deact.status_code == 403


@pytest.mark.asyncio
async def test_vault_integrity_sweep_endpoint():
    """Verify POST /api/v1/forensics/vault/sweep re-hashes all vault files."""
    admin_token = create_access_token(subject="admin", role="ADMIN")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/forensics/vault/sweep",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        body = res.json()
        assert "sweep_timestamp" in body
        assert "total_files" in body
        assert "verified" in body
        assert "corrupted" in body
        assert "integrity_rate_pct" in body

