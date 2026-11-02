"""Comprehensive Unit and Integration Tests for AICTE Forensic Database Layer.

Validates:
1. Cryptographic Evidence Vault (SHA-256/MD5 hashing, WORM immutability, HMAC-SHA256 audit ledger).
2. SQLAlchemy 2.0 ORM Models & Relationships (Cascade deletes, UUID PKs, JSON attributes).
3. Forensic Seed Cases & Attribution (5 demo cases, Threat scores, IOC links, Campaign clustering).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from backend.app.database.models import (
    Campaign,
    CampaignEmail,
    Email,
    EvidenceAuditLog,
    ForensicAnalysis,
    HeaderHop,
    ThreatIndicator,
)
from backend.app.database.seed_data import seed_forensic_database
from backend.app.database.session import Base
from backend.app.database.vault import (
    calculate_hashes,
    canonicalize_audit_payload,
    generate_hmac_signature,
    read_raw_evidence,
    store_raw_evidence,
    verify_evidence_integrity,
    verify_hmac_signature,
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def test_session():
    """Create an isolated temporary SQLite database for each test function."""
    temp_dir = tempfile.mkdtemp(prefix="aicte_test_db_")
    db_path = Path(temp_dir) / "test_forensic.db"
    db_url = f"sqlite+aiosqlite:///{db_path.resolve().as_posix()}"

    test_engine = create_async_engine(db_url, future=True)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_maker() as session:
        yield session

    await test_engine.dispose()
    try:
        if db_path.exists():
            db_path.unlink()
    except Exception:
        pass


# =============================================================================
# 1. CRYPTOGRAPHIC EVIDENCE VAULT TESTS
# =============================================================================

def test_hash_calculation():
    """Verify SHA-256 and MD5 hash calculations against known vectors."""
    test_bytes = b"AICTE Cyber Security Cell - Forensic Evidence Stream Test"
    expected_sha256 = hashlib.sha256(test_bytes).hexdigest()
    expected_md5 = hashlib.md5(test_bytes).hexdigest()

    computed_sha256, computed_md5 = calculate_hashes(test_bytes)
    assert computed_sha256 == expected_sha256
    assert computed_md5 == expected_md5


def test_vault_store_and_read(tmp_path):
    """Test storing raw email bytes under {sha256}.raw and reading with integrity check."""
    sample_eml = b"From: test@aicte-india.org\r\nSubject: Test\r\n\r\nSample body content"
    sha256, md5, stored_path, size = store_raw_evidence(sample_eml, vault_dir=tmp_path)

    assert Path(stored_path).exists()
    assert Path(stored_path).name == f"{sha256}.raw"
    assert size == len(sample_eml)

    retrieved = read_raw_evidence(sha256, vault_dir=tmp_path)
    assert retrieved == sample_eml

    report = verify_evidence_integrity(sha256, vault_dir=tmp_path)
    assert report["exists"] is True
    assert report["intact"] is True
    assert report["computed_sha256"] == sha256


def test_vault_tamper_detection(tmp_path):
    """Test that tampering with stored raw evidence is detected immediately."""
    sample_eml = b"Authentic untampered evidence bytes."
    sha256, _, stored_path, _ = store_raw_evidence(sample_eml, vault_dir=tmp_path)

    # Maliciously modify the file on disk
    file_path = Path(stored_path)
    # Remove read-only attribute if on Windows
    os.chmod(file_path, 0o666)
    with open(file_path, "wb") as f:
        f.write(b"Tampered hostile payload bytes!")

    # Reading should fail cryptographic verification
    with pytest.raises(ValueError, match="Cryptographic integrity violation"):
        read_raw_evidence(sha256, vault_dir=tmp_path)

    report = verify_evidence_integrity(sha256, vault_dir=tmp_path)
    assert report["exists"] is True
    assert report["intact"] is False


def test_hmac_signatures():
    """Verify HMAC-SHA256 generation, verification, and tamper rejection."""
    payload = canonicalize_audit_payload(
        actor="FORENSIC_OFFICER_01",
        action="EVIDENCE_EXPORT",
        evidence_sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        recorded_at=datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc),
        details={"case": "AICTE-26106"},
    )

    signature = generate_hmac_signature(payload)
    assert len(signature) == 64  # SHA-256 hex string

    # Authentic signature verifies
    assert verify_hmac_signature(payload, signature) is True

    # Tampered payload fails
    tampered_payload = payload.replace("FORENSIC_OFFICER_01", "ROGUE_ACTOR")
    assert verify_hmac_signature(tampered_payload, signature) is False

    # Tampered signature fails
    assert verify_hmac_signature(payload, "0" * 64) is False


# =============================================================================
# 2. ORM MODELS & RELATIONSHIP TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_email_crud_and_cascade(test_session: AsyncSession, tmp_path):
    """Test email entity creation, relationships, and cascade deletion."""
    test_bytes = b"Subject: Test Cascade\r\n\r\nTest"
    sha256, md5, stored_path, size = store_raw_evidence(test_bytes, vault_dir=tmp_path)

    email = Email(
        id=uuid.uuid4(),
        sha256_hash=sha256,
        md5_hash=md5,
        file_name="test_cascade.eml",
        file_size_bytes=size,
        raw_storage_path=stored_path,
        subject="Test Cascade Email",
        sender_email="test@aicte-india.org",
        recipient_list=["target@example.edu"],
    )
    test_session.add(email)
    await test_session.flush()

    # Add header hop
    hop = HeaderHop(
        id=uuid.uuid4(),
        email_id=email.id,
        hop_order=1,
        hop_ip="1.2.3.4",
        asn_number=12345,
        node_type="ORIGINATING",
    )
    # Add forensic analysis
    analysis = ForensicAnalysis(
        id=uuid.uuid4(),
        email_id=email.id,
        spf_status="PASS",
        dkim_status="PASS",
        dmarc_status="PASS",
        threat_score=15.0,
        verdict="BENIGN",
    )
    # Add threat indicator
    ioc = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email.id,
        ioc_type="IP",
        ioc_value="1.2.3.4",
    )
    test_session.add_all([hop, analysis, ioc])
    await test_session.commit()

    # Query with relationships
    stmt = (
        select(Email)
        .options(
            selectinload(Email.header_hops),
            selectinload(Email.forensic_analysis),
            selectinload(Email.threat_indicators),
        )
        .where(Email.id == email.id)
    )
    result = await test_session.execute(stmt)
    loaded_email = result.scalar_one()

    assert len(loaded_email.header_hops) == 1
    assert loaded_email.forensic_analysis is not None
    assert loaded_email.forensic_analysis.verdict == "BENIGN"
    assert len(loaded_email.threat_indicators) == 1

    # Test serialization
    data_dict = loaded_email.to_dict()
    assert data_dict["sha256_hash"] == sha256
    assert data_dict["recipient_list"] == ["target@example.edu"]

    # Delete email and verify cascade
    await test_session.delete(loaded_email)
    await test_session.commit()

    hop_count = (await test_session.execute(select(func.count()).select_from(HeaderHop))).scalar()
    fa_count = (await test_session.execute(select(func.count()).select_from(ForensicAnalysis))).scalar()
    ioc_count = (await test_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar()

    assert hop_count == 0
    assert fa_count == 0
    assert ioc_count == 0


@pytest.mark.asyncio
async def test_email_sha256_unique_constraint(test_session: AsyncSession):
    """Test that duplicate SHA-256 hashes are rejected by the database."""
    dup_hash = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
    e1 = Email(
        id=uuid.uuid4(),
        sha256_hash=dup_hash,
        md5_hash="11112222333344445555666677778888",
        file_name="first.eml",
        file_size_bytes=100,
        raw_storage_path="/path/first",
        recipient_list=["a@b.com"],
    )
    test_session.add(e1)
    await test_session.commit()

    e2 = Email(
        id=uuid.uuid4(),
        sha256_hash=dup_hash,  # duplicate
        md5_hash="11112222333344445555666677778888",
        file_name="second.eml",
        file_size_bytes=100,
        raw_storage_path="/path/second",
        recipient_list=["c@d.com"],
    )
    test_session.add(e2)
    with pytest.raises(IntegrityError):
        await test_session.commit()


# =============================================================================
# 3. FORENSIC SEED CASES & ATTRIBUTION TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_forensic_seeder_execution(test_session: AsyncSession):
    """Verify that seed_forensic_database seeds all 5 cases with accurate forensic parameters."""
    counts = await seed_forensic_database(test_session)

    # 5 test scenarios = 7 emails (Case 1, 2, 3, 4, and 3 emails in Case 5 cluster)
    assert counts["emails"] == 7
    assert counts["hops"] >= 13
    assert counts["analyses"] == 7
    assert counts["iocs"] >= 20
    assert counts["campaigns"] == 1
    assert counts["campaign_emails"] == 3
    assert counts["audit_logs"] == 7

    # Verify Case 1 (Legitimate AICTE Circular)
    c1_stmt = (
        select(Email)
        .options(selectinload(Email.forensic_analysis))
        .where(Email.subject.like("%[AICTE-OFFICIAL]%"))
    )
    c1_email = (await test_session.execute(c1_stmt)).scalar_one()
    assert c1_email.forensic_analysis.verdict == "BENIGN"
    assert c1_email.forensic_analysis.threat_score <= 20.0
    assert c1_email.forensic_analysis.spf_status == "PASS"
    assert c1_email.forensic_analysis.dkim_status == "PASS"

    # Verify Case 2 (Executive BEC Wire Fraud)
    c2_stmt = (
        select(Email)
        .options(selectinload(Email.forensic_analysis))
        .where(Email.subject.like("%Release of Emergency Cybersecurity%"))
    )
    c2_email = (await test_session.execute(c2_stmt)).scalar_one()
    assert c2_email.forensic_analysis.verdict == "BEC"
    assert c2_email.forensic_analysis.threat_score >= 90.0
    assert c2_email.forensic_analysis.display_spoof_flag is True
    assert "gmail.com" in c2_email.reply_to

    # Verify Case 3 (Tor Exit Node Credential Harvesting)
    c3_stmt = (
        select(Email)
        .options(selectinload(Email.header_hops), selectinload(Email.forensic_analysis))
        .where(Email.subject.like("%Faculty Portal Credentials Expiration%"))
    )
    c3_email = (await test_session.execute(c3_stmt)).scalar_one()
    assert c3_email.forensic_analysis.verdict == "PHISHING"
    assert c3_email.forensic_analysis.threat_score >= 95.0
    origin_hop = next(h for h in c3_email.header_hops if h.hop_order == 1)
    assert origin_hop.hop_ip == "185.220.101.5"
    assert origin_hop.is_tor is True
    assert origin_hop.node_type == "TOR_EXIT"

    # Verify Case 4 (Cyrillic Homograph 'а' Attack)
    c4_stmt = (
        select(Email)
        .options(selectinload(Email.forensic_analysis))
        .where(Email.subject.like("%Approval Process Handbook%"))
    )
    c4_email = (await test_session.execute(c4_stmt)).scalar_one()
    assert c4_email.forensic_analysis.verdict == "PHISHING"
    assert c4_email.forensic_analysis.homograph_flag is True
    assert c4_email.forensic_analysis.lookalike_flag is True

    # Verify Case 5 (Operation FalconShield Campaign Cluster)
    camp_stmt = (
        select(Campaign)
        .options(selectinload(Campaign.email_associations).selectinload(CampaignEmail.email))
        .where(Campaign.name.like("%Operation FalconShield%"))
    )
    campaign = (await test_session.execute(camp_stmt)).scalar_one()
    assert campaign.cluster_type == "COMPOSITE_ASN_SIMHASH"
    assert campaign.severity == "CRITICAL"
    assert len(campaign.email_associations) == 3

    # All cluster emails share AS49870 bulletproof infrastructure and high similarity
    for assoc in campaign.email_associations:
        assert assoc.similarity_score >= 0.95
        assert assoc.matched_criteria["shared_asn"] == 49870

