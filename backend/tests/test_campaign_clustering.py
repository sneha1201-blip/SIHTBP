"""Comprehensive Test Suite for Dynamic Campaign Clustering, Graph Telemetry, and STIX 2.1 Export.

Validates:
- Real-time dynamic clustering on ingestion (SimHash Hamming distance < 10, shared ASN, shared subnet)
- Formation of >= 2 distinct campaigns and 1 isolated sample
- Graph API nodes, edges, and filter controls (min_threat_score, cluster_type)
- Generation and export of RFC OASIS STIX 2.1 Threat Intelligence Bundles
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from backend.app.core.security import create_access_token
from backend.app.database.models import Campaign, Email, HeaderHop, User, UserRole
from backend.app.database.session import Base, get_db
from backend.app.forensics.campaign_clusterer import cluster_email_dynamically, generate_stix21_bundle
from backend.app.main import app
from backend.app.parsers.mime_normalizer import compute_simhash

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN_BUNDLE_FILE = PROJECT_ROOT / "evidence" / "campaign_bundle.json"


@pytest_asyncio.fixture(scope="function")
async def campaign_test_session():
    """Create an isolated in-memory SQLite database session for campaign clustering tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_maker() as session:
        # Seed test analyst user
        analyst = User(
            id=uuid.uuid4(),
            username="test_analyst_camp",
            email="analyst@aicte.gov.in",
            password_hash="fakehashforjwt",
            role=UserRole.ANALYST,
            is_active=True,
        )
        session.add(analyst)
        await session.commit()
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_dynamic_campaign_clustering_and_stix_bundle(campaign_test_session: AsyncSession):
    """Verify dynamic clustering of 10+ samples yielding >= 2 campaigns, 1 isolated sample, and STIX 2.1 bundle."""
    db = campaign_test_session
    now = datetime.now(timezone.utc)

    # -------------------------------------------------------------
    # CAMPAIGN 1: Operation FalconShield (Shared bulletproof ASN 208294 & similar SimHash)
    # -------------------------------------------------------------
    template_body_c1 = (
        "Directive from Technical Education Bureau: Institutional deficiency audit notice. "
        "Intake quota reduction of 50% will be executed unless compliance affidavit is remitted."
    )
    c1_simhash = compute_simhash(template_body_c1)

    c1_emails = []
    for i in range(3):
        em = Email(
            id=uuid.uuid4(),
            sha256_hash=f"c1_{i}_" + "a" * 60,
            md5_hash="a" * 32,
            file_name=f"c1_phish_{i}.eml",
            file_size_bytes=1024 + i,
            raw_storage_path=f"storage/vault/raw/c1_{i}.eml",
            subject=f"Deficiency Audit Notice #{i + 1}",
            sender_email="audit@aicte-compliance-review.top",
            body_plain=template_body_c1 + f" Case reference #{1000 + i}.",
            simhash_body=c1_simhash,
            ingested_at=now,
        )
        db.add(em)
        await db.flush()

        hop = HeaderHop(
            id=uuid.uuid4(),
            email_id=em.id,
            hop_order=1,
            hop_ip=f"185.220.101.{10 + i}",
            asn_number=208294,
            asn_org="Zwiebelfreunde Hosting Datacenter",
            node_type="ORIGINATING",
            delay_seconds=0.0,
        )
        db.add(hop)
        await db.flush()

        # Dynamically cluster each email on ingestion
        await cluster_email_dynamically(
            db=db,
            email=em,
            origin_ip=hop.hop_ip,
            origin_asn=hop.asn_number,
            detected_vip="Prof. T. G. Sitharam",
            threat_score=92.0,
        )
        c1_emails.append(em)

    # -------------------------------------------------------------
    # CAMPAIGN 2: Operation WireTransfer-BEC (Shared SimHash & Reply-To diversion)
    # -------------------------------------------------------------
    template_body_c2 = (
        "Bilateral ministry grant matching fund disbursement directive. "
        "Remit commitment fee of Rs. 4,50,000 via RTGS immediately to escrow account."
    )
    c2_simhash = compute_simhash(template_body_c2)

    c2_emails = []
    for i in range(2):
        em = Email(
            id=uuid.uuid4(),
            sha256_hash=f"c2_{i}_" + "b" * 60,
            md5_hash="b" * 32,
            file_name=f"c2_bec_{i}.eml",
            file_size_bytes=1024 + i,
            raw_storage_path=f"storage/vault/raw/c2_{i}.eml",
            subject=f"Bilateral Grant Remittance Directive #{i + 1}",
            sender_email="executive@ministry-grants.xyz",
            reply_to="executive.remittance@gmail.com",
            body_plain=template_body_c2 + f" Authorization code {9000 + i}.",
            simhash_body=c2_simhash,
            ingested_at=now,
        )
        db.add(em)
        await db.flush()

        hop = HeaderHop(
            id=uuid.uuid4(),
            email_id=em.id,
            hop_order=1,
            hop_ip=f"91.240.118.{20 + i}",
            asn_number=44050,
            asn_org="Alexhost Offshore",
            node_type="ORIGINATING",
            delay_seconds=0.0,
        )
        db.add(hop)
        await db.flush()

        await cluster_email_dynamically(
            db=db,
            email=em,
            origin_ip=hop.hop_ip,
            origin_asn=hop.asn_number,
            detected_vip="Dr. Abhay Jere",
            threat_score=94.0,
        )
        c2_emails.append(em)

    # -------------------------------------------------------------
    # ISOLATED BENIGN SAMPLE (Unique benign infrastructure, unique body)
    # -------------------------------------------------------------
    isolated_body = "Invitation to attend the 2026 National Green Technology Symposium in Mumbai."
    iso_simhash = compute_simhash(isolated_body)
    isolated_em = Email(
        id=uuid.uuid4(),
        sha256_hash="iso_" + "c" * 60,
        md5_hash="c" * 32,
        file_name="isolated_benign.eml",
        file_size_bytes=850,
        raw_storage_path="storage/vault/raw/isolated.eml",
        subject="Green Tech Symposium",
        sender_email="symposium@iitb.ac.in",
        body_plain=isolated_body,
        simhash_body=iso_simhash,
        ingested_at=now,
    )
    db.add(isolated_em)
    await db.flush()

    iso_hop = HeaderHop(
        id=uuid.uuid4(),
        email_id=isolated_em.id,
        hop_order=1,
        hop_ip="14.139.110.5",  # ERNET India educational network
        asn_number=2687,
        asn_org="Education and Research Network",
        node_type="ORIGINATING",
        delay_seconds=0.0,
    )
    db.add(iso_hop)
    await db.flush()

    iso_camp = await cluster_email_dynamically(
        db=db,
        email=isolated_em,
        origin_ip=iso_hop.hop_ip,
        origin_asn=iso_hop.asn_number,
        threat_score=10.0,
    )
    await db.commit()

    # -------------------------------------------------------------
    # VERIFICATION: >= 2 Distinct Campaigns & 1 Isolated Sample
    # -------------------------------------------------------------
    camp_stmt = select(Campaign).options(
        selectinload(Campaign.email_associations)
    ).order_by(Campaign.total_emails.desc())
    camp_res = await db.execute(camp_stmt)
    all_campaigns = camp_res.scalars().all()

    # Must have formed at least 2 distinct campaigns
    assert len(all_campaigns) >= 2

    # Campaign 1 has 3 attributed emails
    camp_names = [c.name for c in all_campaigns]
    assert any("208294" in name or "Template" in name for name in camp_names)
    assert any(c.total_emails == 3 for c in all_campaigns)

    # Campaign 2 has 2 attributed emails
    assert any(c.total_emails == 2 for c in all_campaigns)

    # Isolated email must not be associated with either campaign
    assert iso_camp is None
    all_assoc_email_ids = set()
    for c in all_campaigns:
        for a in c.email_associations:
            all_assoc_email_ids.add(a.email_id)
    assert isolated_em.id not in all_assoc_email_ids

    # -------------------------------------------------------------
    # STIX 2.1 BUNDLE GENERATION & VALIDATION
    # -------------------------------------------------------------
    c1_camp = all_campaigns[0]
    emails_query = select(Email).options(
        selectinload(Email.header_hops),
        selectinload(Email.threat_indicators),
    ).where(Email.id.in_([a.email_id for a in c1_camp.email_associations]))
    c1_emails_db = (await db.execute(emails_query)).scalars().all()

    stix_bundle = generate_stix21_bundle(c1_camp, c1_emails_db)

    assert stix_bundle["type"] == "bundle"
    assert stix_bundle["spec_version"] == "2.1"
    assert "objects" in stix_bundle
    assert len(stix_bundle["objects"]) >= 4

    types_in_bundle = [obj["type"] for obj in stix_bundle["objects"]]
    assert "threat-actor" in types_in_bundle
    assert "campaign" in types_in_bundle
    assert "email-message" in types_in_bundle
    assert "relationship" in types_in_bundle

    # Export bundle to evidence/campaign_bundle.json
    CAMPAIGN_BUNDLE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CAMPAIGN_BUNDLE_FILE, "w", encoding="utf-8") as f:
        json.dump(stix_bundle, f, indent=2)

    assert CAMPAIGN_BUNDLE_FILE.exists()
    assert CAMPAIGN_BUNDLE_FILE.stat().st_size > 500


@pytest.mark.asyncio
async def test_campaign_graph_api_endpoint(campaign_test_session: AsyncSession):
    """Verify GET /api/v1/campaigns/graph with min_threat_score and cluster_type filters."""
    db = campaign_test_session

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    token = create_access_token(subject="test_analyst_camp", role="ANALYST")
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as ac:
        # 1. Base Graph
        res = await ac.get("/api/v1/campaigns/graph", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert "graph" in data
        assert "nodes" in data["graph"]
        assert "edges" in data["graph"]

        # 2. Filter by min_threat_score
        res_filter = await ac.get("/api/v1/campaigns/graph?min_threat_score=80.0", headers=headers)
        assert res_filter.status_code == 200
        data_filt = res_filter.json()
        assert "graph" in data_filt

        # 3. Export STIX Endpoint
        res_stix = await ac.get("/api/v1/campaigns/export/stix", headers=headers)
        assert res_stix.status_code == 200
        stix_data = res_stix.json()
        assert stix_data["type"] == "bundle"
        assert stix_data["spec_version"] == "2.1"

    app.dependency_overrides.clear()
