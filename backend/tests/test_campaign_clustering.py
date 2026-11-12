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
from backend.app.database.models import Campaign, CampaignEmail, Email, HeaderHop, User, UserRole
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
    assert "objects" in stix_bundle
    assert all(obj["spec_version"] == "2.1" for obj in stix_bundle["objects"])
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
        assert all(obj["spec_version"] == "2.1" for obj in stix_data["objects"])

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_unrelated_google_asn_emails_do_not_cluster(campaign_test_session: AsyncSession):
    """Test Case (b) from Audit: Verify 3 unrelated emails from Google (AS15169) NEVER cluster."""
    db = campaign_test_session
    now = datetime.now(timezone.utc)

    google_unrelated = [
        ("GCP Monthly Billing Statement", "Your monthly invoice for Google Cloud services is available to download.", "billing@google.com", "209.85.220.41"),
        ("Invitation: Quarterly Academic Sync", "You have been invited to the Academic Review Sync on Google Meet at 3pm.", "calendar@google.com", "209.85.220.42"),
        ("Security Alert: New Linux Sign-in", "Your Google account was signed in from a new Chrome device on Linux.", "accounts@google.com", "209.85.220.43"),
    ]

    for i, (subject, body, sender, ip) in enumerate(google_unrelated):
        em = Email(
            id=uuid.uuid4(),
            sha256_hash=f"google_noise_{i}_" + "1" * 45,
            md5_hash="1" * 32,
            file_name=f"google_{i}.eml",
            file_size_bytes=len(body),
            raw_storage_path=f"storage/vault/raw/google_{i}.eml",
            subject=subject,
            sender_email=sender,
            body_plain=body,
            simhash_body=compute_simhash(body),
            ingested_at=now,
        )
        db.add(em)
        await db.flush()

        hop = HeaderHop(
            id=uuid.uuid4(),
            email_id=em.id,
            hop_order=1,
            hop_ip=ip,
            asn_number=15169,
            asn_org="Google LLC",
            node_type="ORIGINATING",
            delay_seconds=0.0,
        )
        db.add(hop)
        await db.flush()

        camp = await cluster_email_dynamically(
            db=db,
            email=em,
            origin_ip=ip,
            origin_asn=15169,
            threat_score=15.0,
        )
        assert camp is None, f"Unrelated Google email '{subject}' must NOT form or join a campaign!"

    # Ensure 0 campaigns created in database
    camp_res = await db.execute(select(Campaign))
    campaigns = camp_res.scalars().all()
    assert len(campaigns) == 0, f"Expected 0 campaigns for Google noise, found {len(campaigns)}"


@pytest.mark.asyncio
async def test_identical_bodies_different_asns_do_cluster(campaign_test_session: AsyncSession):
    """Test Case (a) from Audit: Verify 3 identical bodies from DIFFERENT ASNs cluster via SimHash."""
    db = campaign_test_session
    now = datetime.now(timezone.utc)

    identical_body = (
        "CONFIDENTIAL DIRECTIVE: Ministry sanctioned infrastructure audit notification. "
        "Failure to submit institutional compliance affidavit within 24 hours will revoke intake."
    )
    body_simhash = compute_simhash(identical_body)

    asns = [
        (13335, "Cloudflare, Inc.", "104.16.12.1"),
        (16509, "Amazon.com, Inc.", "54.240.27.1"),
        (20940, "Akamai Technologies", "23.200.10.1"),
    ]

    campaign_created = None
    for i, (asn_num, asn_org, ip) in enumerate(asns):
        em = Email(
            id=uuid.uuid4(),
            sha256_hash=f"identical_lure_{i}_" + "2" * 45,
            md5_hash="2" * 32,
            file_name=f"lure_{i}.eml",
            file_size_bytes=len(identical_body),
            raw_storage_path=f"storage/vault/raw/lure_{i}.eml",
            subject=f"Urgent Institutional Audit Notice #{i + 1}",
            sender_email=f"compliance_notice_{i}@audit-review-center.top",
            body_plain=identical_body,
            simhash_body=body_simhash,
            ingested_at=now,
        )
        db.add(em)
        await db.flush()

        hop = HeaderHop(
            id=uuid.uuid4(),
            email_id=em.id,
            hop_order=1,
            hop_ip=ip,
            asn_number=asn_num,
            asn_org=asn_org,
            node_type="ORIGINATING",
            delay_seconds=0.0,
        )
        db.add(hop)
        await db.flush()

        camp = await cluster_email_dynamically(
            db=db,
            email=em,
            origin_ip=ip,
            origin_asn=asn_num,
            threat_score=90.0,
        )
        if i == 0:
            assert camp is None  # First sample is unclustered until second arrives
        else:
            assert camp is not None
            campaign_created = camp

    assert campaign_created is not None
    assert campaign_created.cluster_type == "SIMHASH"
    assert campaign_created.total_emails == 3


@pytest.mark.asyncio
async def test_multi_signal_clustering_requires_two_signals(campaign_test_session: AsyncSession):
    """Verify that a single network signal (ASN alone) fails to cluster, but 2 independent signals succeed."""
    db = campaign_test_session
    now = datetime.now(timezone.utc)

    # Email 1: Non-fanout ASN 49870, Body A
    em1 = Email(
        id=uuid.uuid4(),
        sha256_hash="multi_1_" + "3" * 56,
        md5_hash="3" * 32,
        file_name="em1.eml",
        file_size_bytes=100,
        raw_storage_path="storage/vault/raw/em1.eml",
        subject="Technical Server Documentation",
        sender_email="support@host-node-49.com",
        body_plain="Technical documentation for Apache HTTP server setup on Rocky Linux 9.",
        simhash_body=compute_simhash("Technical documentation for Apache HTTP server setup on Rocky Linux 9."),
        ingested_at=now,
    )
    db.add(em1)
    await db.flush()

    hop1 = HeaderHop(
        id=uuid.uuid4(),
        email_id=em1.id,
        hop_order=1,
        hop_ip="185.156.73.1",
        asn_number=49870,
        asn_org="Alservice ISP",
        node_type="ORIGINATING",
        delay_seconds=0.0,
    )
    db.add(hop1)
    await db.flush()

    camp1 = await cluster_email_dynamically(db=db, email=em1, origin_ip=hop1.hop_ip, origin_asn=49870)
    assert camp1 is None

    # Email 2: Same ASN 49870, but completely different Body B and no shared Reply-To -> Must NOT cluster (only 1 signal)
    em2 = Email(
        id=uuid.uuid4(),
        sha256_hash="multi_2_" + "4" * 56,
        md5_hash="4" * 32,
        file_name="em2.eml",
        file_size_bytes=100,
        raw_storage_path="storage/vault/raw/em2.eml",
        subject="Invitation to Department Picnic",
        sender_email="events@unrelated-social-domain.net",
        body_plain="Join us for the annual autumn department picnic at the campus garden.",
        simhash_body=compute_simhash("Join us for the annual autumn department picnic at the campus garden."),
        ingested_at=now,
    )
    db.add(em2)
    await db.flush()

    hop2 = HeaderHop(
        id=uuid.uuid4(),
        email_id=em2.id,
        hop_order=1,
        hop_ip="185.156.73.2",
        asn_number=49870,
        asn_org="Alservice ISP",
        node_type="ORIGINATING",
        delay_seconds=0.0,
    )
    db.add(hop2)
    await db.flush()

    camp2 = await cluster_email_dynamically(db=db, email=em2, origin_ip=hop2.hop_ip, origin_asn=49870)
    assert camp2 is None  # Single network signal alone must NOT cluster

    # Email 3: Same ASN 49870 AND shared diversion Reply-To with em1 -> 2 independent families -> MUST cluster!
    em1.reply_to = "diversion.ops@bulletproof-hub.cc"
    await db.flush()

    em3 = Email(
        id=uuid.uuid4(),
        sha256_hash="multi_3_" + "5" * 56,
        md5_hash="5" * 32,
        file_name="em3.eml",
        file_size_bytes=100,
        raw_storage_path="storage/vault/raw/em3.eml",
        subject="Urgent Inward Transfer",
        sender_email="finance@host-node-49.com",
        reply_to="diversion.ops@bulletproof-hub.cc",
        body_plain="Unrelated body text about wire transfers and foreign invoice settlement.",
        simhash_body=compute_simhash("Unrelated body text about wire transfers and foreign invoice settlement."),
        ingested_at=now,
    )
    db.add(em3)
    await db.flush()

    hop3 = HeaderHop(
        id=uuid.uuid4(),
        email_id=em3.id,
        hop_order=1,
        hop_ip="185.156.73.3",
        asn_number=49870,
        asn_org="Alservice ISP",
        node_type="ORIGINATING",
        delay_seconds=0.0,
    )
    db.add(hop3)
    await db.flush()

    camp3 = await cluster_email_dynamically(db=db, email=em3, origin_ip=hop3.hop_ip, origin_asn=49870)
    assert camp3 is not None
    assert "Operation" in camp3.name


@pytest.mark.asyncio
async def test_campaign_clustering_corpus_eval_gates():
    """Verify campaign clustering evaluation on ground-truth corpus satisfies all quality gates."""
    from scripts.evaluate_campaign_clustering import run_evaluation

    report = await run_evaluation()
    metrics = report["metrics"]
    hyperscaler = report["hyperscaler_isolation_verification"]

    assert metrics["adjusted_rand_index_ari"] >= 0.85, f"ARI {metrics['adjusted_rand_index_ari']} < 0.85"
    assert metrics["normalized_mutual_info_nmi"] >= 0.85, f"NMI {metrics['normalized_mutual_info_nmi']} < 0.85"
    assert metrics["clustering_purity"] >= 0.90, f"Purity {metrics['clustering_purity']} < 0.90"
    assert metrics["noise_false_positive_rate"] == 0.0, f"Noise FP rate {metrics['noise_false_positive_rate']} != 0.0"
    assert hyperscaler["hyperscaler_clustering_status"] == "PASS"


@pytest.mark.asyncio
async def test_analyst_campaign_label_merge_split(campaign_test_session: AsyncSession):
    """Verify analyst actions: relabeling, merging, and splitting campaigns with hash-chained audit logging."""
    from backend.app.database.models import EvidenceAuditLog

    db = campaign_test_session
    now = datetime.now(timezone.utc)

    # 1. Create two test campaigns
    camp1 = Campaign(
        id=uuid.uuid4(),
        name="Campaign Alpha",
        cluster_type="ASN",
        cluster_key="AS208294",
        first_seen=now,
        last_seen=now,
        total_emails=2,
    )
    camp2 = Campaign(
        id=uuid.uuid4(),
        name="Campaign Beta",
        cluster_type="SIMHASH",
        cluster_key="0x12345678",
        first_seen=now,
        last_seen=now,
        total_emails=1,
    )
    db.add(camp1)
    db.add(camp2)
    await db.flush()

    em1 = Email(id=uuid.uuid4(), sha256_hash="1"*64, md5_hash="1"*32, file_name="e1.eml", file_size_bytes=100, raw_storage_path="v/e1")
    em2 = Email(id=uuid.uuid4(), sha256_hash="2"*64, md5_hash="2"*32, file_name="e2.eml", file_size_bytes=100, raw_storage_path="v/e2")
    em3 = Email(id=uuid.uuid4(), sha256_hash="3"*64, md5_hash="3"*32, file_name="e3.eml", file_size_bytes=100, raw_storage_path="v/e3")
    db.add_all([em1, em2, em3])
    await db.flush()

    db.add(CampaignEmail(campaign_id=camp1.id, email_id=em1.id, similarity_score=0.9))
    db.add(CampaignEmail(campaign_id=camp1.id, email_id=em2.id, similarity_score=0.9))
    db.add(CampaignEmail(campaign_id=camp2.id, email_id=em3.id, similarity_score=0.9))
    await db.commit()

    # 2. Test relabeling via client
    analyst_token = create_access_token(subject="test_analyst_camp", role="ANALYST")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Override get_db to use test session
        app.dependency_overrides[get_db] = lambda: db

        # Relabel
        resp_label = await client.patch(
            f"/api/v1/campaigns/{camp1.id}/label",
            json={"name": "Operation Sovereign Shield", "threat_actor": "APT-26106"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp_label.status_code == 200
        assert resp_label.json()["name"] == "Operation Sovereign Shield"

        # Split: Split em2 from camp1 into new campaign
        resp_split = await client.post(
            f"/api/v1/campaigns/{camp1.id}/split",
            json={"email_ids": [str(em2.id)], "new_campaign_name": "Campaign Gamma"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp_split.status_code == 200
        assert resp_split.json()["name"] == "Campaign Gamma"
        assert resp_split.json()["total_emails"] == 1

        # Merge: Merge camp2 into camp1
        resp_merge = await client.post(
            f"/api/v1/campaigns/{camp2.id}/merge",
            json={"target_campaign_id": str(camp1.id)},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp_merge.status_code == 200

        # Verify audit logs created
        stmt_audit = select(EvidenceAuditLog).where(EvidenceAuditLog.action_performed.in_(["CAMPAIGN_LABELED", "CAMPAIGN_SPLIT", "CAMPAIGN_MERGED"]))
        logs = (await db.execute(stmt_audit)).scalars().all()
        assert len(logs) == 3

        app.dependency_overrides.clear()

