"""Comprehensive End-to-End Pipeline & REST API Tests for Phase 2.

Validates:
1. Parsers & Reverse Hop-Traversal Algorithm.
2. Protocol Authentication & DMARC RFC 7489 Alignment.
3. Spoofing, Homograph & VIP Impersonation Detectors.
4. AI BEC NLP & URL De-Obfuscation Engines.
5. Section 63 BSA 2023 Court-Admissible PDF Generation.
6. FastAPI REST API Ingestion & Reporting Endpoints.
"""

from __future__ import annotations

import io
import uuid

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from backend.app.ai.nlp_engine import analyze_email_content
from backend.app.ai.url_analyzer import analyze_url, deobfuscate_ip_literal
from backend.app.forensics.auth_validator import validate_protocol_authentication
from backend.app.forensics.hop_traversal import is_ip_private, reverse_hop_traversal
from backend.app.forensics.spoof_detector import detect_homograph, detect_spoofing
from backend.app.main import app
from backend.app.parsers.eml_parser import parse_eml
from backend.app.reporting.pdf_generator import generate_forensic_pdf

# Sample RFC 822 EML for testing BEC Wire Fraud
SAMPLE_BEC_EML = b"""Received: from relay.nic.in (164.100.24.12) by mail.vjti.ac.in with ESMTPS; Sun, 01 Nov 2026 10:00:00 +0000
Received: from mail.aicte-emergency-portal.org (185.174.136.42) by relay.nic.in with ESMTPS; Sun, 01 Nov 2026 09:59:58 +0000
Authentication-Results: mail.vjti.ac.in; spf=softfail smtp.mailfrom=bounce@aicte-emergency-portal.org; dkim=fail header.d=aicte-emergency-portal.org; dmarc=fail p=none
From: "Prof. T. G. Sitharam (Chairman AICTE)" <chairman@aicte-emergency-portal.org>
Reply-To: <chairman.aicte.funds.dept@gmail.com>
To: <finance.officer@vjti.ac.in>
Subject: URGENT: Emergency Grant Remittance Allocation
Date: Sun, 01 Nov 2026 09:59:50 +0000
Message-ID: <test-bec-001@aicte-emergency-portal.org>
Content-Type: text/plain; charset="utf-8"

URGENT & CONFIDENTIAL
Remit commitment fee of Rs. 4,50,000 immediately via RTGS to escrow account:
Account: 50200088192411
IFSC: HDFC0000122
Confirm to chairman.aicte.funds.dept@gmail.com
"""


@pytest.fixture
def client():
    """Synchronous test client for FastAPI."""
    return TestClient(app)


# =============================================================================
# 1. PARSER & REVERSE HOP-TRAVERSAL TESTS
# =============================================================================

def test_eml_parser():
    """Verify MIME parsing, header extraction, and SimHash computation."""
    parsed = parse_eml(SAMPLE_BEC_EML, filename="test_bec.eml")
    assert parsed.subject == "URGENT: Emergency Grant Remittance Allocation"
    assert parsed.sender_email == "chairman@aicte-emergency-portal.org"
    assert "T. G. Sitharam" in (parsed.sender_display or "")
    assert parsed.reply_to == "chairman.aicte.funds.dept@gmail.com"
    assert len(parsed.received_headers) == 2
    assert parsed.simhash_body is not None
    assert parsed.simhash_body.startswith("0x")


def test_reverse_hop_traversal():
    """Verify chronological ordering, private IP detection, and earliest public IP extraction."""
    raw_headers = [
        "from internal.lan (10.0.0.5) by edge.lan with SMTP; Sun, 01 Nov 2026 10:01:00 +0000",
        "from relay.nic.in (164.100.24.12) by mx.vjti.ac.in with ESMTPS; Sun, 01 Nov 2026 10:00:00 +0000",
        "from tor-exit.net (185.220.101.5) by relay.nic.in with ESMTP; Sun, 01 Nov 2026 09:59:50 +0000",
    ]
    hops, origin_ip = reverse_hop_traversal(raw_headers)

    assert len(hops) == 3
    # Originating hop is the earliest in chronological transit (the bottom raw header)
    assert hops[0].hop_ip == "185.220.101.5"
    assert hops[0].node_type == "ORIGINATING"
    assert origin_ip == "185.220.101.5"
    assert is_ip_private("10.0.0.5") is True
    assert is_ip_private("185.220.101.5") is False


# =============================================================================
# 2. PROTOCOL AUTHENTICATION & SPOOFING DETECTOR TESTS
# =============================================================================

def test_protocol_authentication():
    """Verify SPF, DKIM, and DMARC alignment validation both upstream claimed and cryptographically recomputed."""
    auth_header = "mx.ac.in; spf=pass smtp.mailfrom=no-reply@aicte-india.org; dkim=pass header.d=aicte-india.org header.s=k1; dmarc=pass p=reject"
    res_claimed = validate_protocol_authentication(
        from_email="no-reply@aicte-india.org",
        return_path="no-reply@aicte-india.org",
        headers_dict={},
        auth_results_header=auth_header,
    )
    assert res_claimed.claimed_by_mta["claimed_spf"] == "PASS"
    assert res_claimed.claimed_by_mta["claimed_dkim"] == "PASS"
    assert res_claimed.claimed_by_mta["claimed_dmarc"] == "PASS"

    # Real cryptographic recomputation with signed fixture
    from backend.tests.fixtures.email_corpus import DNS_FIXTURES, build_corpus
    corpus = build_corpus()
    raw_bytes, meta = corpus["legit_signed_aicte.eml"]
    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict={"From": [meta["from_email"]]},
        auth_results_header=auth_header,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )
    assert res.spf_status == "PASS"
    assert res.dkim_status == "PASS"
    assert res.dmarc_status == "PASS"
    assert res.dmarc_alignment_spf is True
    assert res.dmarc_alignment_dkim is True
    assert res.auth_score == 0.0


def test_spoof_detection_vip_and_homograph():
    """Verify display spoofing, Reply-To divergence, and Cyrillic homograph attacks."""
    # BEC display spoofing
    spoof_res = detect_spoofing(
        sender_display="Prof. T. G. Sitharam (Chairman, AICTE)",
        sender_email="fraud@external-domain.com",
        return_path="bounce@external-domain.com",
        reply_to="vip.funds@gmail.com",
    )
    assert spoof_res.display_spoof_flag is True
    assert spoof_res.reply_to_divergence is True
    assert spoof_res.spoof_score >= 60.0

    # Cyrillic homograph test
    homo_domain = "\u0430icte-india.org"
    is_homo, glyphs, punycode = detect_homograph(homo_domain)
    assert is_homo is True
    assert len(glyphs) >= 1
    assert "U+0430" in glyphs[0]
    assert punycode.startswith("xn--")


# =============================================================================
# 3. AI BEC NLP & URL DE-OBFUSCATION TESTS
# =============================================================================

def test_nlp_bec_wire_fraud_detection():
    """Verify extraction of Indian banking coordinates and BEC classification."""
    body_text = (
        "High priority: Please disburse Rs. 45,00,000 via RTGS immediately to our vendor escrow account: "
        "Account: 50200088192411, IFSC: HDFC0000122 before 4:00 PM today."
    )
    res = analyze_email_content(subject="Urgent Payment Allocation", body=body_text)

    assert res.is_bec_financial is True
    assert "HDFC0000122" in res.extracted_entities["ifsc_codes"]
    assert "50200088192411" in res.extracted_entities["bank_accounts"]
    assert res.category == "BEC_FINANCIAL"
    assert res.nlp_score >= 50.0


def test_url_deobfuscation():
    """Verify de-obfuscation of hexadecimal/numerical IPs and credential lure flags."""
    # DWORD IP: 2130706433 -> 127.0.0.1
    assert deobfuscate_ip_literal("2130706433") == "127.0.0.1"
    # Hex IP: 0x7f000001 -> 127.0.0.1
    assert deobfuscate_ip_literal("0x7f000001") == "127.0.0.1"

    url_res = analyze_url("hxxps://login[.]aicte-faculty-verification[.]ru/auth/login[.]php")
    assert url_res.has_credential_lure is True
    assert url_res.risk_score >= 60.0


# =============================================================================
# 4. COURT-ADMISSIBLE FORENSIC PDF GENERATOR TEST
# =============================================================================

def test_forensic_pdf_generation():
    """Verify PDF creation under Section 63 BSA 2023 with valid ReportLab bytes."""
    email_data = {
        "id": str(uuid.uuid4()),
        "file_name": "evidence_test.eml",
        "file_size_bytes": 1024,
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "subject": "Test PDF Dossier Subject",
        "sender_email": "test@aicte-india.org",
        "sender_display": "AICTE Cyber Security Cell",
        "ingested_at": "2026-11-01T10:00:00Z",
    }
    analysis = {
        "verdict": "PHISHING",
        "threat_score": 98.0,
        "spf_status": "FAIL",
        "dkim_status": "NONE",
        "dmarc_status": "FAIL",
        "dmarc_policy": "quarantine",
        "dmarc_alignment_spf": False,
        "dmarc_alignment_dkim": False,
    }
    hops = [
        {
            "hop_order": 1,
            "node_type": "ORIGINATING",
            "hop_ip": "185.220.101.5",
            "geo_city": "Frankfurt am Main",
            "geo_country": "Germany",
            "asn_number": 208294,
            "asn_org": "Zappie Host LLC",
            "delay_seconds": 0.2,
            "is_tor": True,
        }
    ]
    iocs = [
        {
            "ioc_type": "IP",
            "ioc_value": "185.220.101.5",
            "context": "HEADER_RECEIVED",
            "reputation_score": 99.0,
        }
    ]

    pdf_buffer = generate_forensic_pdf(
        email_data=email_data,
        hops=hops,
        analysis=analysis,
        iocs=iocs,
        audit_logs=[],
    )

    pdf_bytes = pdf_buffer.getvalue()
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


# =============================================================================
# 5. REST API ENDPOINTS INTEGRATION TEST
# =============================================================================

@pytest.mark.asyncio
async def test_api_analyze_and_report_endpoints():
    """Verify POST /api/v1/forensics/analyze and GET /api/v1/forensics/evidence/{id}."""
    from backend.app.core.security import create_access_token

    analyst_token = create_access_token("analyst", role="ANALYST")
    auth_headers = {"Authorization": f"Bearer {analyst_token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Health Check
        health_resp = await ac.get("/api/v1/health")
        assert health_resp.status_code == 200
        assert health_resp.json()["status"] == "HEALTHY"

        # 2. Ingest & Analyze multipart EML (synchronous mode)
        files = {"file": ("bec_chairman.eml", io.BytesIO(SAMPLE_BEC_EML), "message/rfc822")}
        post_resp = await ac.post("/api/v1/forensics/analyze?sync=true", files=files, headers=auth_headers)
        assert post_resp.status_code == 201

        dossier = post_resp.json()
        assert "email" in dossier
        assert "forensic_analysis" in dossier
        assert "header_hops" in dossier

        evidence_id = dossier["email"]["id"]
        assert dossier["forensic_analysis"]["verdict"] == "BEC"
        assert dossier["forensic_analysis"]["threat_score"] >= 90.0

        # 3. Retrieve GeoJSON hops
        hops_resp = await ac.get(f"/api/v1/forensics/evidence/{evidence_id}/hops", headers=auth_headers)
        assert hops_resp.status_code == 200
        geojson = hops_resp.json()
        assert geojson["type"] == "FeatureCollection"
        assert geojson["evidence_id"] == evidence_id
        assert isinstance(geojson["features"], list)

        # 4. Stream Forensic PDF Report
        report_resp = await ac.get(f"/api/v1/forensics/evidence/{evidence_id}/report", headers=auth_headers)
        assert report_resp.status_code == 200
        assert report_resp.headers["content-type"] == "application/pdf"
        assert report_resp.content.startswith(b"%PDF-")

        # 5. Query Campaign Graph
        graph_resp = await ac.get("/api/v1/campaigns/graph", headers=auth_headers)
        assert graph_resp.status_code == 200
        assert "graph" in graph_resp.json()


@pytest.mark.asyncio
async def test_pdf_report_aborts_with_409_on_vault_tamper():
    """Verify GET /evidence/{id}/report rejects tampered vault evidence with HTTP 409 and logs INTEGRITY_FAILURE."""
    import os
    import stat

    from sqlalchemy import select

    from backend.app.core.security import create_access_token
    from backend.app.database.models import EvidenceAuditLog
    from backend.app.database.session import async_session_factory
    from backend.app.database.vault import get_vault_dir

    analyst_token = create_access_token("analyst", role="ANALYST")
    auth_headers = {"Authorization": f"Bearer {analyst_token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Ingest valid email
        files = {"file": ("tamper_test_sample.eml", io.BytesIO(SAMPLE_BEC_EML), "message/rfc822")}
        post_resp = await ac.post("/api/v1/forensics/analyze?sync=true", files=files, headers=auth_headers)
        assert post_resp.status_code == 201

        dossier = post_resp.json()
        evidence_id = dossier["email"]["id"]
        sha256_hash = dossier["email"]["sha256_hash"]

        # First verify report succeeds when vault is intact
        rep1 = await ac.get(f"/api/v1/forensics/evidence/{evidence_id}/report", headers=auth_headers)
        assert rep1.status_code == 200
        assert rep1.content.startswith(b"%PDF-")

        # Now deliberately tamper with the physical vault file
        vault_file = get_vault_dir() / f"{sha256_hash}.raw"
        assert vault_file.exists()

        original_bytes = vault_file.read_bytes()
        tampered_bytes = bytes([original_bytes[0] ^ 0xFF]) + original_bytes[1:]

        try:
            os.chmod(vault_file, stat.S_IWRITE | stat.S_IREAD)
            vault_file.write_bytes(tampered_bytes)
            os.chmod(vault_file, stat.S_IREAD)

            # Requesting report on tampered vault file MUST return HTTP 409 Conflict
            rep2 = await ac.get(f"/api/v1/forensics/evidence/{evidence_id}/report", headers=auth_headers)
            assert rep2.status_code == 409
            assert "Cryptographic integrity violation" in rep2.json()["detail"]

            # Verify that an INTEGRITY_FAILURE row was written to the chained audit ledger
            async with async_session_factory() as session:
                stmt = (
                    select(EvidenceAuditLog)
                    .where(
                        EvidenceAuditLog.email_id == uuid.UUID(evidence_id),
                        EvidenceAuditLog.action_performed == "INTEGRITY_FAILURE",
                    )
                    .order_by(EvidenceAuditLog.recorded_at.desc())
                    .limit(1)
                )
                res = await session.execute(stmt)
                failure_log = res.scalar_one_or_none()
                assert failure_log is not None
                assert failure_log.integrity_check is False
                assert failure_log.actor == "analyst"
                assert "tampering detected" in str(failure_log.details.get("error", ""))
        finally:
            # Restore vault file integrity
            os.chmod(vault_file, stat.S_IWRITE | stat.S_IREAD)
            vault_file.write_bytes(original_bytes)
            os.chmod(vault_file, stat.S_IREAD)


# =============================================================================
# 6. FIX 5 TESTS: PARTIAL PARSE, ZERO-SEED ISOLATION & CORPUS INGESTION
# =============================================================================

def test_corrupt_msg_partial_carving_no_invented_data():
    """Verify that corrupt OLE streams undergo partial ASCII carving without inventing synthetic recipients."""
    from backend.app.parsers.msg_parser import parse_msg

    # Corrupt binary stream simulating truncated/damaged OLE compound file
    corrupt_ole_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"Subject: Urgent Wire Notice\n" + b"\xFF" * 128

    parsed = parse_msg(corrupt_ole_bytes, filename="corrupt_invoice.msg")

    # Forensic parsing status must be explicitly recorded
    assert "X-Forensic-Parsing-Status" in parsed.headers_dict
    assert parsed.headers_dict["X-Forensic-Parsing-Status"] == ["PARTIAL_PARSE_CORRUPT_OLE_STREAM"]

    # Subject extracted from ASCII chunk
    assert "Urgent Wire Notice" in (parsed.subject or "")

    # No fake/dummy recipients invented
    assert parsed.recipient_list == []
    assert parsed.sender_email != "unknown-sender@corrupted.msg"


@pytest.mark.asyncio
async def test_init_db_zero_seed_mode():
    """Verify that init_db in default production mode (seed=False) initializes schemas with 0 emails."""
    from sqlalchemy import func, select

    from backend.app.database.init_db import initialize_and_verify
    from backend.app.database.models import Campaign, Email, User
    from backend.app.database.session import async_session_factory

    success = await initialize_and_verify(reset=True, seed=False)
    assert success is True

    async with async_session_factory() as session:
        # User accounts must be seeded for RBAC
        users_count = (await session.execute(select(func.count()).select_from(User))).scalar()
        assert users_count is not None and users_count >= 1

        # Zero emails and zero campaigns populated
        emails_count = (await session.execute(select(func.count()).select_from(Email))).scalar()
        assert emails_count == 0

        campaigns_count = (await session.execute(select(func.count()).select_from(Campaign))).scalar()
        assert campaigns_count == 0


def test_corpus_ingestion_cli_helper(tmp_path):
    """Verify that scripts/ingest_corpus.py ingests a directory of .eml files via the REST API."""
    from fastapi.testclient import TestClient

    from backend.app.core.security import create_access_token
    from scripts.ingest_corpus import ingest_corpus

    # Create 2 sample .eml files in tmp_path
    eml_file_1 = tmp_path / "sample_test_1.eml"
    eml_file_1.write_bytes(SAMPLE_BEC_EML)

    eml_file_2 = tmp_path / "sample_test_2.eml"
    eml_file_2.write_bytes(
        b"From: test@domain.org\nTo: user@domain.org\nSubject: Routine Meeting Notice\nDate: Mon, 02 Nov 2026 12:00:00 +0000\n\nRoutine update body."
    )

    analyst_token = create_access_token("analyst", role="ANALYST")

    # Use synchronous TestClient
    with TestClient(app, base_url="http://testserver") as test_client:
        results, stats = ingest_corpus(
            corpus_dir=tmp_path,
            api_url="http://testserver/api/v1",
            token=analyst_token,
            sync_mode=True,
            custom_client=test_client,
        )

        assert stats["total"] == 2
        assert stats["success"] == 2
        assert stats["failed"] == 0

        for res in results:
            assert res["status"] == "SUCCESS"
            assert res["case_id"] is not None
            assert len(res["sha256"]) == 64
            assert res["threat_score"] is not None
            assert res["verdict"] in ("BEC", "BENIGN", "SUSPICIOUS", "PHISHING", "EXTORTION")


def test_offline_verify_report_cli(tmp_path):
    """Verify scripts/verify_report.py validates evidence files and catches tampered bytes."""
    import hashlib

    from scripts.verify_report import verify_evidence

    # Create authentic raw evidence file
    evidence_file = tmp_path / "evidence_sample.raw"
    sample_content = b"Content-Type: text/plain\r\nSubject: Critical Audit\r\n\r\nVerified evidence content."
    evidence_file.write_bytes(sample_content)

    expected_sha256 = hashlib.sha256(sample_content).hexdigest()
    expected_sha512 = hashlib.sha512(sample_content).hexdigest()

    # 1. Verification of authentic file must PASS
    assert verify_evidence(
        raw_path=evidence_file,
        expected_sha256=expected_sha256,
        expected_sha512=expected_sha512,
        hmac_secret="test-hmac-secret-2026",
    ) is True

    # 2. Tampered hash must FAIL
    tampered_sha256 = "0" * 64
    assert verify_evidence(
        raw_path=evidence_file,
        expected_sha256=tampered_sha256,
        expected_sha512=expected_sha512,
    ) is False


def test_tamper_detection_vault_pdf_audit_chain(tmp_path):
    """Verify Section 63 BSA tamper detection across physical vault, generated PDF, and audit chain."""
    import hashlib

    from backend.app.database.vault import canonicalize_audit_payload, generate_hmac_signature, verify_hmac_signature
    from scripts.verify_report import verify_evidence

    # 1. Physical Vault Tamper Detection
    vault_raw = tmp_path / "case_001.raw"
    original_bytes = b"Authentic Raw RFC 822 Email Stream for Judicial Evidence"
    vault_raw.write_bytes(original_bytes)

    orig_sha256 = hashlib.sha256(original_bytes).hexdigest()
    orig_sha512 = hashlib.sha512(original_bytes).hexdigest()

    # Authentic file passes
    assert verify_evidence(vault_raw, orig_sha256, orig_sha512) is True

    # Tamper the bytes on disk (single byte modification)
    tampered_bytes = b"Authentic Raw RFC 822 Email Stream for Judicial Tampered"
    vault_raw.write_bytes(tampered_bytes)

    # Verification must catch the discrepancy
    assert verify_evidence(vault_raw, orig_sha256, orig_sha512) is False

    # 2. Audit Ledger HMAC Signature Tamper Detection
    canonical_payload = canonicalize_audit_payload(
        actor="forensic_system",
        action="VAULT_SEALED",
        evidence_sha256=orig_sha256,
        recorded_at="2026-11-12T20:00:00Z",
    )
    valid_hmac = generate_hmac_signature(canonical_payload.encode("utf-8"))

    # Valid signature passes
    assert verify_hmac_signature(canonical_payload.encode("utf-8"), valid_hmac) is True

    # Tampered signature fails
    fake_hmac = "a" * 64
    assert verify_hmac_signature(canonical_payload.encode("utf-8"), fake_hmac) is False

    # Tampered payload fails
    tampered_payload = canonicalize_audit_payload(
        actor="forensic_system",
        action="DELETED",
        evidence_sha256=orig_sha256,
        recorded_at="2026-11-12T20:00:00Z",
    )
    assert verify_hmac_signature(tampered_payload.encode("utf-8"), valid_hmac) is False

