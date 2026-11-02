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
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.ai.nlp_engine import analyze_email_content
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import analyze_url, deobfuscate_ip_literal
from backend.app.database.models import Email
from backend.app.database.session import Base, get_db
from backend.app.forensics.auth_validator import check_alignment, validate_protocol_authentication
from backend.app.forensics.hop_traversal import is_ip_private, reverse_hop_traversal
from backend.app.forensics.ioc_extractor import extract_iocs
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
    """Verify SPF, DKIM, and DMARC alignment validation."""
    auth_header = "mx.ac.in; spf=pass smtp.mailfrom=no-reply@aicte-india.org; dkim=pass header.d=aicte-india.org header.s=k1; dmarc=pass p=reject"
    res = validate_protocol_authentication(
        from_email="no-reply@aicte-india.org",
        return_path="no-reply@aicte-india.org",
        headers_dict={},
        auth_results_header=auth_header,
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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Health Check
        health_resp = await ac.get("/api/v1/health")
        assert health_resp.status_code == 200
        assert health_resp.json()["status"] == "HEALTHY"

        # 2. Ingest & Analyze multipart EML
        files = {"file": ("bec_chairman.eml", io.BytesIO(SAMPLE_BEC_EML), "message/rfc822")}
        post_resp = await ac.post("/api/v1/forensics/analyze", files=files)
        assert post_resp.status_code == 201

        dossier = post_resp.json()
        assert "email" in dossier
        assert "forensic_analysis" in dossier
        assert "header_hops" in dossier

        evidence_id = dossier["email"]["id"]
        assert dossier["forensic_analysis"]["verdict"] == "BEC"
        assert dossier["forensic_analysis"]["threat_score"] >= 90.0

        # 3. Retrieve GeoJSON hops
        hops_resp = await ac.get(f"/api/v1/forensics/evidence/{evidence_id}/hops")
        assert hops_resp.status_code == 200
        geojson = hops_resp.json()
        assert geojson["type"] == "FeatureCollection"
        assert len(geojson["features"]) >= 1

        # 4. Stream Forensic PDF Report
        report_resp = await ac.get(f"/api/v1/forensics/evidence/{evidence_id}/report")
        assert report_resp.status_code == 200
        assert report_resp.headers["content-type"] == "application/pdf"
        assert report_resp.content.startswith(b"%PDF-")

        # 5. Query Campaign Graph
        graph_resp = await ac.get("/api/v1/campaigns/graph")
        assert graph_resp.status_code == 200
        assert "graph" in graph_resp.json()
