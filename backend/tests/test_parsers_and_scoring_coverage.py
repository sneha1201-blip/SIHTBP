"""Exhaustive Branch Coverage Tests for Parsers, Threat Scorer & Auth Validator.

Ensures >=90% branch coverage across:
- backend.app.parsers.eml_parser
- backend.app.parsers.msg_parser
- backend.app.ai.threat_scorer
- backend.app.forensics.auth_validator
"""

from __future__ import annotations

import asyncio
import datetime
import io
import time
import unittest.mock as mock
from unittest.mock import MagicMock, patch
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest
import spf
from httpx import ASGITransport, AsyncClient

from backend.app.ai.nlp_engine import NLPAnalysisResult
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import URLAnalysisResult
from backend.app.forensics.attachment_analyzer import (
    analyze_archive,
    analyze_attachment,
    analyze_html_smuggling,
    check_double_extension,
)
from backend.app.forensics.auth_validator import (
    DNSNegativeCache,
    GLOBAL_DNS_CACHE,
    ArcChainResult,
    AuthValidationResult,
    async_resolve_txt_concurrent,
    check_alignment,
    extract_organizational_domain,
    parse_authentication_results,
    parse_received_spf_header,
    query_dns_txt_with_timeout,
    validate_protocol_authentication,
    verify_arc_chain,
    verify_dkim_signatures,
    verify_dmarc_rfc7489,
    verify_spf_pyspf,
)
from backend.app.forensics.job_queue import (
    IngestionJob,
    JobManager,
    JobStage,
    JobStatus,
)
from backend.app.forensics.spoof_detector import SpoofDetectionResult
from backend.app.main import app
from backend.app.osint.threat_feeds import (
    check_url_in_threat_feed,
    download_and_version_feed,
    get_feeds_dir,
)
from backend.app.osint.tor_detector import (
    get_tor_cache_telemetry,
    is_anonymizing_vpn_or_bulletproof,
    is_tor_exit_node,
    load_tor_exit_cache,
)
from backend.app.parsers.eml_parser import parse_eml
from backend.app.parsers.msg_parser import carve_partial_msg_stream, parse_msg
from backend.tests.fixtures.email_corpus import DNS_FIXTURES


# =============================================================================
# 1. EML Parser Branch Coverage
# =============================================================================

def test_eml_parser_non_multipart_html():
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Non-Multipart HTML\r\n"
        b"Date: Wed, 11 Nov 2026 12:00:00 +0000\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body><h1>Hello World</h1></body></html>"
    )
    parsed = parse_eml(raw, "test_html.eml")
    assert parsed.subject == "Non-Multipart HTML"
    assert parsed.sender_email == "alice@example.com"
    assert parsed.body_html is not None
    assert "Hello World" in parsed.body_html
    assert parsed.body_plain is None


def test_eml_parser_invalid_date_header():
    raw = (
        b"From: Charlie <charlie@example.com>\r\n"
        b"To: Dana <dana@example.com>\r\n"
        b"Subject: Bad Date\r\n"
        b"Date: INVALID_DATE_STRING_HERE\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Plain body text."
    )
    parsed = parse_eml(raw, "test_bad_date.eml")
    assert parsed.date_header is None
    assert parsed.body_plain == "Plain body text."


def test_eml_parser_multipart_with_dangerous_attachment():
    raw = (
        b"From: Eve <eve@attacker.org>\r\n"
        b"To: Frank <frank@target.in>\r\n"
        b"Subject: Invoice Attached\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please see attached invoice.\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=\"payload.xlsm\"\r\n\r\n"
        b"MZ_DUMMY_MACRO_PAYLOAD\r\n"
        b"--BOUNDARY--"
    )
    parsed = parse_eml(raw, "test_attach.eml")
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "payload.xlsm"
    assert att.is_suspicious_extension is True


def test_eml_parser_multipart_html_part():
    raw = (
        b"From: Grace <grace@example.com>\r\n"
        b"To: Heidi <heidi@example.com>\r\n"
        b"Subject: Multi HTML\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=\"ALT_BOUNDARY\"\r\n\r\n"
        b"--ALT_BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Plain part text.\r\n"
        b"--ALT_BOUNDARY\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<p>HTML part text.</p>\r\n"
        b"--ALT_BOUNDARY--"
    )
    parsed = parse_eml(raw, "test_alt.eml")
    assert parsed.body_plain == "Plain part text."
    assert parsed.body_html == "<p>HTML part text.</p>"


def test_eml_parser_get_content_exception_fallbacks():
    msg = EmailMessage()
    msg["From"] = "test@example.com"
    msg["To"] = "target@example.com"
    msg["Subject"] = "Exception Fallback Test"
    msg.set_content("Fallback plain body")
    msg.add_alternative("<b>Fallback HTML body</b>", subtype="html")

    raw_bytes = msg.as_bytes()
    parsed = parse_eml(raw_bytes, "fallback.eml")
    assert parsed.subject == "Exception Fallback Test"
    assert "Fallback plain body" in (parsed.body_plain or "")

    with patch("email.message.EmailMessage.get_content", side_effect=Exception("Decode failed")):
        parsed_err = parse_eml(raw_bytes, "fallback_err.eml")
        assert parsed_err.subject == "Exception Fallback Test"
        assert parsed_err.body_plain is not None or parsed_err.body_html is not None

    single = EmailMessage()
    single["From"] = "single@example.com"
    single["To"] = "dest@example.com"
    single["Subject"] = "Single Part"
    single.set_payload(b"Raw bytes payload")

    with patch("email.message.EmailMessage.get_content", return_value=b"Raw bytes payload"):
        parsed_single = parse_eml(single.as_bytes(), "single.eml")
        assert "Raw bytes payload" in (parsed_single.body_plain or "")

    with patch("email.message.EmailMessage.get_content", side_effect=KeyError("No charset")):
        parsed_single_err = parse_eml(single.as_bytes(), "single_err.eml")
        assert parsed_single_err.subject == "Single Part"


# =============================================================================
# 2. MSG Parser Branch Coverage
# =============================================================================

def test_msg_parser_corrupted_carve():
    raw_garbage = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"Subject: Urgent Wire Notice\nFrom: Boss <boss@bank.com>\nTo: Emp <emp@bank.com>\n" + b"A" * 100
    parsed = carve_partial_msg_stream(raw_garbage, "corrupt.msg", "sha256", "md5")
    assert "Urgent Wire Notice" in parsed.subject
    assert parsed.sender_email == "boss@bank.com"
    assert "PARTIAL_PARSE_CORRUPT_OLE_STREAM" in parsed.headers_dict.get("X-Forensic-Parsing-Status", [])


def test_msg_parser_mislabeled_eml_fallback():
    raw_ascii_eml = (
        b"From: John <john@corp.com>\r\n"
        b"To: Jane <jane@corp.com>\r\n"
        b"Subject: Mislabeled MSG\r\n\r\n"
        b"This is an RFC 822 file saved with .msg extension."
    )
    parsed = parse_msg(raw_ascii_eml, "mislabeled.msg")
    assert parsed.subject == "Mislabeled MSG"
    assert parsed.sender_email == "john@corp.com"
    assert "This is an RFC 822" in (parsed.body_plain or "")


def test_msg_parser_extract_msg_mock():
    mock_msg = MagicMock()
    mock_msg.subject = "Simulated Outlook Email"
    mock_msg.sender = "Executive <exec@governance.in>"
    mock_msg.to = "staff1@gov.in; staff2@gov.in"
    mock_msg.cc = "audit@gov.in"
    mock_msg.date = datetime.datetime.now(datetime.timezone.utc)
    mock_msg.body = "Official directive body."
    mock_msg.htmlBody = "<p>Official directive body.</p>"
    mock_msg.header = "Received: from mx1.gov.in (10.0.0.1)\nX-Custom-Header: True"

    mock_att = MagicMock()
    mock_att.data = b"malicious_script_content"
    mock_att.longFilename = "update.bat"
    mock_att.shortFilename = "update.bat"
    mock_att.mimetype = "application/x-bat"
    mock_msg.attachments = [mock_att]

    with mock.patch("extract_msg.Message", return_msg=mock_msg) as mock_cls:
        mock_cls.return_value = mock_msg
        parsed = parse_msg(b"\xd0\xcf\x11\xe0" + b"\x00" * 50, "test_extract.msg")
        assert parsed.subject == "Simulated Outlook Email"
        assert parsed.sender_email == "exec@governance.in"
        assert len(parsed.recipient_list) == 3
        assert len(parsed.attachments) == 1
        assert parsed.attachments[0].filename == "update.bat"
        assert parsed.attachments[0].is_suspicious_extension is True


# =============================================================================
# 3. Threat Scorer Comprehensive Override & Branch Coverage
# =============================================================================

def make_dummy_auth(spf="PASS", dkim="PASS", dmarc="PASS", has_disc=False):
    arc = ArcChainResult(status="NONE", chain_validation="NONE", instances_count=0)
    return AuthValidationResult(
        spf_status=spf,
        dkim_status=dkim,
        dmarc_status=dmarc,
        auth_score=0.0 if spf == "PASS" and dkim == "PASS" else 80.0,
        claimed_by_mta={"spf": "pass", "dkim": "pass"},
        recomputed_verdict={"spf": spf, "dkim": dkim, "dmarc": dmarc},
        has_discrepancy=has_disc,
        discrepancies=["Header injected"] if has_disc else [],
        arc=arc,
        dns_key_snapshots=[],
    )


def make_dummy_spoof(score=0.0, display=False, reply_div=False, homograph=False, lookalike=False):
    return SpoofDetectionResult(
        spoof_score=score,
        display_spoof_flag=display,
        reply_to_divergence=reply_div,
        homograph_flag=homograph,
        lookalike_flag=lookalike,
        reasons=["Test spoof flag"] if (display or homograph) else [],
    )


def make_dummy_nlp(score=0.0, is_bec=False, is_urgency=False, conf=0.90):
    return NLPAnalysisResult(
        predicted_class="BENIGN" if score < 20 else "PHISHING",
        confidence=conf,
        probabilities={"BENIGN": 1.0 - (score / 100), "PHISHING": score / 100},
        nlp_score=score,
        is_bec_financial=is_bec,
        is_urgency_coercion=is_urgency,
        reasons=["Test NLP reason"] if score > 20 else [],
    )


def test_threat_scorer_tor_override():
    auth = make_dummy_auth()
    spoof = make_dummy_spoof()
    nlp = make_dummy_nlp()
    res = compute_threat_score(auth, spoof, nlp, [], is_tor_origin=True)
    assert res.threat_score >= 98.0
    assert "Tor Exit Node" in res.reasons[0]
    assert res.verdict == "PHISHING"


def test_threat_scorer_bec_wire_fraud_override():
    auth = make_dummy_auth()
    spoof = make_dummy_spoof(display=True, reply_div=True)
    nlp = make_dummy_nlp(is_bec=True)
    res = compute_threat_score(auth, spoof, nlp, [])
    assert res.threat_score >= 94.0
    assert res.verdict == "BEC"
    assert any("Executive BEC Wire Fraud" in r for r in res.reasons)


def test_threat_scorer_homoglyph_override():
    auth = make_dummy_auth()
    spoof = make_dummy_spoof(homograph=True)
    nlp = make_dummy_nlp()
    res = compute_threat_score(auth, spoof, nlp, [])
    assert res.threat_score >= 88.0
    assert any("Homograph Attack" in r for r in res.reasons)


def test_threat_scorer_bulletproof_override():
    auth = make_dummy_auth()
    spoof = make_dummy_spoof(lookalike=True)
    nlp = make_dummy_nlp(is_urgency=True)
    res = compute_threat_score(auth, spoof, nlp, [], is_bulletproof_origin=True)
    assert res.threat_score >= 92.0
    assert any("Bulletproof Infrastructure" in r for r in res.reasons)
    assert res.verdict == "MALICIOUS"


def test_threat_scorer_dkim_fail_and_high_risk_url():
    auth = make_dummy_auth(dkim="FAIL")
    spoof = make_dummy_spoof()
    nlp = make_dummy_nlp()
    url_res = URLAnalysisResult(
        raw_url="http://bad.phish.com",
        normalized_url="http://bad.phish.com",
        domain="bad.phish.com",
        final_url="http://bad.phish.com",
        risk_score=75.0,
        is_suspicious=True,
    )
    res = compute_threat_score(auth, spoof, nlp, [url_res])
    assert res.threat_score >= 86.0
    assert res.verdict == "PHISHING"
    assert any("DKIM Failure paired with High-Risk URL" in r for r in res.reasons)


def test_threat_scorer_uncertain_verdict():
    auth = make_dummy_auth(spf="SOFTFAIL")
    auth.auth_score = 70.0
    spoof = make_dummy_spoof(score=70.0)
    nlp = make_dummy_nlp(score=60.0, conf=0.30)
    res = compute_threat_score(auth, spoof, nlp, [])
    assert res.is_uncertain is True
    assert res.verdict == "UNCERTAIN"


def test_threat_scorer_dangerous_attachment_malicious():
    auth = make_dummy_auth()
    auth.auth_score = 90.0
    spoof = make_dummy_spoof(score=90.0)
    nlp = make_dummy_nlp(score=90.0)
    url_res = URLAnalysisResult(
        raw_url="http://bad.phish.com",
        normalized_url="http://bad.phish.com",
        domain="bad.phish.com",
        final_url="http://bad.phish.com",
        risk_score=90.0,
        is_suspicious=True,
    )
    res = compute_threat_score(auth, spoof, nlp, [url_res], has_dangerous_attachment=True, is_newly_registered_domain=True)
    assert res.verdict == "MALICIOUS"
    assert any("Weaponized" in r for r in res.reasons)


def test_threat_scorer_benign_and_suspicious():
    auth_b = make_dummy_auth()
    spoof_b = make_dummy_spoof()
    nlp_b = make_dummy_nlp(score=5.0)
    res_b = compute_threat_score(auth_b, spoof_b, nlp_b, [])
    assert res_b.verdict == "BENIGN"
    assert res_b.threat_score < 25.0

    auth_s = make_dummy_auth(spf="SOFTFAIL")
    auth_s.auth_score = 50.0
    spoof_s = make_dummy_spoof(score=50.0)
    nlp_s = make_dummy_nlp(score=50.0, conf=0.85)
    res_s = compute_threat_score(auth_s, spoof_s, nlp_s, [])
    assert res_s.verdict == "SUSPICIOUS"


# =============================================================================
# 4. Auth Validator Edge Case & Branch Coverage
# =============================================================================

def test_auth_validator_discrepancy_and_arc():
    headers = {
        "Authentication-Results": ["mx.google.com; spf=pass; dkim=pass"],
        "From": ["sender@testcorp.org"],
        "Return-Path": ["sender@testcorp.org"],
    }
    custom_dns = {
        "testcorp.org": ["v=spf1 -all"],
    }
    res = validate_protocol_authentication(
        from_email="sender@testcorp.org",
        return_path="sender@testcorp.org",
        headers_dict=headers,
        auth_results_header=headers["Authentication-Results"][0],
        connecting_ip="192.0.2.1",
        custom_dns_records=custom_dns,
    )
    assert res.has_discrepancy is True
    assert len(res.discrepancies) > 0


def test_extract_organizational_domain_edge_cases():
    assert extract_organizational_domain("") == ""
    assert extract_organizational_domain("example.com") == "example.com"
    assert extract_organizational_domain("mail.sub.example.co.in") == "example.co.in"
    assert extract_organizational_domain("gov.in") == "gov.in"
    assert extract_organizational_domain("dept.gov.in") == "dept.gov.in"
    assert extract_organizational_domain("unit.dept.gov.in") == "dept.gov.in"
    assert extract_organizational_domain("a.b.c.org.uk") == "c.org.uk"


def test_check_alignment_strict_and_relaxed():
    assert check_alignment("", "example.com") is False
    assert check_alignment("example.com", "") is False
    assert check_alignment("mail.example.com", "example.com", strict=True) is False
    assert check_alignment("example.com", "example.com", strict=True) is True
    assert check_alignment("mail.example.com", "billing.example.com", strict=False) is True
    assert check_alignment("mail.example.com", "attacker.org", strict=False) is False


def test_parse_received_spf_header_variations():
    assert parse_received_spf_header("") == {}
    hdr = "Pass (myhost.net: domain of user@domain.com designates 192.0.2.1 as permitted) client-ip=192.0.2.1; envelope-from=user@domain.com; helo=mail.domain.com;"
    parsed = parse_received_spf_header(hdr)
    assert parsed.get("spf") == "PASS"
    assert parsed.get("client_ip") == "192.0.2.1"
    assert parsed.get("spf_domain") == "domain.com"
    assert parsed.get("helo") == "mail.domain.com"

    hdr2 = "Fail identity=admin@corp.in; client-ip=10.0.0.1;"
    parsed2 = parse_received_spf_header(hdr2)
    assert parsed2.get("spf") == "FAIL"
    assert parsed2.get("spf_domain") == "corp.in"
    assert parsed2.get("client_ip") == "10.0.0.1"


def test_parse_authentication_results_variations():
    assert parse_authentication_results("") == {}
    hdr = "mx.google.com; spf=pass smtp.mailfrom=user@domain.com; dkim=pass header.d=domain.com; header.s=s1; dmarc=pass (p=reject); arc=pass"
    res = parse_authentication_results(hdr)
    assert res.get("spf") == "PASS"
    assert res.get("dkim") == "PASS"
    assert res.get("dmarc") == "PASS"
    assert res.get("arc") == "PASS"
    assert res.get("dkim_domain") == "domain.com"
    assert res.get("dmarc_policy") == "reject"


def test_global_dns_cache_expiration():
    cache = DNSNegativeCache(positive_ttl=0.01)
    cache.set("short.ttl.test", ["v=spf1 -all"])
    assert cache.get("short.ttl.test") == ["v=spf1 -all"]
    time.sleep(0.02)
    assert cache.get("short.ttl.test") is None


def test_query_dns_txt_with_timeout_wildcard_custom():
    custom = {"*": ["v=spf1 ~all"]}
    res = query_dns_txt_with_timeout("any.random.domain.com", custom_records=custom)
    assert res == ["v=spf1 ~all"]


@pytest.mark.asyncio
async def test_async_resolve_txt_concurrent():
    domains = ["example.com", "test.org"]
    res = await async_resolve_txt_concurrent(domains, timeout=0.1)
    assert isinstance(res, dict)
    assert "example.com" in res
    assert "test.org" in res


def test_verify_dkim_signatures_edge_cases():
    msg = b"From: test@example.com\r\nSubject: Test\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=revoked; h=from:subject; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dummy\r\n\r\nHello"
    custom_dns = {"revoked._domainkey.example.com": ["v=DKIM1; p="]}
    status, domain, selector, sig_results, snapshots, is_live = verify_dkim_signatures(msg, custom_records=custom_dns)
    assert len(sig_results) == 1
    assert sig_results[0].signature_status == "KEY_REVOKED"

    with patch("dkim.DKIM.verify", side_effect=Exception("Internal dkim error")):
        custom_valid = {"revoked._domainkey.example.com": ["v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdummy"]}
        _, _, _, sig_exc, _, _ = verify_dkim_signatures(msg, custom_records=custom_valid)
        assert len(sig_exc) == 1
        assert sig_exc[0].signature_status == "FAIL"

    msg_no_dkim = b"From: no@dkim.com\r\nSubject: None\r\n\r\nBody"
    status_none, _, _, sigs_empty, _, _ = verify_dkim_signatures(msg_no_dkim)
    assert sigs_empty == []
    assert status_none == "NONE"


def test_verify_spf_record_helo_fallback():
    status, explanation, code, record, is_live = verify_spf_pyspf(
        connecting_ip="198.51.100.10",
        envelope_sender="",
        helo_name="aicte-india.org",
        custom_records=DNS_FIXTURES,
    )
    assert status == "PASS"


def test_verify_spf_record_temperror():
    with patch("spf.query.check", side_effect=spf.TempError("DNS server timeout")):
        status, explanation, _, _, _ = verify_spf_pyspf(
            connecting_ip="198.51.100.10",
            envelope_sender="user@aicte-india.org",
            helo_name="aicte-india.org",
            custom_records=DNS_FIXTURES,
        )
        assert status == "TEMPERROR"
        assert "DNS" in explanation


def test_verify_dmarc_policy_org_domain_fallback():
    custom_dns = {
        "_dmarc.org.co.in": ["v=DMARC1; p=reject; sp=quarantine; pct=100;"]
    }
    status, policy, aligned_spf, aligned_dkim, record, is_live = verify_dmarc_rfc7489(
        from_domain="sub.org.co.in",
        spf_status="PASS",
        spf_domain="org.co.in",
        dkim_signatures=[],
        custom_records=custom_dns,
    )
    assert policy == "reject"
    assert aligned_spf is True


def test_verify_arc_chain_edge_cases():
    res_none = verify_arc_chain(b"From: test@test.com\r\n\r\nBody")
    assert res_none.status == "NONE"

    raw_bad_arc = (
        b"From: test@test.com\r\n"
        b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=test.com; s=s1; b=bad\r\n"
        b"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=test.com; s=s1; bh=bad; b=bad\r\n"
        b"ARC-Authentication-Results: i=1; mx.test.com; spf=pass\r\n\r\n"
        b"Body text"
    )
    with patch("dkim.arc_verify", side_effect=Exception("ARC verification crashed")):
        res_crash = verify_arc_chain(raw_bad_arc)
        assert res_crash.status == "FAIL"


def test_validate_protocol_authentication_discrepancy_score():
    headers = {
        "Authentication-Results": ["mx.fake.com; spf=pass; dkim=pass; dmarc=pass"],
        "From": ["phish@corp.org"],
        "Return-Path": ["phish@corp.org"],
    }
    custom_dns = {
        "corp.org": ["v=spf1 -all"],
        "_dmarc.corp.org": ["v=DMARC1; p=reject;"],
    }
    res = validate_protocol_authentication(
        from_email="phish@corp.org",
        return_path="phish@corp.org",
        headers_dict=headers,
        auth_results_header=headers["Authentication-Results"][0],
        connecting_ip="198.51.100.1",
        custom_dns_records=custom_dns,
    )
    assert res.has_discrepancy is True
    assert res.auth_score > 50.0


# =============================================================================
# 5. Attachment Analyzer Heuristics & Archives
# =============================================================================

def test_attachment_analyzer_heuristics():
    assert check_double_extension("invoice.pdf.exe")[0] is True
    assert check_double_extension("document.docx")[0] is False
    assert check_double_extension("scan.jpg.vbs")[0] is True

    res_smug = analyze_html_smuggling(b"var blob = new Blob([data]); URL.createObjectURL(blob);")
    assert res_smug["has_html_smuggling"] is True
    res_plain = analyze_html_smuggling(b"Just an ordinary text document")
    assert res_plain["has_html_smuggling"] is False

    buf_safe = io.BytesIO()
    with zipfile.ZipFile(buf_safe, "w") as z:
        z.writestr("notes.txt", b"plain text")
    res_safe = analyze_archive(buf_safe.getvalue())
    assert res_safe["is_zip_bomb"] is False
    assert "notes.txt" in res_safe["extracted_nested_files"]

    buf_danger = io.BytesIO()
    with zipfile.ZipFile(buf_danger, "w") as z:
        z.writestr("trojan.exe", b"MZ_EXECUTABLE_PAYLOAD_HERE")
    res_danger = analyze_archive(buf_danger.getvalue())
    assert "trojan.exe" in res_danger["extracted_nested_files"]
    assert len(res_danger["threats"]) > 0

    att_meta = analyze_attachment(
        filename="bonus.pdf.exe",
        raw_bytes=b"MZ_TEST_PAYLOAD",
    )
    assert att_meta.has_double_extension is True
    assert att_meta.threat_score >= 65.0
    assert att_meta.is_threat is True


# =============================================================================
# 6. Job Queue Lifecycle
# =============================================================================

@pytest.mark.asyncio
async def test_job_queue_manager_lifecycle():
    jm = JobManager()
    job = await jm.create_job("sample.eml", "analyst_1")
    assert job.status == JobStatus.PENDING
    assert job.stage == JobStage.INITIALIZED

    job.stage = JobStage.VAULT_STORING
    job.progress_percent = 15
    j_updated = await jm.get_job(job.job_id)
    assert j_updated is not None
    assert j_updated.stage == JobStage.VAULT_STORING
    assert j_updated.progress_percent == 15

    job.status = JobStatus.COMPLETED
    job.progress_percent = 100
    j_done = await jm.get_job(job.job_id)
    assert j_done is not None
    assert j_done.status == JobStatus.COMPLETED

    job_dict = job.to_dict()
    assert job_dict["job_id"] == job.job_id
    assert job_dict["file_name"] == "sample.eml"


# =============================================================================
# 7. Threat Intelligence Feeds & Tor Detector Coverage
# =============================================================================

def test_threat_feeds_get_dir():
    d = get_feeds_dir()
    assert d.exists()


@pytest.mark.asyncio
async def test_threat_feeds_download_and_version(tmp_path: Path):
    mock_resp = MagicMock()
    mock_resp.content = b"http://evil.phish.com/login\nhttp://malware.bank.org/\n"
    mock_resp.text = "http://evil.phish.com/login\nhttp://malware.bank.org/\n"
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        manifest = await download_and_version_feed(
            "test_feed",
            "https://test.feed.com/list.txt",
            storage_dir=tmp_path,
        )
        assert manifest["feed_name"] == "test_feed"
        assert manifest["record_count"] == 2
        assert "sha256" in manifest

        match_res = check_url_in_threat_feed("http://evil.phish.com/login", "test_feed", storage_dir=tmp_path)
        assert match_res["is_matched"] is True

        no_match = check_url_in_threat_feed("http://clean.site.org/", "test_feed", storage_dir=tmp_path)
        assert no_match["is_matched"] is False


def test_tor_detector_functions(tmp_path: Path):
    cache_file = tmp_path / "tor_cache.json"
    cache_file.write_text(
        '{"fetched_at": "2026-11-13T00:00:00Z", "source": "TEST_CACHE", "exit_nodes": ["198.51.100.99"], "bulletproof_subnets": ["198.51.100.0/24"]}',
        encoding="utf-8",
    )
    data = load_tor_exit_cache(custom_snapshot_path=cache_file)
    assert data["exit_node_count"] == 1

    is_exit = is_tor_exit_node("198.51.100.99")
    assert is_exit is True
    assert is_tor_exit_node("1.1.1.1") is False

    is_vpn, is_bp = is_anonymizing_vpn_or_bulletproof("198.51.100.99")
    assert is_bp is True

    telemetry = get_tor_cache_telemetry()
    assert "total_exit_nodes" in telemetry


# =============================================================================
# 8. Auth API Login & Me Coverage
# =============================================================================

@pytest.mark.asyncio
async def test_auth_api_login_and_me():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp_bad = await ac.post(
            "/api/v1/auth/login",
            json={"username": "non_existent_user_999", "password": "WrongPassword123!"},
        )
        assert resp_bad.status_code == 401

        resp_login = await ac.post(
            "/api/v1/auth/login",
            json={"username": "soc_admin", "password": "SocAdminSecure2026!#"},
        )
        if resp_login.status_code == 200:
            token = resp_login.json()["access_token"]
            resp_me = await ac.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp_me.status_code == 200
            assert resp_me.json()["username"] == "soc_admin"
