"""Exhaustive Branch Coverage Tests for Parsers, Threat Scorer & Auth Validator.

Ensures >=90% branch coverage across:
- backend.app.parsers.eml_parser
- backend.app.parsers.msg_parser
- backend.app.ai.threat_scorer
- backend.app.forensics.auth_validator
"""

from __future__ import annotations

import datetime
import io
import time
import unittest.mock as mock
import uuid
import zipfile
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import spf
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from backend.app.ai.nlp_engine import NLPAnalysisResult
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import (
    URLAnalysisResult,
    analyze_url,
    deobfuscate_ip_literal,
    is_ssrf_forbidden_host,
    normalize_defanged_url,
)
from backend.app.core.security import (
    check_login_lockout,
    constant_time_compare,
    create_access_token,
    decode_access_token,
    generate_nonce,
    hash_password,
    record_login_attempt,
    sign_audit_entry,
    validate_password_strength,
    verify_password,
)
from backend.app.core.upload_validator import (
    OLE_MSG_MAGIC,
    sanitize_filename,
    validate_email_bytes,
)
from backend.app.database.models import Campaign, Email, ThreatIndicator
from backend.app.forensics.attachment_analyzer import (
    analyze_archive,
    analyze_attachment,
    analyze_html_smuggling,
    analyze_office_macros,
    check_double_extension,
)
from backend.app.forensics.auth_validator import (
    ArcChainResult,
    AuthValidationResult,
    DNSNegativeCache,
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
from backend.app.forensics.campaign_clusterer import (
    ensure_utc,
    evaluate_pairwise_signals,
    extract_subnet_24,
    generate_stix21_bundle,
    is_high_fanout_asn,
)
from backend.app.forensics.ioc_extractor import defang_ioc, extract_iocs
from backend.app.forensics.job_queue import (
    JobManager,
    JobStage,
    JobStatus,
)
from backend.app.forensics.spoof_detector import (
    SpoofDetectionResult,
    check_cousin_domain,
    detect_homograph,
    detect_spoofing,
    levenshtein_distance,
)
from backend.app.main import app
from backend.app.osint.asn_lookup import resolve_ip_asn
from backend.app.osint.dnsbl_checker import query_dnsbl, reverse_ip_for_dnsbl
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
from backend.app.osint.whois_client import parse_rdap_response
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
        b'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n\r\n'
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please see attached invoice.\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="payload.xlsm"\r\n\r\n'
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
        b'Content-Type: multipart/alternative; boundary="ALT_BOUNDARY"\r\n\r\n'
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
    raw_garbage = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        + b"Subject: Urgent Wire Notice\nFrom: Boss <boss@bank.com>\nTo: Emp <emp@bank.com>\n"
        + b"A" * 100
    )
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
    res = compute_threat_score(
        auth, spoof, nlp, [url_res], has_dangerous_attachment=True, is_newly_registered_domain=True
    )
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
    status, domain, lookups, explanation, is_live = verify_spf_pyspf(
        connecting_ip="198.51.100.10",
        envelope_sender="",
        helo_name="aicte-india.org",
        custom_records=DNS_FIXTURES,
    )
    assert status == "PASS"


def test_verify_spf_record_temperror():
    with patch("spf.query.check", side_effect=spf.TempError("DNS server timeout")):
        status, domain, lookups, explanation, is_live = verify_spf_pyspf(
            connecting_ip="198.51.100.10",
            envelope_sender="user@aicte-india.org",
            helo_name="aicte-india.org",
            custom_records=DNS_FIXTURES,
        )
        assert status == "TEMPERROR"
        assert domain == "aicte-india.org"
        assert "DNS" in explanation


def test_verify_dmarc_policy_org_domain_fallback():
    custom_dns = {"_dmarc.org.co.in": ["v=DMARC1; p=reject; sp=quarantine; pct=100;"]}
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


# =============================================================================
# 9. Deep Edge-Case Branch Coverage for Core Modules
# =============================================================================


def test_auth_validator_deep_branches():
    # 1. Fallback organizational domain parsing when publicsuffix returns empty
    with patch("publicsuffix2.get_sld", return_value=""):
        assert extract_organizational_domain("portal.aicte.gov.in") == "aicte.gov.in"
        assert extract_organizational_domain("sub.bank.co.uk") == "bank.co.uk"
        assert extract_organizational_domain("my.example.com") == "example.com"
        assert extract_organizational_domain("localhost") == "localhost"

    # 2. Alignment with empty arguments
    assert check_alignment("", "example.com") is False
    assert check_alignment("example.com", "") is False

    # 3. DNS TXT queries with empty or single-label domain
    assert query_dns_txt_with_timeout("") == []
    assert query_dns_txt_with_timeout("singlelabel") == []

    # 4. Mock resolver returning byte strings
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"v=spf1 ", "include:_spf.google.com ~all"]
    mock_ans = [mock_rdata]
    with patch("dns.resolver.Resolver.resolve", return_value=mock_ans):
        res = query_dns_txt_with_timeout("test-mock-dns.org", custom_records=None)
        assert len(res) == 1
        assert "v=spf1" in res[0]

    # 5. DKIM parser error handling & malformed tags
    raw_bad_dkim = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1; "
        b"x=invalid_non_int; l=invalid_non_int; h=from; b=fake==\r\n\r\n"
        b"Body content\r\n"
    )
    status, sel, dom, dkim_res, dns_snaps, live = verify_dkim_signatures(
        raw_bad_dkim,
        dnsfunc=lambda name: None,
    )
    assert status in ["NONE", "FAIL", "INVALID", "KEY_UNAVAILABLE"]

    # 6. SPF PermError and generic exception branches
    with patch("spf.query.check", side_effect=spf.PermError("Invalid SPF syntax")):
        st, dom, lk, expl, _ = verify_spf_pyspf(
            connecting_ip="93.184.216.34",
            envelope_sender="test@bad-spf.org",
            helo_name="bad-spf.org",
            custom_records={},
        )
        assert st == "PERMERROR"
        assert dom == "bad-spf.org"

    with patch("spf.query.check", side_effect=RuntimeError("Unexpected crash")):
        st, dom, lk, expl, _ = verify_spf_pyspf(
            connecting_ip="93.184.216.34",
            envelope_sender="test@bad-spf.org",
            helo_name="bad-spf.org",
            custom_records={},
        )
        assert st == "UNVERIFIABLE"

    # 7. DMARC empty from_domain
    dmarc_status, dmarc_pol, _, _, _, _ = verify_dmarc_rfc7489(
        from_domain="",
        spf_status="PASS",
        spf_domain="example.com",
        dkim_signatures=[],
    )
    assert dmarc_status == "NONE"


def test_campaign_clusterer_deep_branches():
    # 1. ensure_utc with None and naive datetime
    now_utc = ensure_utc(None)
    assert now_utc.tzinfo is not None
    naive = datetime.datetime(2026, 5, 1, 12, 0, 0)
    aware = ensure_utc(naive)
    assert aware.tzinfo == datetime.timezone.utc

    # 2. extract_subnet_24 variations
    assert extract_subnet_24(None) is None
    assert extract_subnet_24("10.0.0.1") is None  # private
    assert extract_subnet_24("127.0.0.1") is None  # loopback
    assert extract_subnet_24("93.184.216.34") == "93.184.216.0/24"
    assert extract_subnet_24("2607:f8b0:4005:805::200e") == "2607:f8b0:4005::/48"
    assert extract_subnet_24("invalid_ip") is None

    # 3. is_high_fanout_asn
    assert is_high_fanout_asn(None) is False
    assert is_high_fanout_asn(16509) is True  # Amazon in settings
    assert is_high_fanout_asn(99999, "Cloudflare CDN") is True
    assert is_high_fanout_asn(12345, "Small Local ISP") is False

    # 4. STIX Campaign Bundle with diverse indicator types
    camp = Campaign(
        id=uuid.uuid4(),
        name="Test Campaign Alpha",
        description="Forensic investigation cluster",
        cluster_type="INFRASTRUCTURE",
        cluster_key="AS12345",
        severity="HIGH",
        first_seen=datetime.datetime.now(datetime.timezone.utc),
        last_seen=datetime.datetime.now(datetime.timezone.utc),
        total_emails=1,
    )
    em = Email(
        id=uuid.uuid4(),
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5_hash="d41d8cd98f00b204e9800998ecf8427e",
        file_name="test.eml",
        file_size_bytes=100,
        raw_storage_path="vault/test.eml",
        sender_email="attacker@malicious.org",
        sender_raw="attacker@malicious.org",
        recipient_list=["victim@aicte-india.org"],
        subject="Urgent Payment Action",
    )
    iocs = [
        ThreatIndicator(ioc_type="URL", ioc_value="http://phish.bad/login"),
        ThreatIndicator(ioc_type="DOMAIN", ioc_value="phish.bad"),
        ThreatIndicator(ioc_type="IP", ioc_value="198.51.100.99"),
        ThreatIndicator(ioc_type="EMAIL", ioc_value="dropper@bad.net"),
    ]
    em.threat_indicators = iocs
    bundle = generate_stix21_bundle(camp, [em])
    assert bundle["type"] == "bundle"
    assert any(obj.get("type") == "indicator" for obj in bundle.get("objects", []))

    # 5. evaluate_pairwise_signals with cur_iocs=None
    em2 = Email(
        id=uuid.uuid4(),
        sha256_hash="a" * 64,
        md5_hash="0" * 32,
        file_name="test2.eml",
        file_size_bytes=100,
        raw_storage_path="vault/test2.eml",
        sender_email="attacker@malicious.org",
        sender_raw="attacker@malicious.org",
        recipient_list=["victim2@aicte-india.org"],
        subject="Urgent Payment Action 2",
    )
    em2.threat_indicators = []
    sigs, score, is_clustered = evaluate_pairwise_signals(
        em,
        "198.51.100.1",
        12345,
        em2,
        "198.51.100.2",
        12345,
        "Local ISP",
        cur_iocs=None,
    )
    assert isinstance(score, float)


def test_spoof_detector_deep_branches():
    # 1. levenshtein_distance edge cases
    assert levenshtein_distance("hello", "") == 5
    assert levenshtein_distance("", "world") == 5

    # 2. detect_homograph empty and invalid
    is_hg, glyphs, puny = detect_homograph("")
    assert is_hg is False
    assert puny == ""

    # 3. check_cousin_domain empty and keyword matches
    assert check_cousin_domain("", ["google.com"]) == (False, None)
    is_lk, target = check_cousin_domain("portal-aicte-india.org", ["aicte-india.org"])
    assert is_lk is True
    assert target == "aicte-india.org"

    # 4. detect_spoofing with Return-Path and non-freemail Reply-To divergence
    res = detect_spoofing(
        sender_display="Chief Executive",
        sender_email="ceo@targetcorp.org",
        reply_to="attacker@diverted-domain.com",
        return_path="bounces@external-infrastructure.com",
        protected_domains=["targetcorp.org"],
    )
    assert res.reply_to_divergence is True
    assert res.spoof_score >= 40.0
    assert any("Return-Path" in r for r in res.reasons)


def test_url_analyzer_deep_branches():
    # 1. deobfuscate_ip_literal
    assert deobfuscate_ip_literal("2130706433") == "127.0.0.1"
    assert deobfuscate_ip_literal("0x7f000001") == "127.0.0.1"
    assert deobfuscate_ip_literal("0177.0.0.1") == "127.0.0.1"
    assert deobfuscate_ip_literal("not_an_ip") is None

    # 2. normalize_defanged_url
    assert normalize_defanged_url("hxxps://malicious[.]org/login") == "https://malicious.org/login"
    assert normalize_defanged_url("h**p://bad(.)com/path[:]80") == "http://bad.com/path:80"

    # 3. is_ssrf_forbidden_host
    assert is_ssrf_forbidden_host("127.0.0.1")[0] is True
    assert is_ssrf_forbidden_host("169.254.169.254")[0] is True
    assert is_ssrf_forbidden_host("8.8.8.8")[0] is False

    # 4. analyze_url on hostile TLD, credential keywords and payload extensions
    url_res = analyze_url("http://2130706433/login/verify.php?auth=account&download=malware.exe")
    assert url_res.has_credential_lure is True
    assert url_res.is_ip_host is True
    assert url_res.risk_score >= 50.0

    url_res2 = analyze_url("http://update-secure-account.xyz/banking/auth")
    assert url_res2.risk_score >= 40.0


def test_attachment_analyzer_deep_branches():
    # 1. check_double_extension
    is_dbl, reason = check_double_extension("invoice.pdf.exe")
    assert is_dbl is True
    assert "Double extension" in reason

    is_single_exe, reason = check_double_extension("tool.exe")
    assert is_single_exe is False

    is_clean, reason = check_double_extension("document.pdf")
    assert is_clean is False

    # 2. analyze_archive: valid zip, script inside, and bad zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("clean.txt", "harmless text")
        zf.writestr("nested.bat", "@echo off\r\ndel C:\\\r\n")
    archive_res = analyze_archive(buf.getvalue())
    assert any("Executable script" in t for t in archive_res["threats"])

    bad_archive = analyze_archive(b"Not a zip file at all")
    assert bad_archive["is_zip_bomb"] is False

    # 3. analyze_html_smuggling
    html_payload = """
    <html>
      <script>
        var blob = new Blob([atob("VGhpcyBpcyBhIHRlc3Q=")], {type: 'application/octet-stream'});
        var url = window.URL.createObjectURL(blob);
      </script>
    </html>
    """
    smuggle_res = analyze_html_smuggling(html_payload.encode("utf-8"))
    assert smuggle_res["has_html_smuggling"] is True

    # 4. analyze_office_macros with mock
    mock_macro = MagicMock()
    mock_macro.detect_vba_macros.return_value = True
    mock_macro.extract_macros.return_value = [("code", "stream", "filename", "AutoOpen Shell cmd.exe")]
    with patch("oletools.olevba.VBA_Parser", return_value=mock_macro):
        macro_res = analyze_office_macros(b"Fake OLE document bytes")
        assert macro_res["has_macros"] is True
        assert macro_res["macro_auto_exec"] is True


@pytest.mark.asyncio
async def test_job_queue_exhaustive_branches():
    mgr = JobManager()
    job = await mgr.create_job("sample_raw_bytes_email.eml", "analyst_1")
    assert job.status == JobStatus.PENDING
    assert job.file_name == "sample_raw_bytes_email.eml"

    job_ret = await mgr.get_job(job.job_id)
    assert job_ret is not None
    assert job_ret.job_id == job.job_id

    job.status = JobStatus.PROCESSING
    job.stage = JobStage.HOP_TRAVERSAL
    job.progress_percent = 25
    d = job.to_dict()
    assert d["status"] == JobStatus.PROCESSING
    assert d["stage"] == JobStage.HOP_TRAVERSAL
    assert d["progress_percent"] == 25

    job.status = JobStatus.FAILED
    job.error = "Simulated worker failure"
    d_fail = job.to_dict()
    assert d_fail["error"] == "Simulated worker failure"


def test_osint_services_deep_branches():
    # 1. reverse_ip_for_dnsbl
    assert reverse_ip_for_dnsbl("198.51.100.25") == "25.100.51.198"
    assert reverse_ip_for_dnsbl("invalid_ip") is None

    # 2. parse_rdap_response
    mock_rdap = {
        "handle": "DOMAIN-12345",
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-01-15T00:00:00Z"},
        ],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy"]]]}],
    }
    intel = parse_rdap_response("example.org", mock_rdap)
    assert intel.domain == "example.org"
    assert intel.registrar == "GoDaddy"


@pytest.mark.asyncio
async def test_api_v1_campaigns_and_forensics_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Login
        resp_login = await ac.post(
            "/api/v1/auth/login",
            json={"username": "soc_admin", "password": "SocAdminSecure2026!#"},
        )
        if resp_login.status_code == 200:
            token = resp_login.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # 1. Campaign endpoints
            resp_camps = await ac.get("/api/v1/campaigns", headers=headers)
            assert resp_camps.status_code == 200

            resp_graph = await ac.get("/api/v1/campaigns/graph", headers=headers)
            assert resp_graph.status_code == 200

            resp_stix = await ac.get("/api/v1/campaigns/stix", headers=headers)
            assert resp_stix.status_code == 200

            # 2. Forensics ledger & sweep
            resp_ledger = await ac.get("/api/v1/forensics/ledger/verify", headers=headers)
            assert resp_ledger.status_code in [200, 404]

            resp_sweep = await ac.post("/api/v1/forensics/vault/sweep", headers=headers)
            assert resp_sweep.status_code in [200, 404]

            # 3. Auth refresh & users
            resp_refresh = await ac.post("/api/v1/auth/refresh", json={"token": token})
            assert resp_refresh.status_code in [200, 401]

            resp_users = await ac.get("/api/v1/auth/users", headers=headers)
            assert resp_users.status_code in [200, 403]

            # 4. Reports endpoints
            resp_rep_bad = await ac.get("/api/v1/reports/not-a-uuid/report", headers=headers)
            assert resp_rep_bad.status_code == 400

            resp_rep_missing = await ac.get(f"/api/v1/reports/{uuid.uuid4()}/report", headers=headers)
            assert resp_rep_missing.status_code == 404

            # 5. Forensics detail endpoints
            dummy_uuid = str(uuid.uuid4())
            resp_dos = await ac.get(f"/api/v1/forensics/dossier/{dummy_uuid}", headers=headers)
            assert resp_dos.status_code == 404

            resp_raw = await ac.get(
                "/api/v1/forensics/raw/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                headers=headers,
            )
            assert resp_raw.status_code in [200, 404]

            resp_hops = await ac.get(f"/api/v1/forensics/hops/{dummy_uuid}", headers=headers)
            assert resp_hops.status_code == 404

            resp_job = await ac.get(f"/api/v1/forensics/jobs/{dummy_uuid}", headers=headers)
            assert resp_job.status_code == 404


def test_core_and_forensics_coverage_boost():
    # 1. ioc_extractor tests
    assert defang_ioc("http://evil.com/phish", "URL") == "hxxp://evil[.]com/phish"
    assert defang_ioc("attacker@malicious.org", "EMAIL_ADDR") == "attacker[@]malicious[.]org"
    assert defang_ioc("", "URL") == ""

    html = '<p>Check <a href="https://phish.com/login">this</a> link or 198.51.100.99</p>'
    iocs = extract_iocs(body_plain="Contact admin@evil.net", body_html=html)
    assert any(i.ioc_type == "URL" for i in iocs)
    assert any(i.ioc_type == "DOMAIN" for i in iocs)

    # 2. upload_validator tests
    assert sanitize_filename("../../etc/passwd\x00.eml") == "passwd.eml"
    assert sanitize_filename("") == "evidence.eml"

    validate_email_bytes(b"From: sender@domain.com\r\nSubject: Test\r\n\r\nBody", "test.eml")
    validate_email_bytes(OLE_MSG_MAGIC + b"padding", "test.msg")

    with pytest.raises(HTTPException) as exc_exe:
        validate_email_bytes(b"MZ\x90\x00", "payload.exe")
    assert exc_exe.value.status_code == 422

    with pytest.raises(HTTPException) as exc_junk:
        validate_email_bytes(b"garbage bytes without headers", "bad.eml")
    assert exc_junk.value.status_code == 422

    # 3. asn_lookup tests
    info_none = resolve_ip_asn(None)
    assert info_none.resolution_status == "UNRESOLVED"

    info_priv = resolve_ip_asn("10.0.0.1")
    assert info_priv.asn_org == "Private Subnet"

    info_bad = resolve_ip_asn("not_an_ip")
    assert "Malformed" in (info_bad.reason or "")

    info_custom = resolve_ip_asn(
        "93.184.216.34",
        custom_asn_db={"93.184.216.34": {"asn": 15133, "org": "EdgeCast"}},
    )
    assert info_custom.asn_number == 15133

    # 4. security tests
    nonce = generate_nonce(16)
    assert len(nonce) == 16
    assert sign_audit_entry("test payload") is not None
    assert constant_time_compare("abc", "abc") is True
    assert constant_time_compare("abc", "xyz") is False

    hp = hash_password("Password123!Safe")
    assert verify_password("Password123!Safe", hp) is True
    assert verify_password("WrongPassword!", hp) is False

    token = create_access_token(subject="testuser", role="ANALYST")
    payload = decode_access_token(token)
    assert payload["sub"] == "testuser"

    record_login_attempt("lockout_test", success=False)
    record_login_attempt("lockout_test", success=True)
    check_login_lockout("lockout_test")  # should not raise
    validate_password_strength("StrongPass2026!#")

    # 5. geo_resolver & dnsbl tests
    from backend.app.osint.geo_resolver import is_ip_private_or_local, resolve_ip_geo

    assert is_ip_private_or_local("127.0.0.1")[0] is True
    assert is_ip_private_or_local("10.0.0.1")[0] is True
    assert is_ip_private_or_local("93.184.216.34")[0] is False
    assert is_ip_private_or_local("")[0] is True

    geo_none = resolve_ip_geo(None)
    assert geo_none.resolution_status == "UNRESOLVED"

    geo_priv = resolve_ip_geo("192.168.1.1")
    assert geo_priv.is_private is True

    dnsbl_res = query_dnsbl("127.0.0.1")
    assert hasattr(dnsbl_res, "is_listed") and dnsbl_res.is_listed is False


@pytest.mark.asyncio
async def test_extended_coverage_boost(tmp_path):
    import io
    import os
    from unittest.mock import AsyncMock, MagicMock, patch

    from backend.app.ai.url_analyzer import deobfuscate_ip_literal, normalize_defanged_url, trace_url_redirects
    from backend.app.database.session import resolve_database_url
    from backend.app.database.vault import (
        calculate_stream_hashes,
        get_vault_dir,
        read_raw_evidence,
        store_raw_evidence,
    )
    from backend.app.forensics.job_queue import IngestionJob, JobManager, JobStatus
    from backend.app.osint.dnsbl_checker import query_dnsbl, reverse_ip_for_dnsbl
    from backend.app.osint.tor_detector import load_tor_exit_cache
    from backend.app.osint.whois_client import _RDAP_CACHE, lookup_domain_whois

    # 1. Database session URL normalization
    with patch.dict(os.environ, {"DATABASE_URL": ""}):
        u1 = resolve_database_url()
        assert "sqlite" in u1
    with patch.dict(os.environ, {"DATABASE_URL": "postgres://user:pass@localhost/db"}):
        u2 = resolve_database_url()
        assert u2.startswith("postgresql+asyncpg://")
    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://user:pass@localhost/db"}):
        u3 = resolve_database_url()
        assert u3.startswith("postgresql+asyncpg://")
    with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///local.db"}):
        u4 = resolve_database_url()
        assert u4.startswith("sqlite+aiosqlite://")

    # 2. Vault
    s_sha256, s_md5, s_len = calculate_stream_hashes(io.BytesIO(b"stream bytes for hash test"))
    assert s_len == 26

    v_dir = get_vault_dir()
    assert v_dir.exists()

    with patch.dict(os.environ, {"VAULT_STORAGE_DIR": str(tmp_path / "custom_vault")}):
        custom_v = get_vault_dir()
        assert "custom_vault" in str(custom_v)

    test_ev_bytes = b"evidence payload sample"
    h256, hmd5, pth, sz = store_raw_evidence(test_ev_bytes, "sample.eml", vault_dir=tmp_path)
    # verify re-store same bytes
    h256_b, _, _, _ = store_raw_evidence(test_ev_bytes, "sample.eml", vault_dir=tmp_path)
    assert h256_b == h256
    # read evidence
    read_b = read_raw_evidence(h256, vault_dir=tmp_path)
    assert read_b == test_ev_bytes

    # test tampering in vault
    with pytest.raises(ValueError):
        fake_path = Path(pth)
        fake_path.chmod(0o666)
        fake_path.write_bytes(b"corrupted bytes")
        read_raw_evidence(h256, vault_dir=tmp_path)

    # 3. DNSBL
    assert reverse_ip_for_dnsbl("2001:db8::1") is None
    assert reverse_ip_for_dnsbl("not_an_ip") is None
    assert reverse_ip_for_dnsbl("1.2.3.4") == "4.3.2.1"

    empty_res = query_dnsbl("")
    assert empty_res.status == "UNVERIFIABLE"

    bad_res = query_dnsbl("invalid.ip.str")
    assert bad_res.status == "UNVERIFIABLE"

    ipv6_res = query_dnsbl("2607:f8b0:4005:805::200e")
    assert ipv6_res.status == "UNVERIFIABLE"

    with patch("dns.resolver.Resolver") as mock_res_cls:
        mock_resolver = MagicMock()
        mock_res_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = ["127.0.0.2"]
        res = query_dnsbl("8.8.8.8", zones=[{"name": "Spamhaus", "zone": "zen.spamhaus.org"}])
        assert res.is_listed is True
        assert len(res.listings) == 1

    # 4. WHOIS / RDAP
    assert (await lookup_domain_whois("")).resolution_status == "UNKNOWN"
    assert (await lookup_domain_whois("invalid")).resolution_status == "UNKNOWN"

    fixture_db = {
        "tested-threat.org": {
            "domain_age_days": 5,
            "registrar": "BadRegistrar Inc",
            "is_newly_registered": True,
            "reputation_score": 95.0,
        }
    }
    hit = await lookup_domain_whois("tested-threat.org", custom_rdap_db=fixture_db)
    assert hit.is_newly_registered is True
    assert hit.domain_age_days == 5

    miss = await lookup_domain_whois("not-in-db.org", custom_rdap_db=fixture_db)
    assert miss.resolution_status == "UNKNOWN"

    _RDAP_CACHE["cached-domain.com"] = (hit, 9999999999.0)
    cached = await lookup_domain_whois("cached-domain.com")
    assert cached.domain == "tested-threat.org"

    # 5. Tor Detector
    t_file = tmp_path / "tor.json"
    t_file.write_text(
        '{"exit_nodes": ["198.51.100.44"], "exit_subnets": ["198.51.100.0/24"], "bulletproof_subnets": ["203.0.113.0/24"], "fetched_at": "2026-11-12T00:00:00Z"}'
    )
    stats = load_tor_exit_cache(custom_snapshot_path=t_file)
    assert stats["exit_node_count"] == 1

    bad_t_file = tmp_path / "bad_tor.json"
    bad_t_file.write_text("{bad json}")
    bad_stats = load_tor_exit_cache(custom_snapshot_path=bad_t_file)
    assert bad_stats["source"] == "ERROR"

    # 6. URL Analyzer
    assert deobfuscate_ip_literal("0x7f000001") == "127.0.0.1"
    assert deobfuscate_ip_literal("2130706433") == "127.0.0.1"
    assert deobfuscate_ip_literal("0177.0.0.1") == "127.0.0.1"
    assert deobfuscate_ip_literal("0xinvalid") is None
    assert deobfuscate_ip_literal("99999999999999999999999999") is None
    assert deobfuscate_ip_literal("099.0.0.1") is None

    norm = normalize_defanged_url("hxxps://malicious[.]example[.]com[:]8080/path[//]sub")
    assert norm.startswith("https://malicious.example.com:8080/path//sub")

    hops, final_url = await trace_url_redirects("http://127.0.0.1/admin")
    assert len(hops) > 0
    assert hops[0].status_code == 403
    assert "SSRF" in hops[0].location

    # 7. Job Queue
    job = IngestionJob("job-001", "test.eml", "analyst")
    assert job.status == JobStatus.PENDING
    d = job.to_dict()
    assert d["job_id"] == "job-001"
    assert d["file_name"] == "test.eml"

    mgr = JobManager()
    created = await mgr.create_job("upload.eml", "analyst_bob")
    assert created.file_name == "upload.eml"
    fetched = await mgr.get_job(created.job_id)
    assert fetched is not None
    assert fetched.job_id == created.job_id

    # 8. Report Endpoints
    from fastapi import HTTPException

    from backend.app.api.v1.endpoints_reports import stream_forensic_pdf_report

    with pytest.raises(HTTPException) as exc_info:
        await stream_forensic_pdf_report("invalid-uuid", current_user=MagicMock(), db=AsyncMock())
    assert exc_info.value.status_code == 400

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result
    with pytest.raises(HTTPException) as exc_info:
        await stream_forensic_pdf_report(str(uuid.uuid4()), current_user=MagicMock(), db=mock_db)
    assert exc_info.value.status_code == 404

    # 9. Campaign Endpoints
    from backend.app.api.v1.endpoints_campaigns import get_campaign_graph, list_campaigns

    mock_camp_db = AsyncMock()
    mock_camp_result = MagicMock()
    mock_camp_result.scalars.return_value.all.return_value = []
    mock_camp_db.execute.return_value = mock_camp_result
    camps = await list_campaigns(current_user=MagicMock(), db=mock_camp_db)
    assert camps == []

    graph = await get_campaign_graph(
        min_threat_score=None, cluster_type=None, current_user=MagicMock(), db=mock_camp_db
    )
    assert "graph" in graph
    assert "nodes" in graph["graph"] and "edges" in graph["graph"]
    assert graph["graph"]["total_nodes"] == 0
