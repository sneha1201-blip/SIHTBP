"""Exhaustive Branch Coverage Tests for Parsers, Threat Scorer & Auth Validator.

Ensures >=90% branch coverage across:
- backend.app.parsers.eml_parser
- backend.app.parsers.msg_parser
- backend.app.ai.threat_scorer
- backend.app.forensics.auth_validator
"""

from __future__ import annotations

import datetime
import unittest.mock as mock
from unittest.mock import MagicMock

from backend.app.ai.nlp_engine import NLPAnalysisResult
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import URLAnalysisResult
from backend.app.forensics.auth_validator import (
    ArcChainResult,
    AuthValidationResult,
    validate_protocol_authentication,
)
from backend.app.forensics.spoof_detector import SpoofDetectionResult
from backend.app.parsers.eml_parser import parse_eml
from backend.app.parsers.msg_parser import carve_partial_msg_stream, parse_msg

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
    nlp = make_dummy_nlp(score=60.0, conf=0.30)  # low confidence
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
    # Benign
    auth_b = make_dummy_auth()
    spoof_b = make_dummy_spoof()
    nlp_b = make_dummy_nlp(score=5.0)
    res_b = compute_threat_score(auth_b, spoof_b, nlp_b, [])
    assert res_b.verdict == "BENIGN"
    assert res_b.threat_score < 25.0

    # Suspicious
    auth_s = make_dummy_auth(spf="SOFTFAIL")
    auth_s.auth_score = 50.0
    spoof_s = make_dummy_spoof(score=50.0)
    nlp_s = make_dummy_nlp(score=50.0, conf=0.85)
    res_s = compute_threat_score(auth_s, spoof_s, nlp_s, [])
    assert res_s.verdict == "SUSPICIOUS"


# =============================================================================
# 4. Auth Validator Edge Case Coverage
# =============================================================================

def test_auth_validator_discrepancy_and_arc():
    headers = {
        "Authentication-Results": ["mx.google.com; spf=pass; dkim=pass"],
        "From": ["sender@testcorp.org"],
        "Return-Path": ["sender@testcorp.org"],
    }
    custom_dns = {
        "testcorp.org": ["v=spf1 -all"],  # Local evaluation says FAIL
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

