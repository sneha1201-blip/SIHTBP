"""Comprehensive Forensic Protocol Authentication Test Suite (SPF, DKIM, DMARC, ARC).

Validates:
- Real DKIM cryptographic verification with dkimpy against raw RFC 822 bytes
- Real SPF evaluation via pyspf (RFC 7208) using connecting IP and RFC 7208 10-lookup limit
- Real DMARC strict/relaxed alignment via Public Suffix List
- ARC chain integrity verification (RFC 8617)
- Upstream MTA claim vs independent recomputed verdict discrepancy detection
- Generates reproducible confusion matrix artifact: Expected vs Got
"""

from __future__ import annotations

import pytest

from backend.app.forensics.auth_validator import (
    validate_protocol_authentication,
    verify_arc_chain,
)
from backend.app.parsers.eml_parser import parse_eml
from backend.tests.fixtures.email_corpus import (
    DNS_FIXTURES,
    build_corpus,
)


@pytest.fixture(scope="module")
def corpus():
    """Load the immutable forensic test corpus."""
    return build_corpus()


def test_authentic_dkim_spf_dmarc_pass(corpus):
    """Case 1: Fully authentic email from AICTE with valid RSA-SHA256 signature, authorized IP, and aligned DMARC."""
    raw_bytes, meta = corpus["legit_signed_aicte.eml"]
    parsed = parse_eml(raw_bytes, filename="legit_signed_aicte.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.spf_status == "PASS"
    assert res.dkim_status == "PASS"
    assert res.dmarc_status == "PASS"
    assert res.dmarc_alignment_spf is True
    assert res.dmarc_alignment_dkim is True
    assert res.has_discrepancy is False
    assert res.auth_score == 0.0
    assert len(res.dns_key_snapshots) >= 1
    assert res.dkim_signatures[0].signature_status == "PASS"
    assert res.dkim_signatures[0].body_hash_status == "MATCH"


def test_tampered_body_hash_mismatch(corpus):
    """Case 2: Attack where email body is modified post-signing; body hash (bh=) must mismatch."""
    raw_bytes, meta = corpus["tampered_body.eml"]
    parsed = parse_eml(raw_bytes, filename="tampered_body.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.dkim_status == "BODY_HASH_MISMATCH"
    assert res.dkim_signatures[0].body_hash_status == "MISMATCH"
    assert res.dmarc_alignment_dkim is False
    assert res.auth_score >= 40.0


def test_tampered_header_signature_fail(corpus):
    """Case 3: Attack where signed header (Subject) is modified; RSA signature verification must fail."""
    raw_bytes, meta = corpus["tampered_header.eml"]
    parsed = parse_eml(raw_bytes, filename="tampered_header.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.dkim_status == "FAIL"
    assert res.dkim_signatures[0].signature_status == "FAIL"
    assert res.dmarc_alignment_dkim is False
    assert res.auth_score >= 40.0


def test_stripped_dkim_none(corpus):
    """Case 4: Email completely stripped of DKIM signature; status must evaluate to NONE."""
    raw_bytes, meta = corpus["stripped_dkim.eml"]
    parsed = parse_eml(raw_bytes, filename="stripped_dkim.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.dkim_status == "NONE"
    assert len(res.dkim_signatures) == 0
    assert res.dmarc_alignment_dkim is False


def test_wrong_domain_alignment_dmarc_fail(corpus):
    """Case 5: Attacker signed message with their own domain (d=attacker-relay.net), From is target domain.

    DKIM crypto passes for attacker domain, but RFC 7489 alignment fails -> DMARC FAIL!
    """
    raw_bytes, meta = corpus["wrong_domain_alignment.eml"]
    parsed = parse_eml(raw_bytes, filename="wrong_domain_alignment.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    # DKIM signature on attacker-relay.net itself is cryptographically valid
    assert res.dkim_status == "PASS"
    assert res.dkim_domain == "attacker-relay.net"
    # But From domain is aicte-india.org -> alignment fails!
    assert res.dmarc_alignment_dkim is False
    assert res.spf_status == "FAIL"
    assert res.dmarc_alignment_spf is False
    assert res.dmarc_status == "FAIL"
    assert res.auth_score >= 60.0


def test_expired_dkim_signature(corpus):
    """Case 6: Signature has x= tag in the past; must evaluate to EXPIRED."""
    raw_bytes, meta = corpus["expired_dkim.eml"]
    parsed = parse_eml(raw_bytes, filename="expired_dkim.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.dkim_status == "EXPIRED"
    assert res.dkim_signatures[0].is_expired is True
    assert res.dmarc_alignment_dkim is False
    assert res.auth_score >= 25.0


def test_revoked_public_key(corpus):
    """Case 7: Public key record exists but p= tag is empty (RFC 6376 Section 6.1.2 key revocation)."""
    raw_bytes, meta = corpus["revoked_key.eml"]
    parsed = parse_eml(raw_bytes, filename="revoked_key.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.dkim_status == "KEY_REVOKED"
    assert res.dkim_signatures[0].signature_status == "KEY_REVOKED"
    assert res.dmarc_alignment_dkim is False
    assert res.auth_score >= 35.0


def test_historical_unavailable_key(corpus):
    """Case 8: Historical email whose selector key no longer resolves in DNS; must return KEY_UNAVAILABLE."""
    raw_bytes, meta = corpus["unavailable_key_historical.eml"]
    parsed = parse_eml(raw_bytes, filename="unavailable_key_historical.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.dkim_status == "KEY_UNAVAILABLE"
    assert res.dkim_signatures[0].signature_status == "KEY_UNAVAILABLE"
    assert res.dmarc_alignment_dkim is False


def test_l_tag_length_abuse_detection(corpus):
    """Case 9: Length tag abuse where attacker appends malicious payload beyond l= count."""
    raw_bytes, meta = corpus["l_tag_abuse_injected.eml"]
    parsed = parse_eml(raw_bytes, filename="l_tag_abuse_injected.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    # dkimpy verifies first l bytes so crypto passes, but forensic detector flags l_tag_abuse!
    assert res.dkim_signatures[0].l_tag_abuse_detected is True
    assert "Length tag l=" in (res.dkim_signatures[0].l_tag_explanation or "")
    assert res.has_discrepancy is True
    assert any("DKIM Header Warning" in d for d in res.discrepancies)


def test_spf_permerror_exceeded_dns_lookups(corpus):
    """Case 10: SPF record with > 10 DNS lookups (RFC 7208 Section 4.6.4); must evaluate to PERMERROR."""
    raw_bytes, meta = corpus["spf_permerror_lookups.eml"]
    parsed = parse_eml(raw_bytes, filename="spf_permerror_lookups.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.spf_status == "PERMERROR"
    assert res.spf_lookups_count > 10
    assert "10-lookup limit exceeded" in (res.spf_explanation or "")


def test_upstream_mta_discrepancy_forgery_flagged(corpus):
    """Case 11: Attacker injected forged Authentication-Results header claiming SPF and DKIM pass.

    Independent cryptographic recomputation catches the lie and flags AUTH DISCREPANCY!
    """
    raw_bytes, meta = corpus["auth_discrepancy_mta_spoof.eml"]
    parsed = parse_eml(raw_bytes, filename="auth_discrepancy_mta_spoof.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert res.claimed_by_mta["claimed_spf"] == "PASS"
    assert res.claimed_by_mta["claimed_dkim"] == "PASS"
    assert res.has_discrepancy is True
    assert len(res.discrepancies) >= 1
    assert any("Discrepancy" in d for d in res.discrepancies)
    assert res.auth_score >= 50.0


def test_arc_chain_validation():
    """Case 12: RFC 8617 Authenticated Received Chain parsing and verification."""
    # Email without ARC
    no_arc_res = verify_arc_chain(b"From: a@b.com\r\n\r\nHello")
    assert no_arc_res.status == "NONE"
    assert no_arc_res.instances_count == 0

    # Malformed ARC headers
    broken_arc_msg = (
        b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=test.com; s=s1; b=fake\r\n"
        b"From: a@b.com\r\n\r\nHello"
    )
    broken_res = verify_arc_chain(broken_arc_msg)
    assert broken_res.status in ("FAIL", "NONE")


def test_confusion_matrix_verification(corpus):
    """Confusion Matrix Verification: Expected vs Recomputed ground truth across the entire corpus."""
    confusion_records = []

    for name, (raw_bytes, meta) in corpus.items():
        parsed = parse_eml(raw_bytes, filename=name)
        res = validate_protocol_authentication(
            from_email=meta["from_email"],
            return_path=meta["from_email"],
            headers_dict=parsed.headers_dict,
            auth_results_header=parsed.authentication_results,
            raw_bytes=raw_bytes,
            connecting_ip=meta["connecting_ip"],
            custom_dns_records=DNS_FIXTURES,
        )

        match_spf = (res.spf_status == meta["expected_spf"])
        match_dkim = (res.dkim_status == meta["expected_dkim"])
        match_dmarc = (res.dmarc_status == meta["expected_dmarc"])
        match_disc = (res.has_discrepancy == meta["expected_discrepancy"])

        confusion_records.append({
            "sample": name,
            "spf_expected": meta["expected_spf"],
            "spf_got": res.spf_status,
            "spf_match": match_spf,
            "dkim_expected": meta["expected_dkim"],
            "dkim_got": res.dkim_status,
            "dkim_match": match_dkim,
            "dmarc_expected": meta["expected_dmarc"],
            "dmarc_got": res.dmarc_status,
            "dmarc_match": match_dmarc,
            "disc_expected": meta["expected_discrepancy"],
            "disc_got": res.has_discrepancy,
            "disc_match": match_disc,
        })

    # Assert 100% accuracy on all evaluated samples
    mismatches = [c for c in confusion_records if not (c["spf_match"] and c["dkim_match"] and c["dmarc_match"] and c["disc_match"])]
    assert len(mismatches) == 0, f"Confusion matrix mismatches: {mismatches}"
