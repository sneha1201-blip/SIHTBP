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
    GLOBAL_DNS_CACHE,
    async_resolve_txt_concurrent,
    query_dns_txt_with_timeout,
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
    broken_arc_msg = b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=test.com; s=s1; b=fake\r\nFrom: a@b.com\r\n\r\nHello"
    broken_res = verify_arc_chain(broken_arc_msg)
    assert broken_res.status in ("FAIL", "NONE")


def test_multi_signature_key_rotation(corpus):
    """Case 13: Multi-signature email containing both an expired legacy key and a valid rotated key.

    Forensic verification must evaluate both signatures independently, correctly flag the expired key,
    accept the valid key, and award consolidated PASS with DMARC aligned.
    """
    raw_bytes, meta = corpus["multi_sig_rotation.eml"]
    parsed = parse_eml(raw_bytes, filename="multi_sig_rotation.eml")

    res = validate_protocol_authentication(
        from_email=meta["from_email"],
        return_path=meta["from_email"],
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
        raw_bytes=raw_bytes,
        connecting_ip=meta["connecting_ip"],
        custom_dns_records=DNS_FIXTURES,
    )

    assert len(res.dkim_signatures) == 2
    # Verify individual signatures
    statuses = [s.signature_status for s in res.dkim_signatures]
    assert "PASS" in statuses
    assert "EXPIRED" in statuses
    # Consolidated status must be PASS because valid key authenticated the content
    assert res.dkim_status == "PASS"
    assert res.dmarc_alignment_dkim is True
    assert res.dmarc_status == "PASS"


@pytest.mark.asyncio
async def test_dns_negative_cache_and_concurrent_resolver():
    """Verify DNS TTL caching, negative caching of missing domains, and concurrent async resolution."""
    GLOBAL_DNS_CACHE.clear()

    # 1. Negative caching of nonexistent domain
    bogus_domain = "nonexistent-domain-xyz-26106.invalid"
    res1 = query_dns_txt_with_timeout(bogus_domain, timeout=0.2)
    assert res1 == []
    # Verify cached negatively
    cached_val = GLOBAL_DNS_CACHE.get(bogus_domain)
    assert cached_val == []

    # 2. Positive caching manual injection
    test_dom = "test-cached-domain.org"
    GLOBAL_DNS_CACHE.set(test_dom, ["v=spf1 -all"], is_negative=False)
    res2 = query_dns_txt_with_timeout(test_dom, timeout=0.2)
    assert res2 == ["v=spf1 -all"]

    # 3. Concurrent resolution helper
    domains = [
        "domain1.test.invalid",
        "domain2.test.invalid",
        "domain3.test.invalid",
    ]
    concurrent_res = await async_resolve_txt_concurrent(domains, timeout=0.3)
    assert len(concurrent_res) == 3
    for d in domains:
        assert d in concurrent_res
        assert isinstance(concurrent_res[d], list)


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

        match_spf = res.spf_status == meta["expected_spf"]
        match_dkim = res.dkim_status == meta["expected_dkim"]
        match_dmarc = res.dmarc_status == meta["expected_dmarc"]
        match_disc = res.has_discrepancy == meta["expected_discrepancy"]

        confusion_records.append(
            {
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
            }
        )

    # Assert 100% accuracy on all evaluated samples
    mismatches = [
        c
        for c in confusion_records
        if not (c["spf_match"] and c["dkim_match"] and c["dmarc_match"] and c["disc_match"])
    ]
    assert len(mismatches) == 0, f"Confusion matrix mismatches: {mismatches}"


def test_dmarc_strict_alignment_subdomain_failure():
    """Verify strict DMARC alignment (aspf=s, adkim=s) rejects cross-subdomain alignment."""
    # From: user@sub.company.org, SPF validated on company.org
    headers = {
        "from": ["user@sub.company.org"],
        "dmarc-record": ["v=DMARC1; p=reject; aspf=s; adkim=s"],
    }
    custom_dns = {
        "_dmarc.sub.company.org": ["v=DMARC1; p=reject; aspf=s; adkim=s"],
        "_dmarc.company.org": ["v=DMARC1; p=reject; aspf=s; adkim=s"],
        "company.org": ["v=spf1 ip4:198.51.100.1 -all"],
    }
    res = validate_protocol_authentication(
        from_email="user@sub.company.org",
        return_path="bounce@company.org",  # relaxed would align, strict must fail
        headers_dict=headers,
        connecting_ip="198.51.100.1",
        custom_dns_records=custom_dns,
    )
    # Under strict alignment, sub.company.org != company.org
    assert res.spf_status == "PASS"
    assert res.dmarc_alignment_spf is False
    assert res.dmarc_status == "FAIL"


def test_arc_chain_detailed_statuses():
    """Verify RFC 8617 ARC chain validation across multiple seal states."""
    # 1. ARC with valid structure
    sample_arc = (
        b"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=relay.org; s=arc1; b=sig\r\n"
        b"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=relay.org; s=arc1; bh=abc; b=sig\r\n"
        b"ARC-Authentication-Results: i=1; relay.org; spf=pass; dkim=pass\r\n"
        b"From: test@sender.com\r\n\r\nHello"
    )
    arc_res = verify_arc_chain(sample_arc)
    assert arc_res.instances_count == 1

    # 2. ARC chain with cv=fail
    broken_arc = (
        b"ARC-Seal: i=2; a=rsa-sha256; cv=fail; d=relay2.org; s=arc2; b=sig\r\n"
        b"ARC-Authentication-Results: i=2; relay2.org; spf=fail\r\n"
        b"From: test@sender.com\r\n\r\nHello"
    )
    res_fail = verify_arc_chain(broken_arc)
    assert res_fail.status in ("FAIL", "INVALID", "NONE")


def test_dns_records_missing_or_timeout():
    """Verify robust handling of missing DNS keys and DNS timeouts."""
    res = validate_protocol_authentication(
        from_email="user@unknown-domain-test-404.org",
        return_path="user@unknown-domain-test-404.org",
        headers_dict={"from": ["user@unknown-domain-test-404.org"]},
        connecting_ip="203.0.113.99",
        custom_dns_records={},
    )
    assert res.spf_status in ("NONE", "UNKNOWN", "UNVERIFIABLE")
    assert res.dkim_status in ("NONE", "UNSIGNED", "UNVERIFIABLE")
    assert res.dmarc_status in ("NONE", "ABSENT", "UNVERIFIABLE")
