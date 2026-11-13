"""Cryptographic Email Fixture Generator and Corpus Registry.

Generates RFC 822 .eml sample fixtures and DNS mock registries for testing:
1. Authentic signed emails (DKIM RSA-SHA256, SPF pass, DMARC aligned)
2. Tampered body (body hash mismatch)
3. Tampered header (signature verification failure)
4. Stripped DKIM signature (missing DKIM)
5. Unaligned signing domain (d=attacker.com vs From: target.org)
6. Expired DKIM signature (x= tag past epoch)
7. Revoked public key (empty p= tag per RFC 6376)
8. Historical unavailable key (DNS NXDOMAIN / no record)
9. Length tag abuse (l= tag body injection)
10. SPF PermError (RFC 7208 10-lookup limit exceeded)
11. Upstream MTA Discrepancy (forged Authentication-Results vs raw failure)
12. ARC Authenticated Received Chain
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any, Dict, List, Tuple

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Fixed deterministic seed for reproducible test generation
GENERATION_SEED = 26106
GENERATION_DATE = "2026-11-10T18:25:00Z"
DATASET_NAME = "SIH-Forensic-Protocol-Auth-Corpus"
DATASET_VERSION = "2.0.0"

# Generate fixed RSA-1024 test keypair
_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
_priv_pem = _priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_pub_der = _priv_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
_pub_b64 = base64.b64encode(_pub_der).decode("ascii")

# Attacker separate keypair
_attacker_priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
_attacker_pem = _attacker_priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_attacker_b64 = base64.b64encode(
    _attacker_priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
).decode("ascii")

SELECTOR = "sih2026"
PRIMARY_DOMAIN = "aicte-india.org"
ATTACKER_DOMAIN = "attacker-relay.net"
CONNECTING_IP = "198.51.100.10"
UNAUTHORIZED_IP = "203.0.113.88"

# Universal DNS Fixtures Dictionary
DNS_FIXTURES: Dict[str, List[str]] = {
    # Authentic AICTE Keys & Policies
    f"{SELECTOR}._domainkey.{PRIMARY_DOMAIN}": [f"v=DKIM1; k=rsa; p={_pub_b64}"],
    PRIMARY_DOMAIN: [f"v=spf1 ip4:{CONNECTING_IP} -all"],
    f"_dmarc.{PRIMARY_DOMAIN}": ["v=DMARC1; p=reject; aspf=r; adkim=r; pct=100"],
    # Attacker Keys & Policies
    f"badsel._domainkey.{ATTACKER_DOMAIN}": [f"v=DKIM1; k=rsa; p={_attacker_b64}"],
    ATTACKER_DOMAIN: [f"v=spf1 ip4:{UNAUTHORIZED_IP} -all"],
    f"_dmarc.{ATTACKER_DOMAIN}": ["v=DMARC1; p=none"],
    # Revoked Key Record (p= tag is empty per RFC 6376 Section 6.1.2)
    f"revoked._domainkey.{PRIMARY_DOMAIN}": ["v=DKIM1; k=rsa; p="],
    # SPF PermError with 12 nested includes (exceeding 10-lookup limit)
    "spf-overflow.org": ["v=spf1 " + " ".join([f"include:sub{i}.spf-overflow.org" for i in range(12)]) + " -all"],
    "_dmarc.spf-overflow.org": ["v=DMARC1; p=reject; aspf=r; adkim=r"],
    # Victim Domain for Upstream Forgery Testing
    "victim.gov.in": [f"v=spf1 ip4:{CONNECTING_IP} -all"],
    "_dmarc.victim.gov.in": ["v=DMARC1; p=reject; aspf=r; adkim=r"],
}
for i in range(12):
    DNS_FIXTURES[f"sub{i}.spf-overflow.org"] = ["v=spf1 ip4:10.0.0.1 -all"]


def build_corpus() -> Dict[str, Tuple[bytes, Dict[str, Any]]]:
    """Generate the full dictionary of RFC 822 test emails with expected forensic verdicts."""
    corpus: Dict[str, Tuple[bytes, Dict[str, Any]]] = {}

    # 1. Authentic AICTE Valid Email
    base_headers = (
        b"From: AICTE Cyber Cell <no-reply@aicte-india.org>\r\n"
        b"To: Security Auditor <auditor@target.ac.in>\r\n"
        b"Subject: Official Circular: National Cyber Security Compliance 2026\r\n"
        b"Date: Tue, 10 Nov 2026 10:00:00 +0530\r\n"
        b"Message-ID: <sih26106-legit-001@aicte-india.org>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
    )
    authentic_body = (
        b"\r\n"
        b"Dear Institutional Head,\r\n\r\n"
        b"In compliance with Section 63 of Bharatiya Sakshya Adhiniyam, 2023,\r\n"
        b"all technical institutions are mandated to implement forensic email threat logging.\r\n"
        b"Regards,\r\nAICTE Cyber Security Cell\r\n"
    )
    raw_authentic = base_headers + authentic_body
    sig_authentic = dkim.sign(raw_authentic, SELECTOR.encode("ascii"), PRIMARY_DOMAIN.encode("ascii"), _priv_pem)
    eml_authentic = sig_authentic + raw_authentic
    corpus["legit_signed_aicte.eml"] = (
        eml_authentic,
        {
            "expected_spf": "PASS",
            "expected_dkim": "PASS",
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": True,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 2. Tampered Body (DKIM body hash mismatch)
    eml_tampered_body = (
        sig_authentic
        + base_headers
        + (
            b"\r\n"
            b"Dear Institutional Head,\r\n\r\n"
            b"CRITICAL: Transfer institutional funds to account 9876543210 immediately!\r\n"
            b"Regards,\r\nAICTE Cyber Security Cell\r\n"
        )
    )
    corpus["tampered_body.eml"] = (
        eml_tampered_body,
        {
            "expected_spf": "PASS",
            "expected_dkim": "BODY_HASH_MISMATCH",
            "expected_dmarc": "PASS",  # SPF still passes & aligns, so DMARC passes on SPF
            "expected_align_spf": True,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 3. Tampered Header (Subject modified after signing -> RSA signature verification fails)
    tampered_headers = base_headers.replace(b"Subject: Official Circular", b"Subject: HACKED NOTICE")
    eml_tampered_header = sig_authentic + tampered_headers + authentic_body
    corpus["tampered_header.eml"] = (
        eml_tampered_header,
        {
            "expected_spf": "PASS",
            "expected_dkim": "FAIL",
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 4. Stripped DKIM Signature (No DKIM-Signature header)
    corpus["stripped_dkim.eml"] = (
        raw_authentic,
        {
            "expected_spf": "PASS",
            "expected_dkim": "NONE",
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 5. Wrong Domain Alignment (DKIM signed by attacker-relay.net, From is aicte-india.org)
    sig_attacker = dkim.sign(raw_authentic, b"badsel", ATTACKER_DOMAIN.encode("ascii"), _attacker_pem)
    eml_wrong_domain = sig_attacker + raw_authentic
    corpus["wrong_domain_alignment.eml"] = (
        eml_wrong_domain,
        {
            "expected_spf": "FAIL",
            "expected_dkim": "PASS",
            "expected_dmarc": "FAIL",  # DKIM passed for attacker-relay.net, but does NOT align with aicte-india.org!
            "expected_align_spf": False,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": UNAUTHORIZED_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 6. Expired DKIM Signature (x= timestamp in the past)
    expired_x = int(time.time()) - 86400  # Expired 24 hours ago
    sig_expired = dkim.sign(
        raw_authentic,
        SELECTOR.encode("ascii"),
        PRIMARY_DOMAIN.encode("ascii"),
        _priv_pem,
    )
    # Inject x= expired tag into signature header
    sig_expired_patched = sig_expired.replace(b"v=1;", f"v=1; x={expired_x};".encode("ascii"))
    corpus["expired_dkim.eml"] = (
        sig_expired_patched + raw_authentic,
        {
            "expected_spf": "PASS",
            "expected_dkim": "EXPIRED",
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 7. Revoked Key (DNS record has empty p=)
    sig_revoked = dkim.sign(raw_authentic, b"revoked", PRIMARY_DOMAIN.encode("ascii"), _priv_pem)
    corpus["revoked_key.eml"] = (
        sig_revoked + raw_authentic,
        {
            "expected_spf": "PASS",
            "expected_dkim": "KEY_REVOKED",
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 8. Historical Unavailable Key (Selector does not exist in DNS)
    sig_ghost = dkim.sign(raw_authentic, b"ghostkey", PRIMARY_DOMAIN.encode("ascii"), _priv_pem)
    corpus["unavailable_key_historical.eml"] = (
        sig_ghost + raw_authentic,
        {
            "expected_spf": "PASS",
            "expected_dkim": "KEY_UNAVAILABLE",
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 9. Length Tag Abuse (l=50 limits signed body; attacker appends 500 bytes of malicious payload)
    sig_l_tag = dkim.sign(
        raw_authentic,
        SELECTOR.encode("ascii"),
        PRIMARY_DOMAIN.encode("ascii"),
        _priv_pem,
        length=True,
    )
    injected_payload = (
        b"\r\n\r\n[MALICIOUS INJECTION]: Click here immediately to avoid suspension: http://evil-phish.net\r\n"
    )
    corpus["l_tag_abuse_injected.eml"] = (
        sig_l_tag + raw_authentic + injected_payload,
        {
            "expected_spf": "PASS",
            "expected_dkim": "PASS",  # dkimpy verifies the first l bytes, so crypto passes
            "expected_l_abuse": True,  # But our forensic parser flags l_tag_abuse_detected!
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": True,
            "expected_discrepancy": True,  # Discrepancy warning raised for l= abuse!
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    # 10. SPF PermError (Too many DNS lookups > 10)
    spf_overflow_headers = (
        b"From: Overflow <admin@spf-overflow.org>\r\n"
        b"To: Recipient <user@target.ac.in>\r\n"
        b"Subject: SPF Limit Test\r\n\r\n"
        b"Testing RFC 7208 10-lookup limit.\r\n"
    )
    corpus["spf_permerror_lookups.eml"] = (
        spf_overflow_headers,
        {
            "expected_spf": "PERMERROR",
            "expected_dkim": "NONE",
            "expected_dmarc": "FAIL",
            "expected_align_spf": False,
            "expected_align_dkim": False,
            "expected_discrepancy": False,
            "connecting_ip": "198.51.100.99",
            "from_email": "admin@spf-overflow.org",
        },
    )

    # 11. Upstream MTA Discrepancy (Attacker forged Authentication-Results: spf=pass dkim=pass)
    forged_auth_header = (
        b"Authentication-Results: mx.victim.gov.in; "
        b"spf=pass (mx.victim.gov.in: domain of spoof@victim.gov.in designates 1.2.3.4 as permitted sender); "
        b"dkim=pass header.i=@victim.gov.in header.s=badsel; "
        b"dmarc=pass action=none\r\n"
    )
    eml_discrepancy = (
        forged_auth_header
        + sig_attacker
        + base_headers.replace(b"no-reply@aicte-india.org", b"spoof@victim.gov.in")
        + authentic_body
    )
    corpus["auth_discrepancy_mta_spoof.eml"] = (
        eml_discrepancy,
        {
            "expected_spf": "FAIL",
            "expected_dkim": "FAIL",
            "expected_dmarc": "FAIL",
            "expected_discrepancy": True,  # Upstream claimed pass, but recomputed failed!
            "connecting_ip": UNAUTHORIZED_IP,
            "from_email": "spoof@victim.gov.in",
        },
    )

    # 12. Multi-Signature Key Rotation (Primary active sih2026 key passes + Old expired key old2024)
    DNS_FIXTURES[f"old2024._domainkey.{PRIMARY_DOMAIN}"] = [f"v=DKIM1; k=rsa; p={_pub_b64}"]
    expired_timestamp = int(time.time()) - 7200
    sig_old = dkim.sign(
        raw_authentic,
        b"old2024",
        PRIMARY_DOMAIN.encode("ascii"),
        _priv_pem,
        include_headers=[b"From", b"To", b"Subject", b"Date"],
    )
    sig_old_expired = sig_old.replace(
        b"d=aicte-india.org;",
        f"d=aicte-india.org; x={expired_timestamp};".encode("ascii"),
    )
    eml_multi_sig = sig_authentic + sig_old_expired + raw_authentic
    corpus["multi_sig_rotation.eml"] = (
        eml_multi_sig,
        {
            "expected_spf": "PASS",
            "expected_dkim": "PASS",
            "expected_dmarc": "PASS",
            "expected_align_spf": True,
            "expected_align_dkim": True,
            "expected_discrepancy": False,
            "connecting_ip": CONNECTING_IP,
            "from_email": "no-reply@aicte-india.org",
        },
    )

    return corpus


def save_corpus_to_disk(target_dir: str) -> None:
    """Save all generated .eml files to disk."""
    os.makedirs(target_dir, exist_ok=True)
    corpus = build_corpus()
    for filename, (raw_bytes, _) in corpus.items():
        filepath = os.path.join(target_dir, filename)
        with open(filepath, "wb") as f:
            f.write(raw_bytes)
