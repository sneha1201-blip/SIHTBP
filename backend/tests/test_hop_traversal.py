"""Comprehensive Test Suite for RFC 5321 Hop Traversal & MTA Route Forensics.

Validates:
- Real-world MTA header parsing (Exchange, Postfix, Gmail, Sendmail, qmail, Exim)
- IPv4 and IPv6 extraction (bracketed, unbracketed, IPv6: prefix)
- Timestamp timezone normalization to UTC
- Clock skew anomaly detection (< -300 seconds)
- Temporal impossibility and out-of-order hop detection
- Downstream MTA trust boundary enforcement
- Earliest Reliable Public Originating IP extraction
"""

from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from backend.app.forensics.hop_traversal import (
    extract_ip_address_from_hop,
    is_ip_private_or_reserved,
    parse_received_header,
    reverse_hop_traversal,
)


def test_postfix_received_header():
    """Verify parsing of standard Postfix ESMTPS received header."""
    raw = (
        "Received: from mail.sender.org (mail.sender.org [185.220.101.50]) "
        "by mx.recipient.com (Postfix) with ESMTPS id 4StL3j5bKxz2a3D "
        "for <target@recipient.com>; Wed, 11 Nov 2026 09:15:00 +0000 (UTC)"
    )
    hop = parse_received_header(raw, order=1)

    assert hop.hop_order == 1
    assert hop.hop_ip == "185.220.101.50"
    assert hop.is_private_ip is False
    assert hop.mta_vendor == "Postfix"
    assert hop.by_mta == "mx.recipient.com"
    assert hop.from_mta == "mail.sender.org"
    assert "ESMTPS" in (hop.protocol or "")
    assert hop.timestamp == datetime(2026, 11, 11, 9, 15, 0, tzinfo=timezone.utc)
    assert hop.is_reliable is True


def test_microsoft_exchange_received_header():
    """Verify parsing of Microsoft Exchange / Outlook SMTP server header."""
    raw = (
        "Received: from EXCH01.corp.contoso.com (10.0.1.25) by mail.contoso.com "
        "(10.0.1.10) with Microsoft SMTP Server id 15.1.2507.0; "
        "Wed, 11 Nov 2026 14:45:00 +0530"
    )
    hop = parse_received_header(raw, order=1)

    assert hop.hop_ip == "10.0.1.25"
    assert hop.is_private_ip is True
    assert hop.mta_vendor == "Microsoft Exchange"
    # 14:45 +05:30 -> 09:15 UTC
    assert hop.timestamp == datetime(2026, 11, 11, 9, 15, 0, tzinfo=timezone.utc)


def test_gmail_workspace_received_header():
    """Verify parsing of Google Workspace / Gmail received header."""
    raw = (
        "Received: by 2002:a05:6512:3885:0:0:0:0 with SMTP id v5csp1234567lfg; "
        "Wed, 11 Nov 2026 01:15:00 -0800 (PST)"
    )
    hop = parse_received_header(raw, order=1)

    assert hop.mta_vendor == "Google Workspace / Gmail"
    # 01:15 -08:00 -> 09:15 UTC
    assert hop.timestamp == datetime(2026, 11, 11, 9, 15, 0, tzinfo=timezone.utc)


def test_sendmail_and_qmail_and_exim():
    """Verify parsing of Sendmail, qmail, and Exim header variants."""
    sendmail_raw = (
        "Received: from mail.gw.net (mail.gw.net [203.0.113.88]) by mx.org (8.14.4/8.14.4) "
        "with ESMTP id k0B2jX7w012345; Wed, 11 Nov 2026 10:15:00 +0100"
    )
    hop_sm = parse_received_header(sendmail_raw, order=1)
    assert hop_sm.mta_vendor == "Sendmail"
    assert hop_sm.hop_ip == "203.0.113.88"
    assert hop_sm.timestamp == datetime(2026, 11, 11, 9, 15, 0, tzinfo=timezone.utc)

    qmail_raw = "Received: (qmail 24512 invoked from network); 11 Nov 2026 09:15:00 -0000"
    hop_qm = parse_received_header(qmail_raw, order=2)
    assert hop_qm.mta_vendor == "qmail"
    assert hop_qm.timestamp == datetime(2026, 11, 11, 9, 15, 0, tzinfo=timezone.utc)

    exim_raw = (
        "Received: from [198.51.100.99] (helo=smtp.attacker.com) by mail.target.in "
        "with esmtp (Exim 4.94) id 1l9k2p-0001ab-12; 11 Nov 2026 09:15:00 +0000"
    )
    hop_ex = parse_received_header(exim_raw, order=3)
    assert hop_ex.mta_vendor == "Exim"
    assert hop_ex.hop_ip == "198.51.100.99"


def test_ipv6_address_variants():
    """Verify robust extraction of IPv6 addresses with and without brackets or prefix."""
    raw1 = "Received: from [2001:db8:85a3::8a2e:370:7334] by mx.test.com; Wed, 11 Nov 2026 10:00:00 +0000"
    assert extract_ip_address_from_hop(raw1) == "2001:db8:85a3::8a2e:370:7334"

    raw2 = "Received: from mail.net ([IPv6:2001:db8::1]) by mx.test.com; Wed, 11 Nov 2026 10:00:00 +0000"
    assert extract_ip_address_from_hop(raw2) == "2001:db8::1"

    # RFC 3849 documentation prefix 2001:db8::/32 is reserved
    assert is_ip_private_or_reserved("2001:db8::1") is True
    # Public routable IPv6
    assert is_ip_private_or_reserved("2607:f8b0:4005:805::200e") is False


def test_clock_skew_detection():
    """Verify that a negative delay > 300s triggers clock skew detection."""
    headers = [
        # Final edge gateway (top header) - received at 10:00 UTC
        "Received: from relay.isp.com (relay.isp.com [203.0.113.10]) by mx.local (Postfix); Wed, 11 Nov 2026 10:00:00 +0000",
        # Hop 2 claims it was received at 10:10 UTC (upstream)
        "Received: from origin.net (origin.net [198.51.100.1]) by relay.isp.com; Wed, 11 Nov 2026 10:10:00 +0000",
        # Oldest hop claims 09:55 UTC (this means relay claims it received at 10:10, but mx received at 10:00 -> -600s clock skew)
    ]
    # In chronological order:
    # Hop 1: origin.net (timestamp 10:10:00)
    # Hop 2: mx.local (timestamp 10:00:00) -> transit delay = -600s
    hops, _ = reverse_hop_traversal(headers)
    assert len(hops) == 2
    assert hops[1].clock_skew_detected is True
    assert hops[1].delay_seconds == -600.0
    assert any("Clock Skew Anomaly" in reason for reason in hops[1].anomaly_reasons)


def test_trust_boundary_and_origin_extraction():
    """Verify trust boundary isolation and earliest reliable public origin IP."""
    # Headers in RFC 822 top-to-bottom order (index 0 is recipient edge gateway)
    headers = [
        # Hop 3: Trusted Recipient Edge MX
        "Received: from mail.external-relay.com (mail.external-relay.com [198.51.100.22]) by mx.victim.gov.in (Postfix) with ESMTPS; Wed, 11 Nov 2026 12:00:05 +0000",
        # Hop 2: Legitimate sending server
        "Received: from client.attacker.org (client.attacker.org [185.220.101.5]) by mail.external-relay.com with ESMTP; Wed, 11 Nov 2026 12:00:00 +0000",
        # Hop 1: Internal client network
        "Received: from desktop.internal (192.168.1.100) by client.attacker.org with ESMTPA; Wed, 11 Nov 2026 11:59:58 +0000",
    ]

    hops, origin_ip = reverse_hop_traversal(headers)

    assert len(hops) == 3
    # Chronological:
    # Hop 1: desktop.internal (192.168.1.100) - INTERNAL / ORIGINATING
    assert hops[0].hop_ip == "192.168.1.100"
    assert hops[0].is_private_ip is True

    # Hop 2: 185.220.101.5 - First public hop
    assert hops[1].hop_ip == "185.220.101.5"
    assert hops[1].is_private_ip is False
    assert hops[1].is_reliable is True

    # Hop 3: 198.51.100.22 - EDGE_GATEWAY
    assert hops[2].node_type == "EDGE_GATEWAY"

    # Earliest reliable public IP must be 185.220.101.5
    assert origin_ip == "185.220.101.5"


def test_forged_hop_temporal_anomaly():
    """Verify that a forged lower hop claiming an impossible future timestamp is marked untrusted."""
    headers = [
        # Edge gateway received at 12:00:00 UTC
        "Received: from relay.trusted.com (relay.trusted.com [203.0.113.1]) by mx.target.in; Wed, 11 Nov 2026 12:00:00 +0000",
        # Forged hop claims it was sent at 15:30:00 UTC (> 3.5 hours after edge gateway received it!)
        "Received: from fake.sender.com (fake.sender.com [198.51.100.77]) by relay.trusted.com; Wed, 11 Nov 2026 15:30:00 +0000",
    ]

    hops, _ = reverse_hop_traversal(headers)
    assert len(hops) == 2
    # Hop 1 (the forged hop) must be flagged
    assert hops[0].is_reliable is False
    assert hops[0].node_type == "FORGED_OR_UNVERIFIED"
    assert any("Temporal Anomaly" in reason for reason in hops[0].anomaly_reasons)


# =====================================================================
# Hypothesis Property-Based Fuzzing & 200+ Corpus Parse Stress Tests
# =====================================================================

@given(st.text(max_size=500))
@hyp_settings(max_examples=100, deadline=None)
def test_hop_parser_fuzz_arbitrary_strings(random_str: str):
    """Fuzz testing: parser must never raise unhandled exceptions on arbitrary strings."""
    hop = parse_received_header(random_str, order=1)
    assert hop.hop_order == 1
    assert isinstance(hop.anomaly_reasons, list)
    assert 0.0 <= hop.confidence_score <= 1.0


def test_hop_parser_diverse_corpus_200_headers():
    """Evaluate parse robustness and confidence calculation across >= 200 diverse MTA headers."""
    vendors = ["Postfix", "Sendmail", "Exim", "qmail", "Microsoft Exchange", "Google Workspace / Gmail"]
    protocols = ["ESMTPS", "ESMTP", "SMTP", "HTTP", "MSExchange15"]
    timezones = ["+0000", "+0530", "-0500", "-0800", "+0100", "+0900", "UTC", "PST", "EST"]

    headers_corpus = []
    for i in range(210):
        v = vendors[i % len(vendors)]
        p = protocols[i % len(protocols)]
        tz = timezones[i % len(timezones)]
        ip_last = (i % 250) + 1
        if i % 5 == 0:
            # IPv6
            hdr = f"Received: from [2001:db8::{i:x}] by mx{i}.domain.org ({v}) with {p}; Wed, 11 Nov 2026 10:{i%60:02d}:00 {tz}"
        elif i % 7 == 0:
            # With comment and id
            hdr = f"Received: from mail{i}.corp.net (mail{i}.corp.net [198.51.100.{ip_last}]) (using TLSv1.3) by gw.target.in (id 4XYZ{i}) with {p}; 11 Nov 2026 12:{i%60:02d}:00 {tz}"
        else:
            # Standard ESMTPS
            hdr = f"Received: from srv{i}.upstream.com ([185.220.101.{ip_last}]) by relay{i}.isp.com with {p} ({v}); 11 Nov 2026 08:{i%60:02d}:00 {tz}"
        headers_corpus.append(hdr)

    assert len(headers_corpus) >= 200

    parsed_count = 0
    failure_categories = {"unparsed_ip": 0, "unparsed_timestamp": 0}

    for idx, raw_h in enumerate(headers_corpus, start=1):
        hop = parse_received_header(raw_h, order=idx)
        assert hop.raw_header == raw_h
        assert 0.0 <= hop.confidence_score <= 1.0
        if hop.hop_ip:
            parsed_count += 1
        else:
            failure_categories["unparsed_ip"] += 1
        if not hop.timestamp:
            failure_categories["unparsed_timestamp"] += 1

    # Assert > 95% IP parsing success rate on structured MTA headers
    success_rate = (parsed_count / len(headers_corpus)) * 100.0
    assert success_rate >= 95.0, f"Parse success rate too low: {success_rate}%"
    assert failure_categories["unparsed_timestamp"] == 0, "All valid timestamps must parse"

