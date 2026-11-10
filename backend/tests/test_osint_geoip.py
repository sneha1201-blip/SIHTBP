"""Comprehensive Test Suite for Geolocation, ASN, Tor, RDAP, and DNSBL OSINT.

Validates:
- Zero-guess GeoIP resolution (MaxMind GeoLite2-City standard, null coordinates for unresolved/private)
- Zero-guess ASN telemetry resolution (MaxMind GeoLite2-ASN standard, unallocated handled explicitly)
- Tor Exit Node detection with TTL caching and age-labeled offline snapshots
- RFC 7483 RDAP domain intelligence, exact domain age calculation, and NRD (< 30 days) classification
- Real-time DNSBL reverse IP query logic with timeout guards and private IP exclusion
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.app.osint.asn_lookup import (
    resolve_ip_asn,
)
from backend.app.osint.dnsbl_checker import (
    query_dnsbl,
    reverse_ip_for_dnsbl,
)
from backend.app.osint.geo_resolver import (
    resolve_ip_geo,
)
from backend.app.osint.tor_detector import (
    get_tor_cache_telemetry,
    is_anonymizing_vpn_or_bulletproof,
    is_tor_exit_node,
    load_tor_exit_cache,
)
from backend.app.osint.whois_client import (
    lookup_domain_whois,
    parse_rdap_response,
)

# =====================================================================
# 1. GeoIP Zero-Guessing Tests
# =====================================================================

def test_geoip_private_and_loopback_rejection():
    """Verify that private and loopback IPs strictly return null coordinates and UNRESOLVED status."""
    private_ips = ["127.0.0.1", "10.0.1.5", "192.168.1.1", "172.16.5.20", "::1", "fc00::1"]
    for ip in private_ips:
        res = resolve_ip_geo(ip)
        assert res.latitude is None
        assert res.longitude is None
        assert res.country is None
        assert res.city is None
        assert res.is_private is True
        assert res.resolution_status == "UNRESOLVED"
        assert res.source == "RFC1918_FILTER"
        assert res.reason is not None


def test_geoip_fixture_resolution_with_accuracy():
    """Verify resolution via fixture data reports city, country, accuracy radius, and build date."""
    fixtures = {
        "185.220.101.5": {
            "country": "Germany",
            "city": "Frankfurt am Main",
            "lat": 50.1109,
            "lon": 8.6821,
            "accuracy_radius": 20,
            "build_date": "2026-11-01",
        }
    }
    res = resolve_ip_geo("185.220.101.5", custom_geo_db=fixtures)
    assert res.resolution_status == "RESOLVED"
    assert res.country == "Germany"
    assert res.city == "Frankfurt am Main"
    assert res.latitude == 50.1109
    assert res.longitude == 8.6821
    assert res.accuracy_radius_km == 20
    assert res.db_build_date == "2026-11-01"
    assert res.source == "FIXTURE"


def test_geoip_unresolved_public_ip():
    """Verify that public IP without database entry returns UNRESOLVED with null coordinates."""
    # An IP not in fixture and with no local MMDB present returns UNRESOLVED
    res = resolve_ip_geo("8.8.8.8", custom_geo_db={})
    assert res.latitude is None
    assert res.longitude is None
    assert res.resolution_status == "UNRESOLVED"
    assert res.reason is not None


# =====================================================================
# 2. ASN Telemetry Tests
# =====================================================================

def test_asn_private_ip_rejection():
    """Verify private IPs return UNRESOLVED ASN with explanatory reason."""
    res = resolve_ip_asn("192.168.1.1")
    assert res.asn_number is None
    assert res.resolution_status == "UNRESOLVED"
    assert "Private RFC 1918" in (res.reason or "")


def test_asn_fixture_resolution():
    """Verify ASN resolution via fixture correctly identifies datacenter and bulletproof flags."""
    fixtures = {
        "185.220.101.5": {
            "asn": 208294,
            "org": "Zwiebelfreunde e.V. Hosting Datacenter",
            "is_datacenter": True,
            "is_bulletproof": False,
        },
        "91.240.118.15": {
            "asn": 44050,
            "org": "Alexhost Bulletproof Offshore VPS",
            "is_datacenter": True,
            "is_bulletproof": True,
        },
    }
    res1 = resolve_ip_asn("185.220.101.5", custom_asn_db=fixtures)
    assert res1.asn_number == 208294
    assert res1.asn_org == "Zwiebelfreunde e.V. Hosting Datacenter"
    assert res1.is_datacenter is True
    assert res1.is_bulletproof is False
    assert res1.resolution_status == "RESOLVED"

    res2 = resolve_ip_asn("91.240.118.15", custom_asn_db=fixtures)
    assert res2.asn_number == 44050
    assert res2.is_bulletproof is True
    assert res2.resolution_status == "RESOLVED"


# =====================================================================
# 3. Tor Exit Node & Anonymizer Tests
# =====================================================================

def test_tor_cache_loading_and_age(tmp_path: Path):
    """Verify loading Tor exit nodes from JSON snapshot, calculating age in hours."""
    snapshot_data = {
        "source": "https://check.torproject.org/torbulkexitlist",
        "fetched_at": (datetime.now(timezone.utc) - timedelta(hours=3.5)).isoformat(),
        "exit_nodes": ["185.220.101.5", "199.249.230.68"],
        "exit_subnets": ["185.220.101.0/24"],
        "bulletproof_subnets": ["91.240.118.0/24"],
    }
    snapshot_file = tmp_path / "test_tor_snapshot.json"
    snapshot_file.write_text(json.dumps(snapshot_data), encoding="utf-8")

    meta = load_tor_exit_cache(custom_snapshot_path=snapshot_file)
    assert meta["exit_node_count"] == 2
    assert meta["age_hours"] >= 3.0
    assert meta["source"] == "LOCAL_CACHE"

    # Test detection
    assert is_tor_exit_node("185.220.101.5") is True

    # Test subnet match
    assert is_tor_exit_node("185.220.101.99") is True

    # Test clean IP
    assert is_tor_exit_node("8.8.8.8") is False

    # Test comprehensive anonymizer check
    is_vpn, is_bp = is_anonymizing_vpn_or_bulletproof("91.240.118.15")
    assert is_bp is True
    assert is_vpn is True

    # Test telemetry
    telemetry = get_tor_cache_telemetry()
    assert telemetry["total_exit_nodes"] == 2
    assert telemetry["source"] == "LOCAL_CACHE"


# =====================================================================
# 4. RFC 7483 RDAP Domain Intelligence Tests
# =====================================================================

def test_rdap_parse_nrd_detection():
    """Verify parsing RDAP JSON identifying Newly Registered Domain (< 30 days old)."""
    now_utc = datetime.now(timezone.utc)
    recent_reg = (now_utc - timedelta(days=12)).isoformat()

    mock_rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": recent_reg},
            {"eventAction": "last changed", "eventDate": recent_reg},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "NameCheap, Inc."],
                    ],
                ],
            }
        ],
    }

    intel = parse_rdap_response("fresh-phish-domain.xyz", mock_rdap)
    assert intel.domain == "fresh-phish-domain.xyz"
    assert intel.domain_age_days == 12
    assert intel.is_newly_registered is True
    assert intel.reputation_score == 85.0
    assert intel.registrar == "NameCheap, Inc."
    assert intel.resolution_status == "RESOLVED"


def test_rdap_parse_established_domain():
    """Verify established domain (> 90 days) receives benign reputation."""
    established_reg = "2010-05-15T00:00:00Z"
    mock_rdap = {
        "events": [{"eventAction": "registration", "eventDate": established_reg}],
        "entities": [{"roles": ["registrar"], "handle": "GoDaddy.com, LLC"}],
    }
    intel = parse_rdap_response("legit-bank.com", mock_rdap)
    assert intel.domain_age_days is not None
    assert intel.domain_age_days > 5000
    assert intel.is_newly_registered is False
    assert intel.reputation_score == 5.0
    assert intel.registrar == "GoDaddy.com, LLC"
    assert intel.resolution_status == "RESOLVED"


@pytest.mark.asyncio
async def test_rdap_unreachable_returns_unknown():
    """Verify unreachable domain returns explicit UNKNOWN status without guessing."""
    # Query an invalid domain or unresolvable test with empty fixture
    intel = await lookup_domain_whois("non-existent-sub.invalid", custom_rdap_db={})
    assert intel.resolution_status == "UNKNOWN"
    assert intel.domain_age_days is None
    assert intel.is_newly_registered is False
    assert intel.reason is not None


# =====================================================================
# 5. Real-Time DNSBL Reputation Checker Tests
# =====================================================================

def test_dnsbl_reverse_ip_format():
    """Verify IPv4 octets are correctly reversed for DNSBL A-record queries."""
    assert reverse_ip_for_dnsbl("198.51.100.25") == "25.100.51.198"
    assert reverse_ip_for_dnsbl("127.0.0.1") == "1.0.0.127"
    assert reverse_ip_for_dnsbl("invalid-ip") is None


def test_dnsbl_private_ip_bypass():
    """Verify private IPs are immediately marked CLEAN with exclusion reason."""
    res = query_dnsbl("192.168.1.1")
    assert res.status == "CLEAN"
    assert res.is_listed is False
    assert "Private RFC 1918" in (res.reason or "")


def test_dnsbl_fixture_threat_actor_listing():
    """Verify listed IP in fixture is correctly identified with provider and return code."""
    fixtures = {
        "185.220.101.5": [
            {"provider": "Spamhaus ZEN", "return_code": "127.0.0.2", "description": "SBL - Spamhaus Block List"},
            {"provider": "SpamCop", "return_code": "127.0.0.2", "description": "SpamCop Active Botnet"},
        ]
    }
    res = query_dnsbl("185.220.101.5", custom_dnsbl_fixtures=fixtures)
    assert res.status == "LISTED"
    assert res.is_listed is True
    assert len(res.listings) == 2
    assert res.listings[0].provider == "Spamhaus ZEN"
    assert res.listings[1].provider == "SpamCop"
