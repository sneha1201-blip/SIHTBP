"""Real-Time DNS-based Blackhole List (DNSBL) IP Reputation Checker.

Performs forward reverse-octet DNS A-record queries against free industry reputation zones:
- Spamhaus ZEN (zen.spamhaus.org)
- Spamcop (bl.spamcop.net)
- Barracuda Central (b.barracudacentral.org)

Protected by aggressive 1.5s timeout guards for air-gapped / offline hackathon execution.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("dnsbl_checker")

DNSBL_TIMEOUT_SECONDS = 1.5

DEFAULT_DNSBL_ZONES = [
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org"},
    {"name": "SpamCop", "zone": "bl.spamcop.net"},
    {"name": "Barracuda Reputation", "zone": "b.barracudacentral.org"},
]


class DNSBLListing(BaseModel):
    """Details of an individual DNSBL listing."""

    provider: str
    return_code: str
    description: str


class DNSBLCheckResult(BaseModel):
    """Consolidated reputation evaluation across queried DNSBL zones."""

    ip: str
    is_listed: bool = False
    listings: List[DNSBLListing] = Field(default_factory=list)
    status: str = "CLEAN"  # CLEAN, LISTED, UNVERIFIABLE
    reason: Optional[str] = None


def reverse_ip_for_dnsbl(ip_str: str) -> Optional[str]:
    """Convert an IPv4 address to reverse dotted-quad notation (e.g. 1.2.3.4 -> 4.3.2.1)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip().strip("[]"))
        if ip.version == 4:
            octets = str(ip).split(".")
            return ".".join(reversed(octets))
        return None
    except ValueError:
        return None


def query_dnsbl(
    ip_str: str,
    zones: Optional[List[Dict[str, str]]] = None,
    timeout: float = DNSBL_TIMEOUT_SECONDS,
    custom_dnsbl_fixtures: Optional[Dict[str, List[Dict[str, str]]]] = None,
) -> DNSBLCheckResult:
    """Query DNSBL zones for an IP address with timeout protection."""
    if not ip_str:
        return DNSBLCheckResult(ip="", status="UNVERIFIABLE", reason="No IP provided")

    clean_ip = ip_str.strip().strip("[]")

    # Check for private or non-routable IPs
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return DNSBLCheckResult(
                ip=clean_ip,
                status="CLEAN",
                reason="Private RFC 1918 / Local address is excluded from public DNSBL checks.",
            )
    except ValueError:
        return DNSBLCheckResult(ip=clean_ip, status="UNVERIFIABLE", reason="Malformed IP address")

    # 1. Custom/Fixture Lookup (for tests and offline benchmarks)
    if custom_dnsbl_fixtures and clean_ip in custom_dnsbl_fixtures:
        fixture_listings = [
            DNSBLListing(
                provider=item.get("provider", "TestDNSBL"),
                return_code=item.get("return_code", "127.0.0.2"),
                description=item.get("description", "Confirmed threat actor IP"),
            )
            for item in custom_dnsbl_fixtures[clean_ip]
        ]
        return DNSBLCheckResult(
            ip=clean_ip,
            is_listed=len(fixture_listings) > 0,
            listings=fixture_listings,
            status="LISTED" if fixture_listings else "CLEAN",
        )

    reversed_ip = reverse_ip_for_dnsbl(clean_ip)
    if not reversed_ip:
        return DNSBLCheckResult(ip=clean_ip, status="UNVERIFIABLE", reason="IPv6 DNSBL not supported")

    active_zones = zones or DEFAULT_DNSBL_ZONES
    listings: List[DNSBLListing] = []

    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for z in active_zones:
            query_name = f"{reversed_ip}.{z['zone']}"
            try:
                answers = resolver.resolve(query_name, "A")
                for rdata in answers:
                    code = str(rdata)
                    listings.append(
                        DNSBLListing(
                            provider=z["name"],
                            return_code=code,
                            description=f"Listed on {z['name']} (return code {code})",
                        )
                    )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue

        return DNSBLCheckResult(
            ip=clean_ip,
            is_listed=len(listings) > 0,
            listings=listings,
            status="LISTED" if listings else "CLEAN",
        )
    except Exception as exc:
        logger.debug("DNSBL resolver exception for %s: %s", clean_ip, exc)
        return DNSBLCheckResult(
            ip=clean_ip,
            status="UNVERIFIABLE",
            reason=f"DNSBL resolution error or timeout: {exc}",
        )
