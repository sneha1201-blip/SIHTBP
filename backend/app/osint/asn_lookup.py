"""Autonomous System (ASN) and Network Operator Telemetry Resolver.

Resolves ASN numbers, organization names, and infrastructure classifications
using the official MaxMind GeoLite2-ASN database via maxminddb / geoip2.

Zero Guessing Policy:
- Does not guess ASN based on prefixes or default to Cloudflare ASN.
- If database is missing or IP is unallocated: returns asn_number=None, asn_org=None,
  and resolution_status="UNRESOLVED" with explicit explanation.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional

from pydantic import BaseModel

from backend.app.core.config import settings

logger = logging.getLogger("asn_lookup")


class ASNInfo(BaseModel):
    """Autonomous System intelligence record."""
    asn_number: Optional[int] = None
    asn_org: Optional[str] = None
    is_datacenter: bool = False
    is_bulletproof: bool = False
    resolution_status: str = "UNRESOLVED"  # RESOLVED or UNRESOLVED
    reason: Optional[str] = None
    source: str = "NONE"


def resolve_ip_asn(
    ip_str: Optional[str],
    custom_asn_db: Optional[Dict[str, Dict[str, Any]]] = None,
) -> ASNInfo:
    """Resolve ASN number, network organization, and infrastructure flags for an IP."""
    if not ip_str:
        return ASNInfo(reason="No IP provided")

    clean_ip = ip_str.strip().strip("[]").lstrip("IPv6:").lstrip("ipv6:")

    # Check for private or loopback IPs
    try:
        ip = ipaddress.ip_address(clean_ip)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return ASNInfo(
                asn_number=None,
                asn_org="Private Subnet",
                is_datacenter=False,
                is_bulletproof=False,
                resolution_status="UNRESOLVED",
                reason="Private RFC 1918 / Loopback address has no public ASN",
                source="RFC1918_FILTER",
            )
    except ValueError:
        return ASNInfo(reason=f"Malformed IP: {ip_str}")

    # 1. Custom/Fixture Lookup (for tests and reproducible benchmarks)
    if custom_asn_db and clean_ip in custom_asn_db:
        entry = custom_asn_db[clean_ip]
        asn_num = entry.get("asn")
        org_name = entry.get("org")
        return ASNInfo(
            asn_number=int(asn_num) if asn_num is not None else None,
            asn_org=str(org_name) if org_name is not None else None,
            is_datacenter=bool(entry.get("is_datacenter", False)),
            is_bulletproof=bool(entry.get("is_bulletproof", False)),
            resolution_status="RESOLVED" if asn_num is not None else "UNRESOLVED",
            reason=None if asn_num is not None else "ASN unallocated in fixture",
            source="FIXTURE",
        )

    # 2. MaxMind GeoLite2 ASN Lookup
    mmdb_path = settings.MAXMIND_GEOIP_ASN_PATH
    if mmdb_path.exists():
        try:
            import geoip2.database

            with geoip2.database.Reader(str(mmdb_path)) as reader:
                response = reader.asn(clean_ip)
                asn = response.autonomous_system_number
                org = response.autonomous_system_organization
                org_lower = (org or "").lower()

                return ASNInfo(
                    asn_number=asn,
                    asn_org=org,
                    is_datacenter=any(
                        term in org_lower
                        for term in ["hosting", "cloud", "vps", "server", "telecom", "datacenter", "ovh", "hetzner", "digitalocean", "linode", "aws", "amazon"]
                    ),
                    is_bulletproof=any(
                        term in org_lower
                        for term in ["alexhost", "alservice", "bulletproof", "offshore", "floki"]
                    ),
                    resolution_status="RESOLVED",
                    source="MAXMIND_MMDB",
                )
        except geoip2.errors.AddressNotFoundError:
            return ASNInfo(
                resolution_status="UNRESOLVED",
                reason="IP not found in MaxMind GeoLite2-ASN database",
                source="MAXMIND_MMDB",
            )
        except Exception as exc:
            logger.debug("MaxMind ASN lookup error for %s: %s", clean_ip, exc)
            return ASNInfo(
                resolution_status="UNRESOLVED",
                reason=f"MaxMind ASN lookup error: {exc}",
                source="MAXMIND_MMDB",
            )

    return ASNInfo(
        resolution_status="UNRESOLVED",
        reason="MaxMind GeoLite2-ASN database not installed (run scripts/update_geoip.sh with MAXMIND_LICENSE_KEY)",
        source="NONE",
    )
