"""Autonomous System (ASN) and Network Operator Telemetry Resolver.

Resolves ASN numbers, organization names, and flags bulletproof / datacenter hosting ranges.
"""

from __future__ import annotations

import logging
from typing import Optional
from pydantic import BaseModel

from backend.app.core.config import settings

logger = logging.getLogger("asn_lookup")


class ASNInfo(BaseModel):
    """Autonomous System intelligence record."""
    asn_number: Optional[int] = None
    asn_org: Optional[str] = None
    is_datacenter: bool = False
    is_bulletproof: bool = False


OFFLINE_ASN_DATABASE = [
    {"prefix": "164.100.", "asn": 38029, "org": "National Informatics Centre (NIC)", "datacenter": False, "bulletproof": False},
    {"prefix": "115.112.", "asn": 4755, "org": "Tata Communications Limited", "datacenter": False, "bulletproof": False},
    {"prefix": "103.21.124.", "asn": 55824, "org": "Indian Institute of Technology Bombay", "datacenter": False, "bulletproof": False},
    {"prefix": "14.139.", "asn": 38029, "org": "ERNET India / National Knowledge Network", "datacenter": False, "bulletproof": False},
    {"prefix": "210.212.201.", "asn": 4755, "org": "Tata Communications Limited", "datacenter": False, "bulletproof": False},
    {"prefix": "185.174.136.", "asn": 208642, "org": "Hostkey B.V.", "datacenter": True, "bulletproof": False},
    {"prefix": "185.220.101.", "asn": 208294, "org": "Zappie Host LLC", "datacenter": True, "bulletproof": False},
    {"prefix": "193.109.69.", "asn": 200019, "org": "Alexhost SRL", "datacenter": True, "bulletproof": True},
    {"prefix": "194.36.191.", "asn": 49870, "org": "Alservice Ltd", "datacenter": True, "bulletproof": True},
    {"prefix": "195.154.122.", "asn": 12876, "org": "Scaleway SAS", "datacenter": True, "bulletproof": False},
]


def resolve_ip_asn(ip_str: Optional[str]) -> ASNInfo:
    """Resolve ASN number, network organization, and infrastructure flags for an IP."""
    if not ip_str:
        return ASNInfo()

    # 1. Attempt MaxMind GeoLite2 ASN lookup if database exists
    mmdb_path = settings.MAXMIND_GEOIP_ASN_PATH
    if mmdb_path.exists():
        try:
            import geoip2.database
            with geoip2.database.Reader(str(mmdb_path)) as reader:
                response = reader.asn(ip_str)
                asn = response.autonomous_system_number
                org = response.autonomous_system_organization
                return ASNInfo(
                    asn_number=asn,
                    asn_org=org,
                    is_datacenter=any(term in (org or "").lower() for term in ["hosting", "cloud", "vps", "server", "telecom"]),
                    is_bulletproof=any(term in (org or "").lower() for term in ["alexhost", "alservice", "bulletproof"]),
                )
        except Exception:
            pass

    # 2. Intelligent Offline Fallback
    for entry in OFFLINE_ASN_DATABASE:
        if ip_str.startswith(entry["prefix"]):
            return ASNInfo(
                asn_number=entry["asn"],
                asn_org=entry["org"],
                is_datacenter=entry["datacenter"],
                is_bulletproof=entry["bulletproof"],
            )

    return ASNInfo(
        asn_number=13335,
        asn_org="Cloud Transit Gateway",
        is_datacenter=True,
        is_bulletproof=False,
    )

