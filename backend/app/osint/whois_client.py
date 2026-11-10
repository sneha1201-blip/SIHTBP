"""Asynchronous RDAP (Registration Data Access Protocol) Domain Intelligence Client.

Implements IANA bootstrap and RFC 7483 RDAP queries to extract:
- Authoritative domain registration / creation dates
- Exact domain age in days
- Newly Registered Domain (NRD < 30 days) classification
- Accredited registrar telemetry
- In-memory TTL caching with zero-crash timeout protection (2.0s)

Zero Guessing Policy:
- Explicitly rejects TLD-based guessing (never infers domain age from .ru, .xyz, etc.).
- When RDAP servers are unreachable or domain is unallocated, returns domain_age_days=None,
  registrar=None, and resolution_status="UNKNOWN" with explanatory reason.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from pydantic import BaseModel

logger = logging.getLogger("whois_client")

RDAP_BOOTSTRAP_BASE_URL = "https://rdap.org/domain"
DEFAULT_RDAP_TIMEOUT_SECONDS = 2.0
CACHE_TTL_SECONDS = 86400  # 24 hours


class DomainIntel(BaseModel):
    """Authoritative RDAP telemetry for an internet domain."""
    domain: str
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    is_newly_registered: bool = False
    reputation_score: float = 0.0  # 0.0 (benign) to 100.0 (malicious/NRD)
    resolution_status: str = "UNKNOWN"  # RESOLVED or UNKNOWN
    reason: Optional[str] = None
    source: str = "NONE"  # RDAP_LIVE, RDAP_CACHE, FIXTURE, or NONE


# In-memory RDAP response cache: {domain: (DomainIntel, timestamp)}
_RDAP_CACHE: Dict[str, tuple[DomainIntel, float]] = {}


def parse_rdap_response(domain: str, rdap_json: Dict[str, Any], source: str = "RDAP_LIVE") -> DomainIntel:
    """Parse standard RFC 7483 RDAP JSON response into structured DomainIntel."""
    now_utc = datetime.now(timezone.utc)
    creation_dt: Optional[datetime] = None
    registrar_name: Optional[str] = None

    # 1. Parse Events (registration / created)
    events = rdap_json.get("events", [])
    for event in events:
        action = str(event.get("eventAction", "")).lower()
        if action in ("registration", "created", "creation"):
            raw_date = event.get("eventDate")
            if raw_date:
                try:
                    dt = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
                    creation_dt = dt.astimezone(timezone.utc)
                    break
                except Exception:
                    pass

    # 2. Parse Entities for Registrar
    entities = rdap_json.get("entities", [])
    for entity in entities:
        roles = [str(r).lower() for r in entity.get("roles", [])]
        if "registrar" in roles:
            # Check vcardArray
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if len(prop) > 3 and prop[0] == "fn":
                        registrar_name = str(prop[3])
                        break
            if not registrar_name:
                registrar_name = entity.get("handle")
            break

    # 3. Calculate Age in Days & NRD Flag
    age_days: Optional[int] = None
    is_nrd = False
    reputation = 10.0

    if creation_dt:
        diff_days = (now_utc - creation_dt).days
        age_days = max(0, diff_days)
        if age_days < 30:
            is_nrd = True
            reputation = 85.0
        elif age_days < 90:
            reputation = 40.0
        else:
            reputation = 5.0

    return DomainIntel(
        domain=domain,
        domain_age_days=age_days,
        registrar=registrar_name,
        creation_date=creation_dt,
        is_newly_registered=is_nrd,
        reputation_score=reputation,
        resolution_status="RESOLVED" if age_days is not None else "UNKNOWN",
        source=source,
    )


async def lookup_domain_whois(
    domain: str,
    timeout: float = DEFAULT_RDAP_TIMEOUT_SECONDS,
    custom_rdap_db: Optional[Dict[str, Dict[str, Any]]] = None,
) -> DomainIntel:
    """Asynchronously query authoritative RDAP registry with caching and timeout protection."""
    if not domain:
        return DomainIntel(domain="", resolution_status="UNKNOWN", reason="Empty domain")

    clean_dom = domain.lower().strip().split(":")[0].strip(".")
    if "." not in clean_dom:
        return DomainIntel(domain=clean_dom, resolution_status="UNKNOWN", reason="Unqualified domain name")

    now_epoch = datetime.now(timezone.utc).timestamp()

    # 1. Check Custom Fixture (for reproducible testing and benchmarks)
    if custom_rdap_db and clean_dom in custom_rdap_db:
        entry = custom_rdap_db[clean_dom]
        age = entry.get("domain_age_days")
        reg = entry.get("registrar")
        c_date = entry.get("creation_date")
        is_nrd = entry.get("is_newly_registered", (age < 30) if age is not None else False)
        rep = entry.get("reputation_score", 90.0 if is_nrd else 10.0)

        return DomainIntel(
            domain=clean_dom,
            domain_age_days=age,
            registrar=reg,
            creation_date=c_date,
            is_newly_registered=is_nrd,
            reputation_score=rep,
            resolution_status="RESOLVED" if age is not None else "UNKNOWN",
            source="FIXTURE",
        )

    # 2. Check In-Memory Cache (TTL 24 hours)
    if clean_dom in _RDAP_CACHE:
        cached_intel, cached_at = _RDAP_CACHE[clean_dom]
        if now_epoch - cached_at < CACHE_TTL_SECONDS:
            return cached_intel

    # 3. Live RDAP HTTP Query
    url = f"{RDAP_BOOTSTRAP_BASE_URL}/{clean_dom}"
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            headers = {"Accept": "application/rdap+json, application/json"}
            resp = await client.get(url, headers=headers)

            if resp.status_code == 200:
                data = resp.json()
                intel = parse_rdap_response(clean_dom, data, source="RDAP_LIVE")
                _RDAP_CACHE[clean_dom] = (intel, now_epoch)
                return intel
            elif resp.status_code == 404:
                intel = DomainIntel(
                    domain=clean_dom,
                    resolution_status="UNKNOWN",
                    reason="Domain not found in RDAP registry",
                    source="RDAP_LIVE",
                )
                _RDAP_CACHE[clean_dom] = (intel, now_epoch)
                return intel
            else:
                return DomainIntel(
                    domain=clean_dom,
                    resolution_status="UNKNOWN",
                    reason=f"RDAP query returned HTTP {resp.status_code}",
                    source="RDAP_LIVE",
                )
    except Exception as exc:
        logger.debug("RDAP lookup failed for %s: %s", clean_dom, exc)
        return DomainIntel(
            domain=clean_dom,
            resolution_status="UNKNOWN",
            reason=f"RDAP request timeout or network error: {exc}",
            source="NONE",
        )
