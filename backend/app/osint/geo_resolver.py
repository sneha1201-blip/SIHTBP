"""MaxMind GeoLite2-City Geolocation Resolver.

Resolves IP addresses to Country, City, Latitude, Longitude, and Accuracy Radius (km)
using the official MaxMind GeoLite2-City database via maxminddb / geoip2.

Zero Guessing Policy (SIH PS ID: 26106):
- Strictly rejects static prefix tables, first-octet guessing, and geographic defaults (no Nagpur default).
- For unresolvable, private (RFC 1918), or reserved IP addresses: returns latitude=None, longitude=None,
  and an explicit UNRESOLVED status with human-readable reason.
- Reports MaxMind database build date and accuracy radius; never presents city-level as exact coordinates.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel

from backend.app.core.config import settings

logger = logging.getLogger("geo_resolver")


class GeoLocation(BaseModel):
    """Geographical coordinates and precision metadata for an IP address."""

    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: Optional[int] = None
    db_build_date: Optional[str] = None
    is_private: bool = False
    resolution_status: str = "UNRESOLVED"  # RESOLVED or UNRESOLVED
    reason: Optional[str] = None
    source: str = "NONE"  # MAXMIND_MMDB, FIXTURE, or NONE


def is_ip_private_or_local(ip_str: str) -> tuple[bool, Optional[str]]:
    """Check if an IP string is private, loopback, link-local, or reserved."""
    if not ip_str:
        return True, "Empty IP string"
    clean = ip_str.strip().strip("[]").lstrip("IPv6:").lstrip("ipv6:")
    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_loopback:
            return True, "Loopback address (127.0.0.1 / ::1)"
        if ip.is_private:
            return True, "RFC 1918 private network address"
        if ip.is_link_local:
            return True, "Link-local address"
        if ip.is_reserved:
            return True, "IETF reserved / documentation address"
        if ip.is_unspecified:
            return True, "Unspecified address (0.0.0.0 / ::)"
        return False, None
    except ValueError:
        return True, f"Malformed IP address: {ip_str}"


def resolve_ip_geo(
    ip_str: Optional[str],
    custom_geo_db: Optional[Dict[str, Dict[str, Any]]] = None,
) -> GeoLocation:
    """Resolve an IP address to geographical coordinates with zero-guess integrity.

    Returns latitude=None and longitude=None for private, reserved, or unresolvable IPs.
    """
    if not ip_str:
        return GeoLocation(
            ip="",
            is_private=True,
            resolution_status="UNRESOLVED",
            reason="No IP provided",
            source="NONE",
        )

    clean_ip = ip_str.strip().strip("[]").lstrip("IPv6:").lstrip("ipv6:")

    # Check for private, loopback, or reserved IPs
    is_priv, priv_reason = is_ip_private_or_local(clean_ip)
    if is_priv:
        return GeoLocation(
            ip=clean_ip,
            country=None,
            city=None,
            latitude=None,
            longitude=None,
            accuracy_radius_km=None,
            is_private=True,
            resolution_status="UNRESOLVED",
            reason=priv_reason,
            source="RFC1918_FILTER",
        )

    # 1. Custom/Fixture Lookup (for deterministic tests and reproducible benchmarks)
    if custom_geo_db and clean_ip in custom_geo_db:
        entry = custom_geo_db[clean_ip]
        lat = entry.get("latitude") if entry.get("latitude") is not None else entry.get("lat")
        lon = entry.get("longitude") if entry.get("longitude") is not None else entry.get("lon")
        radius = (
            entry.get("accuracy_radius_km")
            if entry.get("accuracy_radius_km") is not None
            else entry.get("accuracy_radius", 20)
        )
        b_date = (
            entry.get("db_build_date")
            if entry.get("db_build_date") is not None
            else entry.get("build_date", "2026-11-01T00:00:00Z")
        )
        return GeoLocation(
            ip=clean_ip,
            country=entry.get("country"),
            city=entry.get("city"),
            latitude=float(lat) if lat is not None else None,
            longitude=float(lon) if lon is not None else None,
            accuracy_radius_km=int(radius) if radius is not None else 20,
            db_build_date=b_date,
            is_private=False,
            resolution_status="RESOLVED" if (lat is not None and lon is not None) else "UNRESOLVED",
            reason=None if (lat is not None and lon is not None) else "Coordinates unavailable in test fixture",
            source="FIXTURE",
        )

    # 2. MaxMind GeoLite2-City Database Lookup
    mmdb_path = settings.MAXMIND_GEOIP_CITY_PATH
    if mmdb_path.exists():
        try:
            import geoip2.database

            with geoip2.database.Reader(str(mmdb_path)) as reader:
                build_epoch = reader.metadata().build_epoch
                build_date = datetime.fromtimestamp(build_epoch, timezone.utc).isoformat()

                response = reader.city(clean_ip)
                lat = response.location.latitude
                lon = response.location.longitude
                accuracy = response.location.accuracy_radius

                if lat is not None and lon is not None:
                    return GeoLocation(
                        ip=clean_ip,
                        country=response.country.name,
                        city=response.city.name,
                        latitude=float(lat),
                        longitude=float(lon),
                        accuracy_radius_km=int(accuracy) if accuracy is not None else None,
                        db_build_date=build_date,
                        is_private=False,
                        resolution_status="RESOLVED",
                        source="MAXMIND_MMDB",
                    )
                else:
                    return GeoLocation(
                        ip=clean_ip,
                        country=response.country.name,
                        city=response.city.name,
                        latitude=None,
                        longitude=None,
                        accuracy_radius_km=None,
                        db_build_date=build_date,
                        is_private=False,
                        resolution_status="UNRESOLVED",
                        reason="MaxMind returned country/city without latitude/longitude coordinates",
                        source="MAXMIND_MMDB",
                    )
        except geoip2.errors.AddressNotFoundError:
            return GeoLocation(
                ip=clean_ip,
                latitude=None,
                longitude=None,
                is_private=False,
                resolution_status="UNRESOLVED",
                reason="IP address not found in MaxMind GeoLite2-City database",
                source="MAXMIND_MMDB",
            )
        except Exception as exc:
            logger.debug("MaxMind database lookup error for %s: %s", clean_ip, exc)
            return GeoLocation(
                ip=clean_ip,
                latitude=None,
                longitude=None,
                is_private=False,
                resolution_status="UNRESOLVED",
                reason=f"MaxMind lookup error: {exc}",
                source="MAXMIND_MMDB",
            )

    # 3. Database not installed (zero guessing, explicit status)
    return GeoLocation(
        ip=clean_ip,
        country=None,
        city=None,
        latitude=None,
        longitude=None,
        accuracy_radius_km=None,
        is_private=False,
        resolution_status="UNRESOLVED",
        reason="MaxMind GeoLite2-City database not installed (run scripts/update_geoip.sh with MAXMIND_LICENSE_KEY)",
        source="NONE",
    )
