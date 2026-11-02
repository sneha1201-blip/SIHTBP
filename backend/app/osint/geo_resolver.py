"""MaxMind GeoIP2 Resolution with Intelligent Offline Forensic Fallback.

Extracts Country, City, Latitude, and Longitude coordinates for MTA transit hops.
Seamlessly falls back to an embedded high-fidelity offline forensic database
when MaxMind .mmdb files are not present in local or air-gapped hackathon environments.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional
from pydantic import BaseModel

from backend.app.core.config import settings

logger = logging.getLogger("geo_resolver")


class GeoLocation(BaseModel):
    """Geographical coordinates and location metadata for an IP address."""
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_private: bool = False
    source: str = "OFFLINE_INTELLIGENCE"  # MAXMIND_MMDB or OFFLINE_INTELLIGENCE


# High-fidelity offline intelligence mapping for Indian institutions, ISPs, and threat infrastructure
OFFLINE_GEO_DATABASE = [
    # Indian National Institutional & Research MTAs (NKN / ERNET / NIC)
    {"prefix": "164.100.24.", "country": "India", "city": "New Delhi", "lat": 28.6139, "lon": 77.2090},
    {"prefix": "164.100.", "country": "India", "city": "New Delhi", "lat": 28.6139, "lon": 77.2090},
    {"prefix": "14.139.245.", "country": "India", "city": "New Delhi", "lat": 28.5450, "lon": 77.1926},
    {"prefix": "14.139.246.", "country": "India", "city": "Delhi", "lat": 28.7501, "lon": 77.1177},
    {"prefix": "14.139.161.", "country": "India", "city": "Chennai", "lat": 13.0827, "lon": 80.2707},
    {"prefix": "14.139.", "country": "India", "city": "New Delhi", "lat": 28.6139, "lon": 77.2090},
    {"prefix": "103.21.124.", "country": "India", "city": "Mumbai", "lat": 19.1334, "lon": 72.9133},
    {"prefix": "210.212.242.", "country": "India", "city": "Chennai", "lat": 13.0108, "lon": 80.2354},
    {"prefix": "210.212.201.", "country": "India", "city": "Surathkal", "lat": 13.0108, "lon": 74.7943},
    {"prefix": "210.212.", "country": "India", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946},
    {"prefix": "202.141.", "country": "India", "city": "New Delhi", "lat": 28.6139, "lon": 77.2090},

    # Indian Major Tier-1 ISPs & Telecom Relays
    {"prefix": "115.112.", "country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    {"prefix": "121.240.", "country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    {"prefix": "182.72.", "country": "India", "city": "Gurugram", "lat": 28.4595, "lon": 77.0266},
    {"prefix": "122.160.", "country": "India", "city": "Noida", "lat": 28.5355, "lon": 77.3910},
    {"prefix": "49.32.", "country": "India", "city": "Navi Mumbai", "lat": 19.0330, "lon": 73.0297},
    {"prefix": "49.36.", "country": "India", "city": "Navi Mumbai", "lat": 19.0330, "lon": 73.0297},
    {"prefix": "117.192.", "country": "India", "city": "Kolkata", "lat": 22.5726, "lon": 88.3639},
    {"prefix": "59.92.", "country": "India", "city": "Hyderabad", "lat": 17.3850, "lon": 78.4867},

    # Known Threat Actors & Bulletproof / Anonymizer Infrastructure
    {"prefix": "185.220.101.", "country": "Germany", "city": "Frankfurt am Main", "lat": 50.1109, "lon": 8.6821},
    {"prefix": "185.220.100.", "country": "Germany", "city": "Frankfurt am Main", "lat": 50.1109, "lon": 8.6821},
    {"prefix": "185.174.136.", "country": "Romania", "city": "Bucharest", "lat": 44.4268, "lon": 26.1025},
    {"prefix": "193.109.69.", "country": "Seychelles", "city": "Victoria", "lat": -4.6191, "lon": 55.4513},
    {"prefix": "194.36.191.", "country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    {"prefix": "45.154.255.", "country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    {"prefix": "195.154.122.", "country": "France", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
    {"prefix": "91.240.118.", "country": "Seychelles", "city": "Victoria", "lat": -4.6191, "lon": 55.4513},
    {"prefix": "171.25.193.", "country": "Sweden", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686},
    {"prefix": "199.249.230.", "country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060},

    # Cloud & Tech Hyper-scalers
    {"prefix": "13.126.", "country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    {"prefix": "3.80.", "country": "United States", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
    {"prefix": "54.240.", "country": "United States", "city": "Seattle", "lat": 47.6062, "lon": -122.3321},
    {"prefix": "209.85.", "country": "United States", "city": "Mountain View", "lat": 37.3861, "lon": -122.0839},
    {"prefix": "142.250.", "country": "United States", "city": "Mountain View", "lat": 37.3861, "lon": -122.0839},
    {"prefix": "40.92.", "country": "United States", "city": "Redmond", "lat": 47.6740, "lon": -122.1215},
    {"prefix": "104.16.", "country": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194},
]


def resolve_ip_geo(ip_str: Optional[str]) -> GeoLocation:
    """Resolve an IP address to Country, City, Lat, Lon coordinates with zero-setup offline fallback."""
    if not ip_str:
        return GeoLocation(ip="", is_private=True, source="NONE")

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return GeoLocation(
                ip=ip_str,
                country="Internal Network",
                city="Local Subnet",
                latitude=None,
                longitude=None,
                is_private=True,
                source="RFC1918",
            )
    except ValueError:
        return GeoLocation(ip=ip_str, is_private=True, source="INVALID_IP")

    # 1. Attempt MaxMind GeoLite2 lookup if database file is installed
    mmdb_path = settings.MAXMIND_GEOIP_CITY_PATH
    if mmdb_path.exists():
        try:
            import geoip2.database
            with geoip2.database.Reader(str(mmdb_path)) as reader:
                response = reader.city(ip_str)
                country_name = response.country.name or "Unknown"
                city_name = response.city.name or "Unknown"
                lat = response.location.latitude
                lon = response.location.longitude

                if lat is not None and lon is not None:
                    return GeoLocation(
                        ip=ip_str,
                        country=country_name,
                        city=city_name,
                        latitude=lat,
                        longitude=lon,
                        is_private=False,
                        source="MAXMIND_MMDB",
                    )
        except Exception as exc:
            logger.debug("MaxMind lookup failed: %s, falling back to offline intelligence", exc)

    # 2. Intelligent Offline Forensic Prefix Database
    for entry in OFFLINE_GEO_DATABASE:
        if ip_str.startswith(entry["prefix"]):
            return GeoLocation(
                ip=ip_str,
                country=entry["country"],
                city=entry["city"],
                latitude=entry["lat"],
                longitude=entry["lon"],
                is_private=False,
                source="OFFLINE_INTELLIGENCE",
            )

    # 3. Deterministic Regional Heuristics based on first octet
    parts = ip_str.split(".")
    first_octet = int(parts[0]) if len(parts) == 4 and parts[0].isdigit() else 0

    if first_octet in (103, 115, 14, 210, 164, 49, 182, 122, 117, 59):
        return GeoLocation(ip=ip_str, country="India", city="New Delhi", latitude=28.6139, longitude=77.2090, source="OFFLINE_REGION")
    elif first_octet in (185, 193, 194, 91, 45, 195, 171, 77, 82, 85):
        return GeoLocation(ip=ip_str, country="European Transit", city="Frankfurt", latitude=50.1109, longitude=8.6821, source="OFFLINE_REGION")
    elif first_octet in (3, 54, 40, 52, 209, 142, 104, 199, 198, 23):
        return GeoLocation(ip=ip_str, country="United States", city="Washington D.C.", latitude=38.9072, longitude=-77.0369, source="OFFLINE_REGION")
    elif first_octet in (202, 203, 128, 133):
        return GeoLocation(ip=ip_str, country="Asia-Pacific", city="Singapore", latitude=1.3521, longitude=103.8198, source="OFFLINE_REGION")

    # Final guaranteed coordinate fallback (India National Gateway coordinates)
    return GeoLocation(
        ip=ip_str,
        country="International Transit Gateway",
        city="Edge POP",
        latitude=20.5937,
        longitude=78.9629,
        is_private=False,
        source="GENERIC_FALLBACK",
    )
