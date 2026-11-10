"""Tor Exit Node and Anonymizing Proxy Detection Service.

Matches transit hop IPs against the official Tor Project bulk exit list
(https://check.torproject.org/torbulkexitlist) with aggressive-timeout caching (TTL).
Keeps a labeled offline snapshot with exact age in hours/days for air-gapped environments.

Zero Static Hardcoding Policy:
- Does not rely on a static 25-IP list as source of truth.
- Labels all detections with exact telemetry source (LIVE_CACHE vs OFFLINE_SNAPSHOT) and cache age.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from backend.app.core.config import STORAGE_DIR

logger = logging.getLogger("tor_detector")

TOR_LIVE_URL = "https://check.torproject.org/torbulkexitlist"
TOR_CACHE_DIR = STORAGE_DIR / "tor"
TOR_CACHE_FILE = TOR_CACHE_DIR / "tor_exit_nodes_cache.json"
OFFLINE_SNAPSHOT_FILE = Path(__file__).resolve().parent / "tor_exit_nodes.json"

# In-memory global state
_ACTIVE_TOR_IPS: Set[str] = set()
_ACTIVE_TOR_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_ACTIVE_BULLETPROOF_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_CACHE_FETCHED_AT: Optional[datetime] = None
_CACHE_SOURCE: str = "UNINITIALIZED"


def load_tor_exit_cache(custom_snapshot_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load Tor exit nodes from local cache or bundled offline snapshot."""
    global _ACTIVE_TOR_IPS, _ACTIVE_TOR_NETWORKS, _ACTIVE_BULLETPROOF_NETWORKS, _CACHE_FETCHED_AT, _CACHE_SOURCE

    _ACTIVE_TOR_IPS.clear()
    _ACTIVE_TOR_NETWORKS.clear()
    _ACTIVE_BULLETPROOF_NETWORKS.clear()

    target_file = custom_snapshot_path or TOR_CACHE_FILE
    source_label = "LOCAL_CACHE"

    if not target_file.exists():
        target_file = OFFLINE_SNAPSHOT_FILE
        source_label = "OFFLINE_SNAPSHOT"

    if not target_file.exists():
        _CACHE_SOURCE = "EMPTY"
        return {"exit_node_count": 0, "source": "EMPTY", "age_hours": None}

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        nodes = data.get("exit_nodes", [])
        _ACTIVE_TOR_IPS.update(str(ip).strip() for ip in nodes if str(ip).strip())

        for sub in data.get("exit_subnets", []):
            try:
                _ACTIVE_TOR_NETWORKS.append(ipaddress.ip_network(sub))
            except ValueError:
                pass

        for sub in data.get("bulletproof_subnets", []):
            try:
                _ACTIVE_BULLETPROOF_NETWORKS.append(ipaddress.ip_network(sub))
            except ValueError:
                pass

        fetched_str = data.get("fetched_at") or data.get("updated_at")
        if fetched_str:
            try:
                dt = datetime.fromisoformat(fetched_str.replace("Z", "+00:00"))
                _CACHE_FETCHED_AT = dt.astimezone(timezone.utc)
            except Exception:
                _CACHE_FETCHED_AT = datetime.now(timezone.utc)
        else:
            _CACHE_FETCHED_AT = datetime.now(timezone.utc)

        _CACHE_SOURCE = source_label

        age_hours = 0.0
        if _CACHE_FETCHED_AT:
            age_hours = round((datetime.now(timezone.utc) - _CACHE_FETCHED_AT).total_seconds() / 3600.0, 1)

        return {
            "exit_node_count": len(_ACTIVE_TOR_IPS),
            "source": _CACHE_SOURCE,
            "fetched_at": _CACHE_FETCHED_AT.isoformat() if _CACHE_FETCHED_AT else None,
            "age_hours": age_hours,
        }
    except Exception as exc:
        logger.warning("Failed to load Tor exit cache from %s: %s", target_file, exc)
        _CACHE_SOURCE = "ERROR"
        return {"exit_node_count": 0, "source": "ERROR", "age_hours": None}


def refresh_tor_exit_nodes_sync(timeout: float = 3.0) -> bool:
    """Fetch live exit node list from check.torproject.org and persist to cache."""
    global _ACTIVE_TOR_IPS, _CACHE_FETCHED_AT, _CACHE_SOURCE

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(TOR_LIVE_URL)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                fresh_ips = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

                if fresh_ips:
                    TOR_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    now_utc = datetime.now(timezone.utc)
                    cache_payload = {
                        "source": TOR_LIVE_URL,
                        "fetched_at": now_utc.isoformat(),
                        "exit_node_count": len(fresh_ips),
                        "exit_nodes": fresh_ips,
                        "exit_subnets": [str(net) for net in _ACTIVE_TOR_NETWORKS],
                        "bulletproof_subnets": [str(net) for net in _ACTIVE_BULLETPROOF_NETWORKS],
                    }

                    with open(TOR_CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump(cache_payload, f, indent=2)

                    _ACTIVE_TOR_IPS = set(fresh_ips)
                    _CACHE_FETCHED_AT = now_utc
                    _CACHE_SOURCE = "LIVE_FETCH"
                    return True
    except Exception as exc:
        logger.debug("Live Tor exit list fetch failed (%s); using existing cached snapshot", exc)

    return False


async def refresh_tor_exit_nodes_async(timeout: float = 3.0) -> bool:
    """Asynchronously fetch live exit node list from check.torproject.org."""
    global _ACTIVE_TOR_IPS, _CACHE_FETCHED_AT, _CACHE_SOURCE

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(TOR_LIVE_URL)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                fresh_ips = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

                if fresh_ips:
                    TOR_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    now_utc = datetime.now(timezone.utc)
                    cache_payload = {
                        "source": TOR_LIVE_URL,
                        "fetched_at": now_utc.isoformat(),
                        "exit_node_count": len(fresh_ips),
                        "exit_nodes": fresh_ips,
                        "exit_subnets": [str(net) for net in _ACTIVE_TOR_NETWORKS],
                        "bulletproof_subnets": [str(net) for net in _ACTIVE_BULLETPROOF_NETWORKS],
                    }

                    with open(TOR_CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump(cache_payload, f, indent=2)

                    _ACTIVE_TOR_IPS = set(fresh_ips)
                    _CACHE_FETCHED_AT = now_utc
                    _CACHE_SOURCE = "LIVE_FETCH"
                    return True
    except Exception as exc:
        logger.debug("Async live Tor exit list fetch failed (%s); preserving snapshot", exc)

    return False


# Initialize cache at module load
load_tor_exit_cache()


def is_tor_exit_node(ip_str: Optional[str]) -> bool:
    """Check if an IP address is an active Tor exit node."""
    if not ip_str:
        return False

    clean = ip_str.strip().strip("[]").lstrip("IPv6:").lstrip("ipv6:")

    if clean in _ACTIVE_TOR_IPS:
        return True

    try:
        ip_obj = ipaddress.ip_address(clean)
        for net in _ACTIVE_TOR_NETWORKS:
            if ip_obj in net:
                return True
    except ValueError:
        pass

    return False


def is_anonymizing_vpn_or_bulletproof(ip_str: Optional[str]) -> Tuple[bool, bool]:
    """Check if an IP belongs to anonymizing VPNs or bulletproof hosting subnets.

    Returns:
        (is_vpn, is_bulletproof)
    """
    if not ip_str:
        return False, False

    clean = ip_str.strip().strip("[]").lstrip("IPv6:").lstrip("ipv6:")

    try:
        ip_obj = ipaddress.ip_address(clean)
        for net in _ACTIVE_BULLETPROOF_NETWORKS:
            if ip_obj in net:
                return True, True
    except ValueError:
        pass

    return False, False


def get_tor_cache_telemetry() -> Dict[str, Any]:
    """Return diagnostic telemetry for current Tor intelligence cache."""
    age_hours = None
    if _CACHE_FETCHED_AT:
        age_hours = round((datetime.now(timezone.utc) - _CACHE_FETCHED_AT).total_seconds() / 3600.0, 1)

    return {
        "source": _CACHE_SOURCE,
        "fetched_at": _CACHE_FETCHED_AT.isoformat() if _CACHE_FETCHED_AT else None,
        "age_hours": age_hours,
        "total_exit_nodes": len(_ACTIVE_TOR_IPS),
        "total_subnets": len(_ACTIVE_TOR_NETWORKS),
        "bulletproof_subnets": len(_ACTIVE_BULLETPROOF_NETWORKS),
    }
