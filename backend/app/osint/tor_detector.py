"""Tor Exit Node and Anonymizing Proxy Detection Service.

Matches transit hop IPs against known Tor exit node caches, commercial VPNs,
and bulletproof hosting subnets. Includes bundled offline tor_exit_nodes.json
for air-gapped hackathon execution.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import ipaddress
from typing import Set, List, Tuple

logger = logging.getLogger("tor_detector")

CURRENT_DIR = Path(__file__).resolve().parent
OFFLINE_TOR_JSON = CURRENT_DIR / "tor_exit_nodes.json"

# In-memory caches
LOADED_TOR_EXIT_IPS: Set[str] = set()
LOADED_TOR_SUBNETS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
LOADED_ANON_SUBNETS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

# Hardcoded fallback set
DEFAULT_TOR_IPS: Set[str] = {
    "185.220.101.5",
    "185.220.101.6",
    "185.220.101.7",
    "185.220.100.242",
    "185.220.100.252",
    "171.25.193.20",
    "171.25.193.25",
    "199.249.230.71",
    "199.249.230.82",
    "51.15.43.205",
}

DEFAULT_TOR_SUBNETS = [
    ipaddress.ip_network("185.220.100.0/23"),
    ipaddress.ip_network("171.25.193.0/24"),
    ipaddress.ip_network("199.249.230.0/24"),
]

DEFAULT_ANON_SUBNETS = [
    ipaddress.ip_network("193.109.69.0/24"),   # Alexhost SRL
    ipaddress.ip_network("194.36.191.0/24"),   # Alservice Ltd
    ipaddress.ip_network("45.154.255.0/24"),   # Flowspec / Bulletproof
]


def load_tor_cache():
    """Load Tor exit nodes and bulletproof subnets from bundled JSON cache."""
    global LOADED_TOR_EXIT_IPS, LOADED_TOR_SUBNETS, LOADED_ANON_SUBNETS

    LOADED_TOR_EXIT_IPS = set(DEFAULT_TOR_IPS)
    LOADED_TOR_SUBNETS = list(DEFAULT_TOR_SUBNETS)
    LOADED_ANON_SUBNETS = list(DEFAULT_ANON_SUBNETS)

    if OFFLINE_TOR_JSON.exists():
        try:
            with open(OFFLINE_TOR_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                nodes = data.get("exit_nodes", [])
                LOADED_TOR_EXIT_IPS.update(nodes)

                for sub in data.get("exit_subnets", []):
                    try:
                        net = ipaddress.ip_network(sub)
                        if net not in LOADED_TOR_SUBNETS:
                            LOADED_TOR_SUBNETS.append(net)
                    except ValueError:
                        pass

                for sub in data.get("bulletproof_subnets", []):
                    try:
                        net = ipaddress.ip_network(sub)
                        if net not in LOADED_ANON_SUBNETS:
                            LOADED_ANON_SUBNETS.append(net)
                    except ValueError:
                        pass
            logger.debug("Successfully loaded %d Tor exit nodes from offline cache", len(LOADED_TOR_EXIT_IPS))
        except Exception as exc:
            logger.warning("Could not parse offline tor_exit_nodes.json: %s. Using default sets.", exc)


# Initialize cache at module load
load_tor_cache()


def is_tor_exit_node(ip_str: str) -> bool:
    """Return True if an IP address matches known Tor exit nodes."""
    if not ip_str:
        return False

    if ip_str in LOADED_TOR_EXIT_IPS:
        return True

    try:
        ip = ipaddress.ip_address(ip_str)
        for subnet in LOADED_TOR_SUBNETS:
            if ip in subnet:
                return True
    except ValueError:
        pass

    return False


def is_anonymizing_vpn_or_bulletproof(ip_str: str) -> Tuple[bool, bool]:
    """Check if IP belongs to a commercial VPN or bulletproof VPS hoster.

    Returns:
        Tuple[bool, bool]: (is_vpn, is_bulletproof)
    """
    if not ip_str:
        return False, False

    try:
        ip = ipaddress.ip_address(ip_str)
        for subnet in LOADED_ANON_SUBNETS:
            if ip in subnet:
                return True, True
    except ValueError:
        pass

    return False, False
