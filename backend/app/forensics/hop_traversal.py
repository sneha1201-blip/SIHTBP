"""Reverse Hop-Traversal Forensic Algorithm for Email Received Headers.

Analyzes MTA transit routes from bottom-to-top (chronological originating order),
validates downstream MTA trust boundaries, identifies RFC 1918 private address ranges,
detects forged Received headers, and extracts the Earliest Reliable Public Originating IP.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Optional, Tuple
from pydantic import BaseModel


class HopAnalysis(BaseModel):
    """Detailed forensic evaluation of an individual MTA transit hop."""
    hop_order: int
    raw_header: str
    by_mta: Optional[str] = None
    from_mta: Optional[str] = None
    hop_ip: Optional[str] = None
    is_private_ip: bool = False
    is_reliable: bool = True
    protocol: Optional[str] = None
    timestamp: Optional[datetime] = None
    delay_seconds: float = 0.0
    node_type: str = "RELAY"  # ORIGINATING, RELAY, EDGE_GATEWAY, INTERNAL, TOR_EXIT, FORGED_OR_UNVERIFIED


# Regular expressions for Received: header tokens
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b")
BY_REGEX = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
FROM_REGEX = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)
WITH_REGEX = re.compile(r"\bwith\s+([A-Za-z0-9_-]+)", re.IGNORECASE)
TIMESTAMP_SPLIT_REGEX = re.compile(r";\s*([^;]+)$")


def is_ip_private(ip_str: str) -> bool:
    """Check if an IPv4 or IPv6 address is RFC 1918 private, loopback, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    except ValueError:
        return False


def parse_received_header(header_str: str, order: int) -> HopAnalysis:
    """Parse an individual RFC 5321 Received header string into structured attributes."""
    cleaned = " ".join(header_str.split())

    # Extract by MTA
    by_match = BY_REGEX.search(cleaned)
    by_mta = by_match.group(1).rstrip(";()") if by_match else None

    # Extract from MTA
    from_match = FROM_REGEX.search(cleaned)
    from_mta = from_match.group(1).rstrip(";()") if from_match else None

    # Extract Protocol (ESMTPS, ESMTPA, SMTP)
    with_match = WITH_REGEX.search(cleaned)
    protocol = with_match.group(1).upper() if with_match else None

    # Extract IP address (prefer bracketed IP inside `from` segment)
    hop_ip = None
    from_segment = cleaned.split("by")[0] if "by" in cleaned else cleaned
    bracketed = re.findall(r"\[([0-9a-fA-F.:]+)\]", from_segment)
    if bracketed:
        for candidate in bracketed:
            if IPV4_REGEX.match(candidate) or IPV6_REGEX.match(candidate):
                hop_ip = candidate
                break

    if not hop_ip:
        # Fallback to any IP in the header
        ips = IPV4_REGEX.findall(cleaned)
        if ips:
            hop_ip = ips[0]

    is_priv = is_ip_private(hop_ip) if hop_ip else False

    # Extract timestamp
    timestamp = None
    time_match = TIMESTAMP_SPLIT_REGEX.search(cleaned)
    if time_match:
        time_candidate = time_match.group(1).strip()
        try:
            timestamp = parsedate_to_datetime(time_candidate)
        except Exception:
            timestamp = None

    return HopAnalysis(
        hop_order=order,
        raw_header=cleaned,
        by_mta=by_mta,
        from_mta=from_mta,
        hop_ip=hop_ip,
        is_private_ip=is_priv,
        protocol=protocol,
        timestamp=timestamp,
        is_reliable=True,
    )


def reverse_hop_traversal(received_headers: List[str]) -> Tuple[List[HopAnalysis], Optional[str]]:
    """Execute the Reverse Hop-Traversal Algorithm with MTA Handoff Continuity Verification.

    In standard MIME messages, Received: headers are appended at the top,
    meaning index 0 is the recipient's internal server, and the last index is
    the originating MTA.

    Chronological Order:
    Reversing the list puts the originating MTA at index 0 (hop 1) and recipient edge at the end.
    We traverse in chronological order, compute transit latencies, evaluate trust boundaries,
    detect forged headers, and pinpoint the Earliest Reliable Public Originating IP.

    Returns:
        Tuple[List[HopAnalysis], Optional[str]]: (analyzed_hops, earliest_reliable_public_ip)
    """
    if not received_headers:
        return [], None

    # Put into chronological transit order: earliest (origin) -> latest (destination)
    chronological_raw = list(reversed(received_headers))
    hops: List[HopAnalysis] = []

    previous_time = None
    for idx, raw_hdr in enumerate(chronological_raw, start=1):
        hop = parse_received_header(raw_hdr, order=idx)

        # Calculate transit delay from previous hop
        if previous_time and hop.timestamp:
            try:
                diff = (hop.timestamp - previous_time).total_seconds()
                hop.delay_seconds = max(0.0, diff)
            except Exception:
                hop.delay_seconds = 0.0

        if hop.timestamp:
            previous_time = hop.timestamp

        hops.append(hop)

    # Detect Forged Received Headers & Handoff Discontinuities:
    # An attacker can inject arbitrary fake "Received:" headers into an email before sending.
    # We inspect consecutive hops for physical impossibility or forged indicators:
    for i in range(len(hops) - 1):
        curr_hop = hops[i]
        next_hop = hops[i + 1]

        # 1. Temporal Anomaly: Hop timestamp claims to occur drastically after downstream recipient hop
        if curr_hop.timestamp and next_hop.timestamp:
            try:
                time_delta = (curr_hop.timestamp - next_hop.timestamp).total_seconds()
                # If current hop claims to be > 3600s in the future compared to downstream hop
                if time_delta > 3600:
                    curr_hop.is_reliable = False
                    curr_hop.node_type = "FORGED_OR_UNVERIFIED"
            except Exception:
                pass

        # 2. Forged syntax without identifiable IP or MTA identity
        if not curr_hop.hop_ip and not curr_hop.from_mta:
            curr_hop.is_reliable = False
            curr_hop.node_type = "FORGED_OR_UNVERIFIED"

    # Classify node types
    if hops:
        if hops[0].node_type != "FORGED_OR_UNVERIFIED":
            hops[0].node_type = "ORIGINATING"
        hops[-1].node_type = "EDGE_GATEWAY"

    for h in hops:
        if h.is_private_ip and h.node_type == "RELAY":
            h.node_type = "INTERNAL"

    # Identify the Earliest Reliable Public Originating IP
    # Search for the earliest hop that is reliable and public
    earliest_public_ip = None
    for h in hops:
        if h.hop_ip and not h.is_private_ip and h.is_reliable:
            earliest_public_ip = h.hop_ip
            break

    # Fallback to first available public IP if strict search yielded none
    if not earliest_public_ip:
        for h in hops:
            if h.hop_ip and not h.is_private_ip:
                earliest_public_ip = h.hop_ip
                break

    # If all hops are private (e.g. internal network trace), take first hop IP
    if not earliest_public_ip and hops and hops[0].hop_ip:
        earliest_public_ip = hops[0].hop_ip

    return hops, earliest_public_ip
