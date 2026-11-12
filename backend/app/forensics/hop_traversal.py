"""Reverse Hop-Traversal Forensic Algorithm for Email Received Headers.

Analyzes MTA transit routes from bottom-to-top (chronological originating order),
validates downstream MTA trust boundaries, parses diverse real-world MTA header formats
(Microsoft Exchange, Postfix, Gmail / Google Workspace, Sendmail, qmail, Exim),
handles IPv4 / IPv6 addresses (bracketed, unbracketed, IPv6: prefix), normalizes timestamps to UTC,
detects clock skew and out-of-order hops, identifies forged lower hops below the recipient
trust boundary, and extracts the Earliest Reliable Public Originating IP.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("hop_traversal")


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
    mta_vendor: Optional[str] = None
    timestamp: Optional[datetime] = None
    delay_seconds: float = 0.0
    clock_skew_detected: bool = False
    node_type: str = "RELAY"  # ORIGINATING, RELAY, EDGE_GATEWAY, INTERNAL, TOR_EXIT, FORGED_OR_UNVERIFIED
    confidence_score: float = 1.0
    anomaly_reasons: List[str] = Field(default_factory=list)


# Robust regular expressions for RFC 5321 Received header components
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b|(?:::ffff:)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

BY_REGEX = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
FROM_REGEX = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
WITH_REGEX = re.compile(r"\bwith\s+([A-Za-z0-9_-]+(?:\s+[A-Za-z0-9_-]+)*?)(\s+id|\s+for|\s*;)", re.IGNORECASE)
TIMESTAMP_SPLIT_REGEX = re.compile(r";\s*([^;]+)$")


def is_ip_private_or_reserved(ip_str: str) -> bool:
    """Check if an IPv4 or IPv6 address is RFC 1918 private, loopback, link-local, or reserved."""
    if not ip_str:
        return False
    clean = ip_str.strip().strip("[]").lstrip("IPv6:").lstrip("ipv6:")
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    except ValueError:
        return False


# Backward-compatibility alias
is_ip_private = is_ip_private_or_reserved


def extract_ip_address_from_hop(cleaned_header: str) -> Optional[str]:
    """Extract and validate the most reliable relaying IP address from a Received header.

    Prefers IP inside `from ... (...)` or `from ... [...]` segment.
    Correctly unwraps IPv6 prefixes (`IPv6:2001:db8::1` -> `2001:db8::1`).
    """
    # 1. Look for bracketed IP inside the 'from' segment before 'by'
    from_segment = cleaned_header.split("by")[0] if "by" in cleaned_header else cleaned_header

    # Match bracketed strings: [1.2.3.4] or [IPv6:2001:db8::1] or (1.2.3.4)
    bracketed = re.findall(r"[\[\(]([0-9a-fA-F.:]+|IPv6:[0-9a-fA-F.:]+)[\]\)]", from_segment, re.IGNORECASE)
    for candidate in bracketed:
        clean = candidate.strip().lstrip("IPv6:").lstrip("ipv6:")
        try:
            ipaddress.ip_address(clean)
            return clean
        except ValueError:
            continue

    # 2. Look for any IPv4 in the from_segment
    ips = IPV4_REGEX.findall(from_segment)
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            continue

    # 3. Look for any IPv6 in the from_segment
    ipv6_candidates = re.findall(r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b", from_segment)
    for ip in ipv6_candidates:
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            continue

    # 4. Search the entire header
    all_ips = IPV4_REGEX.findall(cleaned_header)
    if all_ips:
        return all_ips[0]

    return None


def identify_mta_vendor(header_str: str) -> str:
    """Identify MTA software vendor from header signatures."""
    h_lower = header_str.lower()
    if "microsoft smtp server" in h_lower or "exchange" in h_lower or "outlook" in h_lower:
        return "Microsoft Exchange"
    elif "postfix" in h_lower:
        return "Postfix"
    elif "by 2002:" in h_lower or "google.com" in h_lower or "gmail" in h_lower:
        return "Google Workspace / Gmail"
    elif "sendmail" in h_lower or bool(re.search(r"\(8\.[0-9]+", h_lower)):
        return "Sendmail"
    elif "qmail" in h_lower:
        return "qmail"
    elif "exim" in h_lower:
        return "Exim"
    return "Standard RFC 5321 MTA"


def parse_received_header(header_str: str, order: int) -> HopAnalysis:
    """Parse an individual RFC 5321 Received header string into structured forensic attributes."""
    cleaned = " ".join(header_str.split())

    # Extract by MTA
    by_match = BY_REGEX.search(cleaned)
    by_mta = by_match.group(1).rstrip(";()") if by_match else None

    # Extract from MTA
    from_match = FROM_REGEX.search(cleaned)
    from_mta = from_match.group(1).rstrip(";()") if from_match else None

    # Extract Protocol (ESMTPS, ESMTPA, SMTP, HTTP, etc.)
    with_match = WITH_REGEX.search(cleaned)
    protocol = with_match.group(1).upper().strip() if with_match else None
    if not protocol:
        p_match = re.search(r"\bwith\s+([A-Za-z0-9_-]+)", cleaned, re.IGNORECASE)
        protocol = p_match.group(1).upper() if p_match else None

    # Extract IP address
    hop_ip = extract_ip_address_from_hop(cleaned)
    is_priv = is_ip_private_or_reserved(hop_ip) if hop_ip else False

    # Extract MTA vendor
    vendor = identify_mta_vendor(cleaned)

    # Extract & normalize timestamp to UTC
    timestamp: Optional[datetime] = None
    time_match = TIMESTAMP_SPLIT_REGEX.search(cleaned)
    if time_match:
        time_candidate = time_match.group(1).strip()
        # Strip trailing comments like (PST) or (UTC)
        time_clean = re.sub(r"\s*\([A-Za-z0-9_+\-\s]+\)$", "", time_candidate).strip()
        try:
            raw_dt = parsedate_to_datetime(time_clean)
            if raw_dt.tzinfo is None:
                timestamp = raw_dt.replace(tzinfo=timezone.utc)
            else:
                timestamp = raw_dt.astimezone(timezone.utc)
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
        mta_vendor=vendor,
        timestamp=timestamp,
        is_reliable=True,
    )


def reverse_hop_traversal(received_headers: List[str]) -> Tuple[List[HopAnalysis], Optional[str]]:
    """Execute reverse hop-traversal forensic analysis with trust boundary validation.

    Chronological traversal:
    - Reverses RFC 822 Received headers (top header = index 0 = recipient edge gateway).
    - Traverses from earliest claimed hop (order 1) to final receiving edge gateway (order N).
    - Computes transit delays and flags clock skew or negative latency anomalies.
    - Validates downstream MTA trust boundaries: any lower hops below an untrusted relay
      or with impossible timestamps / broken handoffs are flagged as FORGED_OR_UNVERIFIED.
    - Determines the Earliest Reliable Public Originating IP after the trust boundary.

    Returns:
        (analyzed_hops, earliest_reliable_public_origin_ip)
    """
    if not received_headers:
        return [], None

    # Standard MIME order: index 0 is recipient edge gateway, last index is oldest claimed sender
    # Reverse to put in chronological order: index 0 is oldest (hop 1) -> last is edge gateway
    chronological_raw = list(reversed(received_headers))
    hops: List[HopAnalysis] = []

    previous_time: Optional[datetime] = None
    for idx, raw_hdr in enumerate(chronological_raw, start=1):
        hop = parse_received_header(raw_hdr, order=idx)

        # Calculate transit delay from previous hop
        if previous_time and hop.timestamp:
            try:
                diff = (hop.timestamp - previous_time).total_seconds()
                if diff < -300.0:  # Hop claims to arrive > 5 minutes before upstream sent it!
                    hop.clock_skew_detected = True
                    hop.delay_seconds = diff
                    hop.anomaly_reasons.append(
                        f"Clock Skew Anomaly: Recorded timestamp is {abs(diff):.0f}s earlier than upstream hop."
                    )
                else:
                    hop.delay_seconds = max(0.0, diff)
            except Exception:
                hop.delay_seconds = 0.0

        if hop.timestamp:
            previous_time = hop.timestamp

        hops.append(hop)

    # Trust Boundary Validation (Edge Gateway is trusted; verify upward towards sender)
    # The last hop in chronological order is the Recipient Edge Gateway
    if hops:
        hops[-1].node_type = "EDGE_GATEWAY"
        hops[-1].is_reliable = True

    # Inspect from edge gateway backwards to detect where trust breaks
    # Any hop with impossible timestamps (e.g. claims to be hours in the future compared to edge gateway)
    # or lacking both IP and MTA hostname is marked forged.
    for i in range(len(hops) - 1):
        curr_hop = hops[i]
        downstream_hop = hops[i + 1]

        # 1. Temporal impossibility: Hop claims to occur > 1 hour AFTER downstream hop received it
        if curr_hop.timestamp and downstream_hop.timestamp:
            try:
                time_delta = (curr_hop.timestamp - downstream_hop.timestamp).total_seconds()
                if time_delta > 3600:
                    curr_hop.is_reliable = False
                    curr_hop.node_type = "FORGED_OR_UNVERIFIED"
                    curr_hop.anomaly_reasons.append(
                        f"Temporal Anomaly: Hop timestamp claims to occur {time_delta:.0f}s in the future relative to downstream receiver."
                    )
            except (TypeError, ValueError, OverflowError) as exc:
                logger.debug("Failed calculating hop temporal delta: %s", exc)

        # 2. Syntax anomaly: No identifying IP or from_mta hostname
        if not curr_hop.hop_ip and not curr_hop.from_mta:
            curr_hop.is_reliable = False
            curr_hop.node_type = "FORGED_OR_UNVERIFIED"
            curr_hop.anomaly_reasons.append("Syntax Anomaly: Missing both relaying IP address and MTA hostname.")

    # Classify remaining node types
    if hops:
        if hops[0].is_reliable:
            hops[0].node_type = "ORIGINATING"

        for h in hops:
            if h.is_private_ip and h.node_type == "RELAY":
                h.node_type = "INTERNAL"

        for h in hops:
            if h.node_type == "EDGE_GATEWAY":
                h.confidence_score = 1.0
            elif not h.is_reliable or h.node_type == "FORGED_OR_UNVERIFIED":
                h.confidence_score = 0.1
            elif h.clock_skew_detected:
                h.confidence_score = 0.65
            elif h.is_private_ip:
                h.confidence_score = 0.75 if h.is_reliable else 0.3
            else:
                h.confidence_score = 0.95 if (h.hop_ip and h.by_mta) else 0.85

    # Identify the Earliest Reliable Public Originating IP
    # Search in chronological order for the earliest reliable public IP
    earliest_public_ip: Optional[str] = None
    for h in hops:
        if h.hop_ip and not h.is_private_ip and h.is_reliable:
            earliest_public_ip = h.hop_ip
            break

    # If no public IP among reliable hops, search from edge gateway inwards
    if not earliest_public_ip:
        for h in reversed(hops):
            if h.hop_ip and not h.is_private_ip:
                earliest_public_ip = h.hop_ip
                break

    return hops, earliest_public_ip
