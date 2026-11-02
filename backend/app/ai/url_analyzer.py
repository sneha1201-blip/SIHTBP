"""URL De-Obfuscation and Threat Scoring Engine.

De-obfuscates hex/octal/dword encoded IP addresses, URL-encoded character bypasses,
identifies credential-harvesting endpoint patterns, and calculates URL risk scores.
"""

from __future__ import annotations

import re
import socket
from urllib.parse import unquote, urlparse
from typing import Dict, List, Optional
from pydantic import BaseModel


class URLAnalysisResult(BaseModel):
    """Detailed forensic analysis of an individual URL."""
    raw_url: str
    normalized_url: str
    domain: str
    is_ip_host: bool = False
    resolved_ip: Optional[str] = None
    has_credential_lure: bool = False
    has_obfuscation: bool = False
    risk_score: float = 0.0
    matched_flags: List[str] = []


CREDENTIAL_KEYWORDS = [
    "login", "signin", "auth", "verify", "verification", "password",
    "credential", "account", "update", "portal", "token", "session",
    "secure", "banking", "wallet", "biometric", "rectification"
]


def deobfuscate_ip_literal(host: str) -> Optional[str]:
    """De-obfuscate DWORD, Hexadecimal, or Octal representations of IP addresses.

    Examples:
        - DWORD: 2130706433 -> 127.0.0.1
        - Hex: 0x7f000001 -> 127.0.0.1
        - Octal: 0177.0000.0000.0001 -> 127.0.0.1
    """
    clean = host.strip()

    # Hex integer: 0x...
    if clean.startswith(("0x", "0X")):
        try:
            val = int(clean, 16)
            return socket.inet_ntoa(val.to_bytes(4, byteorder="big"))
        except Exception:
            pass

    # Pure DWORD integer
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return socket.inet_ntoa(val.to_bytes(4, byteorder="big"))
        except Exception:
            pass

    # Octal dotted notation: e.g. 0177.0.0.1
    if "." in clean and any(part.startswith("0") and len(part) > 1 for part in clean.split(".")):
        try:
            octets = [str(int(p, 8)) for p in clean.split(".")]
            return ".".join(octets)
        except Exception:
            pass

    return None


def analyze_url(url_str: str) -> URLAnalysisResult:
    """Analyze and de-obfuscate a URL for phishing, credential theft, and evasion techniques."""
    flags = []
    risk_score = 0.0

    # 1. Multi-pass URL decoding to detect nested percent-encoding
    decoded = url_str
    passes = 0
    while "%" in decoded and passes < 3:
        new_dec = unquote(decoded)
        if new_dec == decoded:
            break
        decoded = new_dec
        passes += 1

    has_obfuscation = passes > 1
    if has_obfuscation:
        risk_score += 25.0
        flags.append("Nested percent-encoding obfuscation detected")

    # Replace defanged markers
    normalized = decoded.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".")
    parsed = urlparse(normalized)
    host = parsed.netloc.split(":")[0].strip().lower()
    path_query = f"{parsed.path} {parsed.query}".lower()

    # 2. Check for IP address host and de-obfuscation
    is_ip_host = False
    deobf_ip = deobfuscate_ip_literal(host)
    if deobf_ip:
        is_ip_host = True
        has_obfuscation = True
        host = deobf_ip
        risk_score += 40.0
        flags.append(f"De-obfuscated numerical/hex host to IP: {deobf_ip}")
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        is_ip_host = True
        risk_score += 30.0
        flags.append("Direct IP address host used in URL (no valid FQDN)")

    # 3. Credential lure keyword detection
    matched_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in path_query]
    has_cred_lure = len(matched_keywords) > 0
    if has_cred_lure:
        risk_score += 35.0
        flags.append(f"Credential harvesting keywords in path: {matched_keywords[:4]}")

    # 4. Hostile TLDs
    hostile_tlds = [".ru", ".top", ".xyz", ".live", ".work", ".click", ".su"]
    if any(host.endswith(tld) for tld in hostile_tlds):
        risk_score += 30.0
        flags.append(f"High-risk top-level domain: {host.split('.')[-1]}")

    # 5. Punycode check
    if "xn--" in host:
        risk_score += 35.0
        flags.append("Internationalized Domain Name (Punycode xn--) detected in URL")

    # 6. Dangerous executable / macro downloads
    if any(path_query.endswith(ext) for ext in [".exe", ".xlsm", ".docm", ".scr", ".zip", ".iso"]):
        risk_score += 45.0
        flags.append("URL targets executable or macro-enabled weaponized payload")

    risk_score = min(100.0, risk_score)

    return URLAnalysisResult(
        raw_url=url_str,
        normalized_url=normalized,
        domain=host,
        is_ip_host=is_ip_host,
        resolved_ip=deobf_ip if is_ip_host else None,
        has_credential_lure=has_cred_lure,
        has_obfuscation=has_obfuscation,
        risk_score=risk_score,
        matched_flags=flags,
    )

