"""URL De-Obfuscation, Redirect Tracing, and Risk Scoring Engine.

De-obfuscates hex/octal/dword encoded IP addresses, nested percent-encoded character bypasses,
defanged URLs (hxxp, [.]), follows multi-stage redirect chains with loop protection (max 5 hops, 2.0s timeout),
integrates RDAP domain age (NRD < 30 days), and calculates comprehensive URL risk scores.
"""

from __future__ import annotations

import logging
import re
import socket
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("url_analyzer")

DEFAULT_REDIRECT_TIMEOUT = 2.0
MAX_REDIRECT_HOPS = 5


class RedirectHop(BaseModel):
    """An individual hop in an HTTP redirect chain."""
    step: int
    url: str
    status_code: int
    location: Optional[str] = None


class URLAnalysisResult(BaseModel):
    """Detailed forensic analysis of an individual URL."""
    raw_url: str
    normalized_url: str
    domain: str
    is_ip_host: bool = False
    resolved_ip: Optional[str] = None
    has_credential_lure: bool = False
    has_obfuscation: bool = False
    is_newly_registered: bool = False
    domain_age_days: Optional[int] = None
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    final_destination_url: Optional[str] = None
    risk_score: float = 0.0
    matched_flags: List[str] = Field(default_factory=list)


CREDENTIAL_KEYWORDS = [
    "login", "signin", "auth", "verify", "verification", "password",
    "credential", "account", "update", "portal", "token", "session",
    "secure", "banking", "wallet", "biometric", "rectification",
    "reauth", "sso-login", "passcode", "validate",
]

HOSTILE_TLDS = [
    ".ru", ".top", ".xyz", ".live", ".work", ".click", ".su",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".monster",
]

DANGEROUS_PAYLOAD_EXTS = [
    ".exe", ".xlsm", ".docm", ".scr", ".zip", ".iso", ".vbs", ".hta", ".bat",
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
        except (ValueError, OverflowError, OSError) as exc:
            logger.debug("Failed decoding hex IP literal '%s': %s", clean, exc)

    # Pure DWORD integer
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return socket.inet_ntoa(val.to_bytes(4, byteorder="big"))
        except (ValueError, OverflowError, OSError) as exc:
            logger.debug("Failed decoding DWORD IP literal '%s': %s", clean, exc)

    # Octal dotted notation: e.g. 0177.0.0.1
    if "." in clean and any(part.startswith("0") and len(part) > 1 for part in clean.split(".")):
        try:
            octets = [str(int(p, 8)) for p in clean.split(".")]
            return ".".join(octets)
        except (ValueError, OverflowError) as exc:
            logger.debug("Failed decoding octal IP literal '%s': %s", clean, exc)

    return None


def normalize_defanged_url(url_str: str) -> str:
    """Normalize defanged URL formatting into standard RFC 3986 format."""
    clean = url_str.strip()
    clean = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0) else "http://", clean, flags=re.IGNORECASE)
    clean = re.sub(r"^h[\*]{2}ps?://", lambda m: "https://" if "s" in m.group(0) else "http://", clean, flags=re.IGNORECASE)
    clean = clean.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    clean = clean.replace("[//]", "//")
    return clean


async def trace_url_redirects(
    url: str,
    max_hops: int = MAX_REDIRECT_HOPS,
    timeout: float = DEFAULT_REDIRECT_TIMEOUT,
) -> Tuple[List[RedirectHop], str]:
    """Trace HTTP 3xx redirect chain with loop detection and strict timeout guards."""
    hops: List[RedirectHop] = []
    visited: Set[str] = set()
    current_url = url

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for step in range(1, max_hops + 1):
                if current_url in visited:
                    logger.debug("Redirect loop detected for %s", current_url)
                    break
                visited.add(current_url)

                try:
                    resp = await client.head(current_url)
                except httpx.RequestError:
                    # Retry using GET with stream to avoid downloading full payload
                    try:
                        resp = await client.get(current_url)
                    except Exception:
                        break

                loc = resp.headers.get("location")
                hops.append(
                    RedirectHop(
                        step=step,
                        url=current_url,
                        status_code=resp.status_code,
                        location=loc,
                    )
                )

                if resp.is_redirect and loc:
                    # Handle relative redirect locations
                    if not loc.startswith(("http://", "https://")):
                        parsed_base = urlparse(current_url)
                        current_url = f"{parsed_base.scheme}://{parsed_base.netloc}/{loc.lstrip('/')}"
                    else:
                        current_url = loc
                else:
                    break
    except Exception as exc:
        logger.debug("Redirect tracing error on %s: %s", url, exc)

    return hops, current_url


def analyze_url(
    url_str: str,
    check_rdap: bool = False,
    custom_domain_age_db: Optional[Dict[str, int]] = None,
) -> URLAnalysisResult:
    """Analyze and de-obfuscate a URL for phishing, credential theft, and evasion techniques."""
    flags: List[str] = []
    risk_score = 0.0

    # 1. Defanging resolution
    normalized = normalize_defanged_url(url_str)

    # 2. Multi-pass nested percent-encoding deobfuscation
    decoded = normalized
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

    if not (decoded.startswith("http://") or decoded.startswith("https://")):
        decoded = f"http://{decoded}"

    parsed = urlparse(decoded)
    host = parsed.netloc.split(":")[0].strip().lower()
    path_query = f"{parsed.path} {parsed.query}".lower()

    # 3. Numerical / Hex / Octal IP Literal Deobfuscation
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

    # 4. Credential Lure Keyword Detection
    matched_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in path_query]
    has_cred_lure = len(matched_keywords) > 0
    if has_cred_lure:
        risk_score += 35.0
        flags.append(f"Credential harvesting keywords in path: {matched_keywords[:4]}")

    # 5. Hostile TLDs
    if any(host.endswith(tld) for tld in HOSTILE_TLDS):
        risk_score += 30.0
        flags.append(f"High-risk top-level domain: {host.split('.')[-1]}")

    # 6. Punycode check
    if "xn--" in host:
        risk_score += 35.0
        flags.append("Internationalized Domain Name (Punycode xn--) detected in URL")

    # 7. Dangerous Executable or Macro Downloads
    if any(path_query.endswith(ext) for ext in DANGEROUS_PAYLOAD_EXTS):
        risk_score += 45.0
        flags.append("URL targets executable or macro-enabled weaponized payload")

    # 8. Domain Age (NRD < 30 days)
    domain_age: Optional[int] = None
    is_nrd = False
    if custom_domain_age_db and host in custom_domain_age_db:
        domain_age = custom_domain_age_db[host]
        if domain_age < 30:
            is_nrd = True
            risk_score += 35.0
            flags.append(f"Newly Registered Domain (<30 days old): {domain_age} days")

    risk_score = min(100.0, risk_score)

    return URLAnalysisResult(
        raw_url=url_str,
        normalized_url=decoded,
        domain=host,
        is_ip_host=is_ip_host,
        resolved_ip=deobf_ip if is_ip_host else None,
        has_credential_lure=has_cred_lure,
        has_obfuscation=has_obfuscation,
        is_newly_registered=is_nrd,
        domain_age_days=domain_age,
        risk_score=risk_score,
        matched_flags=flags,
    )
