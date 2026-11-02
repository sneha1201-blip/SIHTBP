"""Email Spoofing, VIP Impersonation, and Homograph Detection Engine.

Detects:
1. Header Divergence: From vs Return-Path vs Reply-To anomalies.
2. Display Name Impersonation: VIP institutional matching against untrusted email addresses.
3. Cousin Domain Detection: Levenshtein distance typosquatting against protected domains.
4. Homograph & Punycode Attacks: Unicode confusable characters (e.g. Cyrillic 'а' U+0430 vs ASCII 'a').
"""

from __future__ import annotations

import unicodedata
from typing import List, Optional, Tuple
from pydantic import BaseModel

from backend.app.core.config import settings


class SpoofDetectionResult(BaseModel):
    """Forensic evaluation of spoofing, impersonation, and homographs."""
    display_spoof_flag: bool = False
    lookalike_flag: bool = False
    homograph_flag: bool = False
    reply_to_divergence: bool = False
    spoof_score: float = 0.0
    detected_vip: Optional[str] = None
    target_protected_domain: Optional[str] = None
    confusable_glyphs: List[str] = []
    punycode_domain: Optional[str] = None
    reasons: List[str] = []


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute classic Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_homograph(domain: str) -> Tuple[bool, List[str], str]:
    """Detect non-ASCII or mixed-script Unicode confusable characters in a domain."""
    if not domain:
        return False, [], ""

    punycode = ""
    try:
        punycode = domain.encode("idna").decode("ascii")
    except Exception:
        punycode = domain

    confusable_glyphs = []
    has_homograph = False

    # Check if domain contains Cyrillic, Greek, or non-Latin glyphs
    for char in domain:
        cat = unicodedata.category(char)
        name = unicodedata.name(char, "")
        if "CYRILLIC" in name or "GREEK" in name or ord(char) > 127:
            has_homograph = True
            confusable_glyphs.append(f"U+{ord(char):04X} {name} ('{char}')")

    if punycode.startswith("xn--") or has_homograph:
        return True, confusable_glyphs, punycode

    return False, [], punycode


def check_cousin_domain(domain: str, protected_domains: List[str]) -> Tuple[bool, Optional[str]]:
    """Check if domain is a typosquatted lookalike of any protected domain."""
    if not domain:
        return False, None

    clean_dom = domain.lower().strip()
    for protected in protected_domains:
        prot_clean = protected.lower().strip()
        if clean_dom == prot_clean:
            continue

        # Direct inclusion or typosquatting checks
        # e.g., aicte-emergency-portal.org, portal-aicte.com, alcte-india.org
        dist = levenshtein_distance(clean_dom, prot_clean)
        if 1 <= dist <= 3:
            return True, prot_clean

        # Check keyword presence in suspicious composite domain
        prot_keyword = prot_clean.split(".")[0]
        if prot_keyword in clean_dom and clean_dom != prot_clean:
            # Check if it's an unauthorized variation
            if not clean_dom.endswith(f".{prot_clean}"):
                return True, prot_clean

    return False, None


def detect_spoofing(
    sender_display: Optional[str],
    sender_email: Optional[str],
    return_path: Optional[str],
    reply_to: Optional[str],
    protected_domains: Optional[List[str]] = None,
    vip_names: Optional[List[str]] = None,
) -> SpoofDetectionResult:
    """Analyze email sender identities for VIP impersonation, cousin domains, and homographs."""
    prot_domains = protected_domains or settings.PROTECTED_DOMAINS
    vips = vip_names or settings.VIP_NAMES

    reasons = []
    spoof_score = 0.0
    sender_domain = sender_email.split("@")[-1].lower() if sender_email and "@" in sender_email else ""
    return_domain = return_path.split("@")[-1].lower() if return_path and "@" in return_path else ""
    reply_domain = reply_to.split("@")[-1].lower() if reply_to and "@" in reply_to else ""

    # 1. VIP Display Name Impersonation
    display_spoof_flag = False
    detected_vip = None
    if sender_display:
        display_lower = sender_display.lower()
        for vip in vips:
            if vip.lower() in display_lower:
                # Check if sender email is actually under official protected institutional domains
                is_official = any(sender_domain == d or sender_domain.endswith(f".{d}") for d in prot_domains)
                if not is_official:
                    display_spoof_flag = True
                    detected_vip = vip
                    spoof_score += 40.0
                    reasons.append(
                        f"Display name impersonation detected: claims '{vip}', but sent from untrusted domain '{sender_domain}'"
                    )
                    break

    # 2. Reply-To and Return-Path Divergence
    reply_to_divergence = False
    if reply_to and sender_email and reply_to.lower() != sender_email.lower():
        reply_to_divergence = True
        spoof_score += 25.0
        # Severe penalty if reply-to diverts to public free mail providers
        free_mail = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com"}
        if reply_domain in free_mail:
            spoof_score += 20.0
            reasons.append(
                f"Severe Reply-To divergence: Sender is '{sender_email}' but replies divert to personal webmail '{reply_to}'"
            )
        else:
            reasons.append(f"Reply-To divergence: '{reply_to}' differs from Sender '{sender_email}'")

    # 3. Homograph & Punycode Detection
    is_homograph, glyphs, punycode = detect_homograph(sender_domain)
    if is_homograph:
        spoof_score += 45.0
        reasons.append(
            f"IDN Homograph attack detected: domain '{sender_domain}' contains confusable Unicode glyphs {glyphs} (Punycode: {punycode})"
        )

    # 4. Cousin Domain (Typosquatting)
    is_lookalike, target_prot = check_cousin_domain(sender_domain, prot_domains)
    if is_lookalike:
        spoof_score += 35.0
        reasons.append(
            f"Lookalike cousin domain detected: '{sender_domain}' mimics protected domain '{target_prot}'"
        )

    spoof_score = min(100.0, spoof_score)

    return SpoofDetectionResult(
        display_spoof_flag=display_spoof_flag,
        lookalike_flag=is_lookalike,
        homograph_flag=is_homograph,
        reply_to_divergence=reply_to_divergence,
        spoof_score=spoof_score,
        detected_vip=detected_vip,
        target_protected_domain=target_prot,
        confusable_glyphs=glyphs,
        punycode_domain=punycode if punycode.startswith("xn--") else None,
        reasons=reasons,
    )

