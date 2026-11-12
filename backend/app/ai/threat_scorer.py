"""Composite Threat Scoring and Forensic Verdict Engine.

Implements the official SIH 0–100 weighted formula:
Score = min(100, 0.25*Auth + 0.20*Header + 0.20*NLP + 0.15*URL + 0.10*OSINT + 0.10*Attach + CriticalOverrides)
"""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel

from backend.app.ai.nlp_engine import NLPAnalysisResult
from backend.app.ai.url_analyzer import URLAnalysisResult
from backend.app.core.config import settings
from backend.app.forensics.auth_validator import AuthValidationResult
from backend.app.forensics.spoof_detector import SpoofDetectionResult


class CompositeThreatScore(BaseModel):
    """Unified composite forensic score, categorical verdict, and explainability report."""
    threat_score: float
    verdict: str  # BENIGN, SUSPICIOUS, PHISHING, BEC, MALICIOUS, UNCERTAIN
    is_uncertain: bool = False
    score_breakdown: Dict[str, Any]
    reasons: List[str]


def compute_threat_score(
    auth_res: AuthValidationResult,
    spoof_res: SpoofDetectionResult,
    nlp_res: NLPAnalysisResult,
    url_results: List[URLAnalysisResult],
    is_tor_origin: bool = False,
    is_bulletproof_origin: bool = False,
    is_newly_registered_domain: bool = False,
    has_dangerous_attachment: bool = False,
) -> CompositeThreatScore:
    """Compute the weighted 0–100 threat score and assign categorical verdict."""
    reasons: List[str] = []

    # 1. Component Scores
    auth_subscore = auth_res.auth_score
    header_subscore = spoof_res.spoof_score
    nlp_subscore = nlp_res.nlp_score

    # URL subscore: maximum of extracted URL risk scores
    url_subscore = max([u.risk_score for u in url_results], default=0.0)

    # OSINT subscore
    osint_subscore = 0.0
    if is_tor_origin:
        osint_subscore += 60.0
        reasons.append("Originating IP verified as an active Tor Exit Node")
    if is_bulletproof_origin:
        osint_subscore += 40.0
        reasons.append("Originating IP hosted under known bulletproof hosting infrastructure")
    if is_newly_registered_domain:
        osint_subscore += 25.0
        reasons.append("Newly Registered Domain (NRD < 30 days) identified in sender/indicators")
    osint_subscore = min(100.0, osint_subscore)

    # Attachment subscore
    attach_subscore = 80.0 if has_dangerous_attachment else 0.0
    if has_dangerous_attachment:
        reasons.append("Weaponized or macro-enabled attachment extension detected (.xlsm, .exe, .scr)")

    # 2. Weighted Sum
    weighted_score = (
        (settings.WEIGHT_AUTH * auth_subscore)
        + (settings.WEIGHT_HEADER * header_subscore)
        + (settings.WEIGHT_NLP * nlp_subscore)
        + (settings.WEIGHT_URL * url_subscore)
        + (settings.WEIGHT_OSINT * osint_subscore)
        + (settings.WEIGHT_ATTACHMENT * attach_subscore)
    )

    # 3. Critical Overrides (Severe threat scenarios that cannot be diluted)
    critical_override = False
    override_reason = None
    override_score = weighted_score

    # Tor Exit Node override
    if is_tor_origin:
        critical_override = True
        override_score = max(override_score, 98.0)
        override_reason = "CRITICAL OVERRIDE: Tor Exit Node Originating MTA"

    # BEC Executive Wire Fraud override
    if spoof_res.display_spoof_flag and spoof_res.reply_to_divergence and nlp_res.is_bec_financial:
        critical_override = True
        override_score = max(override_score, 94.0)
        override_reason = "CRITICAL OVERRIDE: Executive BEC Wire Fraud (VIP display spoof + personal webmail Reply-To)"

    # Homograph Attack override
    if spoof_res.homograph_flag:
        critical_override = True
        override_score = max(override_score, 88.0)
        override_reason = "CRITICAL OVERRIDE: IDN Cyrillic Homograph Attack against institutional domain"

    # Bulletproof Hosting Campaign cluster override
    if is_bulletproof_origin and (spoof_res.lookalike_flag or nlp_res.is_urgency_coercion):
        critical_override = True
        override_score = max(override_score, 92.0)
        override_reason = "CRITICAL OVERRIDE: Bulletproof Infrastructure Campaign Targeting Institutions"

    # DKIM FAIL + high-risk URL (> 50.0) override -> automatic PHISHING
    if auth_res.dkim_status in ("FAIL", "INVALID", "BODY_HASH_MISMATCH") and url_subscore >= 50.0:
        critical_override = True
        override_score = max(override_score, 86.0)
        override_reason = "CRITICAL OVERRIDE: Cryptographic DKIM Failure paired with High-Risk URL Lure"

    final_score = round(min(100.0, override_score if critical_override else weighted_score), 1)

    # 4. Categorical Verdict & Calibration Uncertainty
    is_uncertain = False
    if not critical_override and 35.0 <= final_score <= 50.0 and nlp_res.confidence < 0.45:
        is_uncertain = True
        verdict = "UNCERTAIN"
        reasons.append("Verdict UNCERTAIN: Intermediate threat score with low model posterior confidence; analyst triage recommended")
    elif spoof_res.display_spoof_flag and nlp_res.is_bec_financial:
        verdict = "BEC"
    elif auth_res.dkim_status in ("FAIL", "INVALID", "BODY_HASH_MISMATCH") and url_subscore >= 50.0:
        verdict = "PHISHING"
    elif is_bulletproof_origin and final_score >= 90.0:
        verdict = "MALICIOUS"
    elif has_dangerous_attachment and final_score >= 80.0:
        verdict = "MALICIOUS"
    elif final_score >= 60.0:
        verdict = "PHISHING"
    elif final_score >= 25.0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    # Collect explainable reasons
    if auth_res.has_discrepancy:
        reasons.extend(auth_res.discrepancies)
    reasons.extend(spoof_res.reasons)
    reasons.extend(nlp_res.reasons)
    if override_reason:
        reasons.insert(0, override_reason)

    score_breakdown = {
        "final_score": final_score,
        "verdict": verdict,
        "weights": {
            "auth": settings.WEIGHT_AUTH,
            "header": settings.WEIGHT_HEADER,
            "nlp": settings.WEIGHT_NLP,
            "url": settings.WEIGHT_URL,
            "osint": settings.WEIGHT_OSINT,
            "attachment": settings.WEIGHT_ATTACHMENT,
        },
        "subscores": {
            "auth": round(auth_subscore, 1),
            "header": round(header_subscore, 1),
            "nlp": round(nlp_subscore, 1),
            "url": round(url_subscore, 1),
            "osint": round(osint_subscore, 1),
            "attachment": round(attach_subscore, 1),
        },
        "critical_override_applied": critical_override,
        "override_reason": override_reason,
        "authentication": {
            "spf_status": auth_res.spf_status,
            "dkim_status": auth_res.dkim_status,
            "dmarc_status": auth_res.dmarc_status,
            "arc_status": auth_res.arc.status,
            "claimed_by_mta": auth_res.claimed_by_mta,
            "recomputed_verdict": auth_res.recomputed_verdict,
            "has_discrepancy": auth_res.has_discrepancy,
            "discrepancies": auth_res.discrepancies,
            "dns_key_snapshots": auth_res.dns_key_snapshots,
        },
    }

    return CompositeThreatScore(
        threat_score=final_score,
        verdict=verdict,
        is_uncertain=is_uncertain,
        score_breakdown=score_breakdown,
        reasons=reasons,
    )

