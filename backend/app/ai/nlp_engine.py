"""AI & NLP Forensic Content Classifier for Email Threat Detection.

Detects:
1. Wire / Payment Diversion: Bank Account, IFSC, SWIFT codes, RTGS/NEFT wire solicitations.
2. Artificial Urgency & Psychological Coercion: Deadlines, intake freeze, zero-admission threats.
3. Credential Harvesting Lures: SSO expiration, password validation, biometric renewal.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from pydantic import BaseModel


class NLPAnalysisResult(BaseModel):
    """Forensic evaluation of email textual content and psychological triggers."""
    nlp_score: float = 0.0
    category: str = "BENIGN"  # BEC_FINANCIAL, CREDENTIAL_LURE, EXTORTION_COERCION, BENIGN
    is_bec_financial: bool = False
    is_urgency_coercion: bool = False
    is_credential_lure: bool = False
    extracted_entities: Dict[str, List[str]] = {}
    matched_phrases: List[str] = []
    reasons: List[str] = []


# Indian Financial System Code (IFSC): 4 letters, '0', 6 alphanumeric
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
# Indian Bank Account Number: 9 to 18 digits preceded by account context
ACCOUNT_REGEX = re.compile(r"(?:account(?:\s+number)?|a\/c|beneficiary(?:\s+acct)?)\s*[:#-]?\s*([0-9]{9,18})\b", re.IGNORECASE)
# Indian Rupee monetary values (Rs., INR, ₹)
CURRENCY_REGEX = re.compile(r"(?:rs\.?|inr|₹)\s*([0-9,]{4,}(?:\s*(?:lakhs?|crores?))?)", re.IGNORECASE)
# SWIFT / BIC codes
SWIFT_REGEX = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")

# Coercion and Urgency Lexicon
URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "before 4:00 pm", "before 5:00 pm",
    "today itself", "confidential & high priority", "immediate action required",
    "final deadline", "strictly confidential", "without delay", "time-sensitive"
]

COERCION_PENALTY_KEYWORDS = [
    "suspension of approval", "zero-admission", "reduction in sanctioned intake",
    "freezing of your aicte", "deficiency notice", "severe non-compliance",
    "legal penalty", "disaffiliation", "cancellation of intake"
]

FINANCIAL_BEC_KEYWORDS = [
    "rtgs", "neft", "wire transfer", "remittance", "escrow account",
    "commitment fee", "grant allocation", "matching grant", "treasury reconciliation",
    "disbursement", "beneficiary account", "advance payment"
]

CREDENTIAL_LURE_KEYWORDS = [
    "password expired", "verify credentials", "biometric re-validation",
    "confirm your credentials", "re-authenticate", "sso account",
    "login immediately", "portal credentials", "session timeout"
]


def analyze_email_content(subject: Optional[str], body: Optional[str]) -> NLPAnalysisResult:
    """Analyze subject and body text for BEC fraud, coercion, and phishing lures."""
    full_text = f"{subject or ''} {body or ''}"
    lower_text = full_text.lower()

    extracted_entities: Dict[str, List[str]] = {
        "ifsc_codes": [],
        "bank_accounts": [],
        "amounts": [],
        "swift_codes": [],
    }
    matched_phrases = []
    reasons = []

    # 1. Financial Entity Extraction
    for match in IFSC_REGEX.finditer(full_text):
        code = match.group(0)
        # Avoid common English false-positive words that might match
        if code not in ("POST000000", "TEXT000000"):
            extracted_entities["ifsc_codes"].append(code)

    for match in ACCOUNT_REGEX.finditer(full_text):
        extracted_entities["bank_accounts"].append(match.group(1))

    for match in CURRENCY_REGEX.finditer(full_text):
        extracted_entities["amounts"].append(match.group(0).strip())

    # 2. Wire & Payment Diversion Classification
    is_bec = False
    financial_hits = [kw for kw in FINANCIAL_BEC_KEYWORDS if kw in lower_text]
    if (extracted_entities["ifsc_codes"] or extracted_entities["bank_accounts"] or extracted_entities["amounts"]) and financial_hits:
        is_bec = True
        matched_phrases.extend(financial_hits)
        reasons.append(
            f"BEC Financial Diversion Detected: Requests wire transfer/remittance with bank coordinates {extracted_entities}"
        )

    # 3. Urgency & Coercion Classification
    is_urgency = False
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in lower_text]
    coercion_hits = [kw for kw in COERCION_PENALTY_KEYWORDS if kw in lower_text]
    if urgency_hits or coercion_hits:
        is_urgency = True
        matched_phrases.extend(urgency_hits + coercion_hits)
        if coercion_hits:
            reasons.append(f"Institutional Coercion Tactics: Threatens administrative penalties {coercion_hits}")
        if urgency_hits:
            reasons.append(f"Artificial Urgency Phrasing: High-pressure time constraints {urgency_hits}")

    # 4. Credential Theft Lures
    is_cred = False
    cred_hits = [kw for kw in CREDENTIAL_LURE_KEYWORDS if kw in lower_text]
    if cred_hits:
        is_cred = True
        matched_phrases.extend(cred_hits)
        reasons.append(f"Credential Harvesting Lures Detected: Requests authentication renewal {cred_hits}")

    # 5. Calculate NLP Threat Score
    score = 0.0
    if is_bec:
        score += 55.0
    if is_cred:
        score += 50.0
    if is_urgency:
        score += 25.0
    if coercion_hits:
        score += 20.0

    score = min(100.0, score)

    # Primary Category Determination
    if is_bec:
        category = "BEC_FINANCIAL"
    elif is_cred:
        category = "CREDENTIAL_LURE"
    elif is_urgency and coercion_hits:
        category = "EXTORTION_COERCION"
    elif score > 20.0:
        category = "SUSPICIOUS_CONTENT"
    else:
        category = "BENIGN"

    return NLPAnalysisResult(
        nlp_score=score,
        category=category,
        is_bec_financial=is_bec,
        is_urgency_coercion=is_urgency,
        is_credential_lure=is_cred,
        extracted_entities=extracted_entities,
        matched_phrases=list(set(matched_phrases)),
        reasons=reasons,
    )

