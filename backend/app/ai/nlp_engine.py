"""AI & Machine Learning Forensic Content Classifier for Email Threat Detection.

Replaces heuristic regex with a trained TF-IDF + Logistic Regression classification pipeline:
1. Multi-class Threat Intent Classification:
   - BEC_FINANCIAL (wire fraud, invoice redirection, payment solicitations)
   - PHISHING (credential harvesting, credential theft lures, SSO expiry)
   - EXTORTION_COERCION (intake reduction threats, zero-admission sanctions, regulatory intimidation)
   - BENIGN (authentic academic notices, grant administrative communications, conferences)
2. Explainable Token Attribution (LIME/Linear Feature Weights):
   - Computes token-level importance scores from TF-IDF feature weights and logistic regression coefficients.
3. High-Precision Entity Extraction:
   - Indian banking coordinates (IFSC, 9-18 digit account numbers, SWIFT codes, Rupee amounts)
   - Targeted regulatory institutions & executive bodies
   - Coercive deadline constraints
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
from pydantic import BaseModel, Field

logger = logging.getLogger("nlp_engine")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
STORAGE_DIR = PROJECT_ROOT / "storage"
MODEL_FILE = STORAGE_DIR / "models" / "email_threat_classifier.joblib"

# Lazy-loaded model singleton
_MODEL_PIPELINE: Any = None


def get_or_load_model(reload: bool = False) -> Any:
    """Load the serialized scikit-learn classifier pipeline or train on first run."""
    global _MODEL_PIPELINE
    if _MODEL_PIPELINE is not None and not reload:
        return _MODEL_PIPELINE

    if MODEL_FILE.exists() and not reload:
        try:
            _MODEL_PIPELINE = joblib.load(MODEL_FILE)
            logger.info("Loaded persisted AI threat classifier from %s", MODEL_FILE)
            return _MODEL_PIPELINE
        except Exception as exc:
            logger.warning("Failed to load model from %s (%s); retraining pipeline", MODEL_FILE, exc)

    from backend.app.ai.model_trainer import train_and_evaluate_model

    train_and_evaluate_model()
    _MODEL_PIPELINE = joblib.load(MODEL_FILE)
    return _MODEL_PIPELINE


class TokenAttribution(BaseModel):
    """Explainable AI feature attribution for top contributing tokens."""

    token: str
    weight: float
    intent: str


class NLPAnalysisResult(BaseModel):
    """Forensic evaluation of email textual content and psychological triggers."""

    nlp_score: float = 0.0
    category: str = "BENIGN"  # BEC_FINANCIAL, PHISHING, EXTORTION_COERCION, BENIGN
    predicted_class: str = "BENIGN"
    confidence: float = 0.0
    probabilities: Dict[str, float] = Field(default_factory=dict)
    top_contributing_tokens: List[TokenAttribution] = Field(default_factory=list)
    is_bec_financial: bool = False
    is_urgency_coercion: bool = False
    is_credential_lure: bool = False
    extracted_entities: Dict[str, List[str]] = Field(default_factory=dict)
    matched_phrases: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)


# High-Precision Regex Patterns for Regulatory & Banking Entities
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
ACCOUNT_REGEX = re.compile(
    r"(?:account(?:\s+number)?|a\/c|beneficiary(?:\s+acct)?)\s*[:#-]?\s*([0-9]{9,18})\b",
    re.IGNORECASE,
)
CURRENCY_REGEX = re.compile(
    r"(?:rs\.?|inr|₹|usd|\$)\s*([0-9,]{3,}(?:\s*(?:lakhs?|crores?))?)",
    re.IGNORECASE,
)
SWIFT_REGEX = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")
DEADLINE_REGEX = re.compile(
    r"\b(?:within\s+[0-9]+\s*(?:hours?|days?)|before\s+[0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?|today\s+itself|close\s+of\s+business)\b",
    re.IGNORECASE,
)

INSTITUTIONAL_TARGETS = [
    "AICTE",
    "All India Council for Technical Education",
    "Ministry of Education",
    "UGC",
    "University Grants Commission",
    "National Board of Accreditation",
    "NBA",
    "State Bank of India",
    "SBI",
    "Bank of Baroda",
    "ICICI Bank",
    "Punjab National Bank",
]


def extract_entities_and_cues(text: str) -> Tuple[Dict[str, List[str]], List[str]]:
    """Extract banking coordinates, monetary sums, deadlines, and institutions."""
    entities: Dict[str, List[str]] = {
        "ifsc_codes": [],
        "bank_accounts": [],
        "amounts": [],
        "swift_codes": [],
        "deadlines": [],
        "targeted_institutions": [],
    }

    # IFSC
    for m in IFSC_REGEX.finditer(text):
        val = m.group(0)
        if val not in ("POST000000", "TEXT000000"):
            entities["ifsc_codes"].append(val)

    # Bank Accounts
    for m in ACCOUNT_REGEX.finditer(text):
        entities["bank_accounts"].append(m.group(1))

    # Amounts
    for m in CURRENCY_REGEX.finditer(text):
        entities["amounts"].append(m.group(0).strip())

    # SWIFT
    for m in SWIFT_REGEX.finditer(text):
        val = m.group(0)
        if any(b in text.upper() for b in ["BANK", "WIRE", "REMIT", "SWIFT"]):
            entities["swift_codes"].append(val)

    # Deadlines
    for m in DEADLINE_REGEX.finditer(text):
        entities["deadlines"].append(m.group(0))

    # Targeted Institutions
    text_upper = text.upper()
    for inst in INSTITUTIONAL_TARGETS:
        if inst.upper() in text_upper:
            entities["targeted_institutions"].append(inst)

    cues: List[str] = []
    if entities["ifsc_codes"] or entities["bank_accounts"]:
        cues.append("Banking coordinates present")
    if entities["amounts"]:
        cues.append(f"Monetary solicitation: {', '.join(entities['amounts'][:2])}")
    if entities["deadlines"]:
        cues.append(f"High-pressure deadline: {', '.join(entities['deadlines'][:2])}")

    return entities, cues


def compute_token_attributions(
    pipeline: Any,
    text: str,
    target_class: str,
    top_k: int = 6,
) -> List[TokenAttribution]:
    """Calculate token-level feature attribution using model coefficients and TF-IDF weights."""
    try:
        vectorizer = pipeline.named_steps["tfidf"]
        classifier = pipeline.named_steps["clf"]

        tfidf_vec = vectorizer.transform([text])
        feature_names = vectorizer.get_feature_names_out()

        class_idx = list(classifier.classes_).index(target_class)
        coefs = classifier.coef_[class_idx]

        # Element-wise product of TF-IDF weight and model coefficient
        nz_indices = tfidf_vec.nonzero()[1]
        scores = []
        for idx in nz_indices:
            weight = float(tfidf_vec[0, idx] * coefs[idx])
            scores.append((str(feature_names[idx]), weight))

        # Sort by positive contribution to the predicted class
        scores.sort(key=lambda x: x[1], reverse=True)

        attributions = [
            TokenAttribution(token=token, weight=round(weight, 4), intent=target_class)
            for token, weight in scores[:top_k]
            if weight > 0.01
        ]
        return attributions
    except Exception as exc:
        logger.debug("Failed computing token attribution: %s", exc)
        return []


def analyze_email_content(subject: Optional[str], body: Optional[str]) -> NLPAnalysisResult:
    """Perform multi-class intent classification and entity extraction on email text."""
    full_text = f"{subject or ''} {body or ''}".strip()
    if not full_text:
        return NLPAnalysisResult(
            nlp_score=0.0,
            category="BENIGN",
            predicted_class="BENIGN",
            confidence=1.0,
            probabilities={"BENIGN": 1.0},
        )

    pipeline = get_or_load_model()
    classes = list(pipeline.classes_)

    # 1. Model Prediction & Probabilities
    probs_raw = pipeline.predict_proba([full_text])[0]
    probabilities = {cls: round(float(prob), 4) for cls, prob in zip(classes, probs_raw)}

    pred_class = str(pipeline.predict([full_text])[0])
    confidence = float(probabilities[pred_class])

    prob_benign = float(probabilities.get("BENIGN", 0.0))
    prob_threat = float(1.0 - prob_benign)

    # Low-confidence thresholding: if confidence is below 0.40 and benign probability >= 0.35, default to BENIGN
    if confidence < 0.40 and prob_benign >= 0.35:
        pred_class = "BENIGN"
        confidence = prob_benign

    # 2. Entity Extraction
    extracted_entities, cues = extract_entities_and_cues(full_text)

    # 3. Explainability Token Attributions
    attributions = compute_token_attributions(pipeline, full_text, pred_class)

    # 4. Intent Classification Flags
    has_banking_coords = bool(extracted_entities["ifsc_codes"] or extracted_entities["bank_accounts"])
    has_wire_cues = any("Banking coordinates" in c or "Monetary" in c for c in cues) or any(
        w in full_text.lower() for w in ["wire transfer", "rtgs", "neft", "remittance", "escrow", "beneficiary account"]
    )
    is_bec = (pred_class == "BEC_FINANCIAL") or (
        has_banking_coords and bool(extracted_entities["amounts"]) and has_wire_cues and pred_class != "BENIGN"
    )
    is_cred = pred_class == "PHISHING"
    is_urgency = pred_class == "EXTORTION_COERCION" or len(extracted_entities["deadlines"]) > 0

    reasons: List[str] = []
    if pred_class == "BEC_FINANCIAL":
        reasons.append(
            f"AI Intent: Business Email Compromise / Wire Diversion ({confidence * 100:.1f}% confidence). "
            f"Banking coordinates extracted: IFSC {extracted_entities['ifsc_codes']}, Accounts {extracted_entities['bank_accounts']}"
        )
    elif pred_class == "PHISHING":
        reasons.append(f"AI Intent: Credential Harvesting / Impersonation Lure ({confidence * 100:.1f}% confidence).")
    elif pred_class == "EXTORTION_COERCION":
        reasons.append(
            f"AI Intent: Regulatory Coercion / Administrative Penalty Threat ({confidence * 100:.1f}% confidence). "
            f"High-pressure deadline cues: {extracted_entities['deadlines']}"
        )
    elif pred_class == "BENIGN":
        reasons.append(
            f"AI Intent: Authentic Routine Institutional Correspondence ({confidence * 100:.1f}% confidence)."
        )

    # 5. Calibrated NLP Threat Score (0.0 to 100.0)
    score = 0.0
    if pred_class == "BEC_FINANCIAL":
        score = 55.0 + (confidence * 35.0)
        if has_banking_coords and has_wire_cues:
            score = max(score, 80.0)
    elif pred_class == "PHISHING":
        score = 50.0 + (confidence * 40.0)
    elif pred_class == "EXTORTION_COERCION":
        score = 45.0 + (confidence * 45.0)
    else:  # BENIGN
        score = prob_threat * 25.0

    score = min(100.0, max(0.0, round(score, 1)))

    matched_phrases = [attr.token for attr in attributions] + cues

    return NLPAnalysisResult(
        nlp_score=score,
        category=pred_class,
        predicted_class=pred_class,
        confidence=confidence,
        probabilities=probabilities,
        top_contributing_tokens=attributions,
        is_bec_financial=is_bec,
        is_urgency_coercion=is_urgency,
        is_credential_lure=is_cred,
        extracted_entities=extracted_entities,
        matched_phrases=matched_phrases,
        reasons=reasons,
    )
