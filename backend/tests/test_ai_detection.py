"""Comprehensive Test Suite for AI Threat Detection, NLP Classification, and Advanced Spoofing.

Validates:
- Trained TF-IDF + LogisticRegression model pipeline on all 4 threat categories
- Explainable AI token feature attributions (LIME / linear feature weights)
- High-precision entity extraction (IFSC, bank accounts, amounts, deadlines, institutions)
- Unicode confusable homoglyph detection and canonical skeleton resolution
- VIP display name impersonation, Return-Path divergence, and cousin domain detection
- Advanced URL deobfuscation (DWORD/Hex/Octal IP hosts, defanged syntax, nested percent-encoding)
- Formula-driven composite threat scoring and critical overrides
"""

from __future__ import annotations

from backend.app.ai.nlp_engine import (
    analyze_email_content,
    get_or_load_model,
)
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import (
    analyze_url,
    deobfuscate_ip_literal,
    normalize_defanged_url,
)
from backend.app.forensics.auth_validator import AuthValidationResult
from backend.app.forensics.spoof_detector import (
    check_cousin_domain,
    detect_spoofing,
    normalize_confusables,
)

# =====================================================================
# 1. AI/NLP Machine Learning Intent Classification Tests
# =====================================================================

def test_model_pipeline_loaded():
    """Verify trained AI model pipeline is active with expected classes."""
    model = get_or_load_model()
    assert hasattr(model, "predict")
    assert hasattr(model, "predict_proba")
    classes = list(model.classes_)
    assert "BEC_FINANCIAL" in classes
    assert "PHISHING" in classes
    assert "EXTORTION_COERCION" in classes
    assert "BENIGN" in classes


def test_bec_financial_intent_and_entities():
    """Verify classification of executive BEC wire fraud and banking extraction."""
    subject = "Urgent Remittance: Ministry Grant Matching Fee"
    body = (
        "Please execute an emergency wire transfer of Rs. 4,50,000 to our vendor escrow account: "
        "Account: 50200088192411, IFSC: SBIN0000691 via RTGS before close of business today."
    )
    res = analyze_email_content(subject=subject, body=body)

    assert res.predicted_class == "BEC_FINANCIAL"
    assert res.category == "BEC_FINANCIAL"
    assert res.is_bec_financial is True
    assert res.confidence >= 0.50
    assert "SBIN0000691" in res.extracted_entities["ifsc_codes"]
    assert "50200088192411" in res.extracted_entities["bank_accounts"]
    assert any("4,50,000" in amt for amt in res.extracted_entities["amounts"])
    assert len(res.top_contributing_tokens) > 0
    assert res.nlp_score >= 80.0


def test_phishing_credential_harvesting_intent():
    """Verify classification of credential theft lures and token explainability."""
    subject = "Mandatory Security Alert: AICTE SSO Portal Expiration"
    body = (
        "Your institutional educator credentials will expire within 24 hours. "
        "Sign in immediately to verify your identity and confirm multi-factor authentication tokens: "
        "http://aicte-portal-verify.top/sso-login"
    )
    res = analyze_email_content(subject=subject, body=body)

    assert res.predicted_class == "PHISHING"
    assert res.category == "PHISHING"
    assert res.is_credential_lure is True
    assert res.confidence >= 0.60
    assert len(res.top_contributing_tokens) > 0
    # Top tokens should reflect phishing cues
    token_names = [t.token for t in res.top_contributing_tokens]
    assert any(k in token_names for k in ["credentials", "verify", "portal", "login", "sso", "security"])


def test_extortion_coercion_intent():
    """Verify classification of regulatory sanctions and zero-admission threats."""
    subject = "Deficiency Notice: Reduction in Sanctioned Intake"
    body = (
        "Surprise inspection revealed severe non-compliance with faculty-cadre ratios. "
        "Immediate compliance affidavit required before 5:00 PM or approved intake will be reduced by 50% "
        "with immediate zero-admission status."
    )
    res = analyze_email_content(subject=subject, body=body)

    assert res.predicted_class == "EXTORTION_COERCION"
    assert res.category == "EXTORTION_COERCION"
    assert res.is_urgency_coercion is True
    assert res.confidence >= 0.60
    assert res.nlp_score >= 65.0


def test_benign_institutional_communication():
    """Verify benign academic correspondence receives lowest risk score."""
    subject = "ATAL Faculty Development Programme on Quantum Computing"
    body = (
        "AICTE ATAL Academy is organizing a 5-day online workshop for engineering faculty next month. "
        "Registration is open to all AICTE approved institutions without charge."
    )
    res = analyze_email_content(subject=subject, body=body)

    assert res.predicted_class == "BENIGN"
    assert res.category == "BENIGN"
    assert res.confidence >= 0.35
    assert res.nlp_score <= 25.0


def test_unseen_real_world_emails_no_false_positives():
    """Verify routine business emails (invoices, password resets) do not trigger false positives."""
    # 1. Legitimate routine vendor invoice
    res_inv = analyze_email_content(
        subject="Vendor Invoice INV-2026-889 Attached",
        body="Hi Team, Please find attached invoice INV-2026-889 for the annual maintenance contract of campus networking hardware. Total amount due is Rs. 45,000. Kindly process within 30 days as per standard payment terms. Regards, NetTech Solutions.",
    )
    assert res_inv.predicted_class == "BENIGN"
    assert res_inv.category == "BENIGN"
    assert res_inv.is_bec_financial is False
    assert res_inv.nlp_score <= 25.0

    # 2. Legitimate self-service password reset
    res_pwd = analyze_email_content(
        subject="Password Reset Request",
        body="Hello, We received a request to reset your password for your institutional account. Click the link below or enter verification code 829104 to proceed with setting a new password. If you did not make this request, please ignore this email and your account will remain secure.",
    )
    assert res_pwd.predicted_class == "BENIGN"
    assert res_pwd.category == "BENIGN"
    assert res_pwd.is_credential_lure is False
    assert res_pwd.nlp_score <= 25.0

    # 3. Malicious BEC wire fraud
    res_bec = analyze_email_content(
        subject="URGENT: Wire Transfer",
        body="I need you to process an immediate wire transfer of Rs. 8,50,000 to our contractor account. Send the transaction confirmation slip as soon as done. We cannot afford any delay on this project milestone.",
    )
    assert res_bec.predicted_class == "BEC_FINANCIAL"
    assert res_bec.category == "BEC_FINANCIAL"
    assert res_bec.nlp_score >= 70.0

    # 4. Credential phishing quota lure
    res_phish = analyze_email_content(
        subject="Action Required: Your mailbox is full",
        body="Your email storage has exceeded its quota limit. Incoming emails will be blocked. Click here to verify your credentials and increase storage capacity immediately: http://mailbox-quota-helpdesk.online/verify",
    )
    assert res_phish.predicted_class == "PHISHING"
    assert res_phish.category == "PHISHING"
    assert res_phish.nlp_score >= 65.0


# =====================================================================
# 2. Advanced Spoofing & Confusable Homograph Tests
# =====================================================================

def test_confusable_skeleton_normalization():
    """Verify Unicode confusable character translation to ASCII."""
    # Cyrillic 'а' (U+0430) and 'е' (U+0435) and 'о' (U+043E)
    cyrillic_text = "\u0430ict\u0435-indi\u0430.\u043erg"
    ascii_skeleton = normalize_confusables(cyrillic_text)
    assert ascii_skeleton == "aicte-india.org"


def test_targeted_homograph_attack_detection():
    """Verify detection of homograph domains targeting protected institutional entities."""
    # Cyrillic 'а' U+0430 in "аicte-india.org"
    spoofed_domain = "\u0430icte-india.org"
    res = detect_spoofing(
        sender_display="AICTE Compliance Office",
        sender_email=f"compliance@{spoofed_domain}",
        return_path=f"bounce@{spoofed_domain}",
        reply_to=None,
    )
    assert res.homograph_flag is True
    assert res.target_protected_domain == "aicte-india.org"
    assert res.confusable_skeleton == "aicte-india.org"
    assert res.spoof_score >= 50.0
    assert any("Targeted Confusable Homograph" in reason for reason in res.reasons)


def test_vip_display_spoof_and_divergent_reply_to():
    """Verify VIP impersonation matching against external webmail reply-to."""
    res = detect_spoofing(
        sender_display="Prof. T. G. Sitharam (Chairman, AICTE)",
        sender_email="chairman.office@external-untrusted-vps.com",
        return_path="bounce@external-untrusted-vps.com",
        reply_to="executive.desk892@gmail.com",
    )
    assert res.display_spoof_flag is True
    assert res.reply_to_divergence is True
    assert res.detected_vip == "Prof. T. G. Sitharam"
    assert res.spoof_score >= 65.0


def test_cousin_domain_levenshtein():
    """Verify cousin domain detection via edit distance against protected domains."""
    # Typo: alcte-india.org (1 char edit from aicte-india.org)
    is_lookalike, target = check_cousin_domain("alcte-india.org", ["aicte-india.org", "ugc.ac.in"])
    assert is_lookalike is True
    assert target == "aicte-india.org"

    # Exact match is not a lookalike
    is_lookalike_exact, _ = check_cousin_domain("aicte-india.org", ["aicte-india.org"])
    assert is_lookalike_exact is False


# =====================================================================
# 3. URL De-obfuscation & Defanging Tests
# =====================================================================

def test_defanged_url_normalization():
    """Verify normalization of defanged URL schemes and bracketed dots."""
    assert normalize_defanged_url("hxxp://evil[.]com/login") == "http://evil.com/login"
    assert normalize_defanged_url("hxxps://target[.]org[:]8080/path") == "https://target.org:8080/path"
    assert normalize_defanged_url("h**p://auth(.)victim(.)com") == "http://auth.victim.com"


def test_numerical_ip_literal_deobfuscation():
    """Verify conversion of DWORD, Hexadecimal, and Octal host representations."""
    # DWORD representation of 127.0.0.1
    assert deobfuscate_ip_literal("2130706433") == "127.0.0.1"
    # Hex representation of 127.0.0.1
    assert deobfuscate_ip_literal("0x7f000001") == "127.0.0.1"
    # Octal representation of 127.0.0.1
    assert deobfuscate_ip_literal("0177.0.0.1") == "127.0.0.1"


def test_url_analyzer_with_nrd_and_payload():
    """Verify URL risk scoring on credential harvesting path, hostile TLD, and NRD."""
    url_str = "hxxps://verify-portal[.]su/auth/update-credentials.php"
    res = analyze_url(
        url_str,
        custom_domain_age_db={"verify-portal.su": 12},  # 12 days old -> NRD
    )
    assert res.has_credential_lure is True
    assert res.is_newly_registered is True
    assert res.domain_age_days == 12
    assert res.risk_score >= 70.0
    assert any("High-risk top-level domain" in f for f in res.matched_flags)
    assert any("Newly Registered Domain" in f for f in res.matched_flags)


# =====================================================================
# 4. Composite Threat Scorer & Hard Overrides Tests
# =====================================================================

def test_dkim_fail_plus_high_risk_url_hard_override():
    """Verify DKIM FAIL + high-risk URL triggers automatic PHISHING override."""
    # Simulate DKIM failure
    auth_res = AuthValidationResult(
        spf_status="PASS",
        dkim_status="FAIL",
        dmarc_status="PASS",
        auth_score=35.0,
    )
    # Simulate normal benign header and NLP
    spoof_res = detect_spoofing(None, "user@victim.com", "user@victim.com", None)
    nlp_res = analyze_email_content("Meeting Update", "Please find agenda attached.")

    # High-risk phishing URL
    url_res = [analyze_url("http://credential-theft.top/sso-login")]
    assert url_res[0].risk_score >= 60.0

    score_res = compute_threat_score(
        auth_res=auth_res,
        spoof_res=spoof_res,
        nlp_res=nlp_res,
        url_results=url_res,
    )

    # Must be overridden to PHISHING with score >= 85.0
    assert score_res.verdict == "PHISHING"
    assert score_res.threat_score >= 85.0
    assert score_res.score_breakdown["critical_override_applied"] is True
    assert "Cryptographic DKIM Failure paired with High-Risk URL Lure" in score_res.score_breakdown["override_reason"]
    # All 6 subscores must be populated
    subscores = score_res.score_breakdown["subscores"]
    assert "auth" in subscores
    assert "header" in subscores
    assert "nlp" in subscores
    assert "url" in subscores
    assert "osint" in subscores
    assert "attachment" in subscores


def test_tor_origin_hard_override():
    """Verify Tor exit node origin triggers critical 98.0 override."""
    auth_res = AuthValidationResult(spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")
    spoof_res = detect_spoofing(None, "user@victim.com", "user@victim.com", None)
    nlp_res = analyze_email_content("General Inquiry", "Hello, can you send the syllabus?")

    score_res = compute_threat_score(
        auth_res=auth_res,
        spoof_res=spoof_res,
        nlp_res=nlp_res,
        url_results=[],
        is_tor_origin=True,
    )

    assert score_res.threat_score >= 98.0
    assert score_res.score_breakdown["critical_override_applied"] is True
    assert "Tor Exit Node" in score_res.score_breakdown["override_reason"]
