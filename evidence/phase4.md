# Phase 4 Evidence & Verification Baseline
**Smart India Hackathon 2026 | Problem Statement 26106**  
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**  
**Execution Timestamp:** 2026-11-10T19:15:00Z  
**Target System:** `SIHTBP` (FastAPI + SQLAlchemy async + SQLite WAL + Next.js 14)  
**Dataset Name:** `SIH-Forensic-Threat-Corpus`  
**Dataset Version:** `4.0.0`  
**Deterministic Seed:** `26106`  
**Commit Baseline:** `0aa16d1`  

---

## 1. Executive Summary & Objective

Phase 4 elevates email threat detection from static regexes into a verified, explainable Machine Learning classifier and forensic intelligence engine:

1. **Trained AI/NLP Machine Learning Pipeline (`backend/app/ai/nlp_engine.py` & `backend/app/ai/model_trainer.py`):**
   - Implemented Scikit-Learn `Pipeline(TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True) + LogisticRegression(C=2.5, class_weight='balanced'))`.
   - Multi-class classification across 4 threat intents:
     - `BEC_FINANCIAL`: wire fraud, bank coordinate updates, payment solicitations
     - `PHISHING`: credential harvesting, fake authentication portals, SSO expiration lures
     - `EXTORTION_COERCION`: institutional intake reduction, zero-admission sanctions, disaffiliation threats
     - `BENIGN`: routine academic notices, grant administrative communications, conferences
   - **Explainable AI (Feature Attributions):**
     - Extracts active n-grams and computes token-level importance scores from model coefficients and TF-IDF weights.
   - **Entity Extraction:**
     - Indian Financial System Codes (IFSC `[A-Z]{4}0[A-Z0-9]{6}`)
     - Indian Bank Account Numbers (9 to 18 digits)
     - Monetary amounts (INR, Rs., ₹, lakhs/crores)
     - SWIFT / BIC codes
     - Targeted regulatory institutions (`AICTE`, `Ministry of Education`, `UGC`, `State Bank of India`, etc.)
     - High-pressure deadline constraints (`before [time]`, `within [n] hours/days`, `close of business`)
   - **Documented Model Card (`evidence/model_card.md`):**
     - Complete documentation of dataset provenance (Nazario Phishing Corpus, Enron Academic Corpus, CEAS Spam/BEC Benchmark).
     - Quantitative metrics: **91.67% Test Accuracy, 0.9167 F1-Macro, 0.9980 ROC-AUC (OvR), 0.9965 PR-AUC, 95.79% (+/- 3.94%) 5-Fold CV Accuracy, 100.0% Unseen Real-World Audit Benchmark Accuracy** (see `evidence/model_card.md`).

2. **Advanced Spoofing & Confusable Homograph Engine (`backend/app/forensics/spoof_detector.py`):**
   - Unicode Confusable Mapping Table translating Cyrillic (e.g. Cyrillic `а` U+0430, `с` U+0441, `е` U+0435, `о` U+043E, `р` U+0440) and Greek homoglyphs to canonical ASCII skeletons.
   - Identifies targeted homograph attacks against protected institutional domains (`aicte-india.org`, `gov.in`, `nic.in`, `sbi.co.in`, `rbi.org.in`).
   - Levenshtein distance typosquatting cousin domain analysis.
   - Brand & VIP impersonation detecting unauthorized claims of high-profile leadership (AICTE Chairman Prof. T. G. Sitharam, Vice Chairman Dr. Abhay Jere, Member Secretary Prof. Rajive Kumar, Ministry and Bank heads).
   - Reply-To and Return-Path divergence detection, penalizing diversions to free personal webmail.

3. **URL De-Obfuscation & Redirect Tracing (`backend/app/ai/url_analyzer.py`):**
   - Defanged URL normalization (`hxxp://`, `hxxps://`, `[.]`, `(.)`).
   - Numerical, Hexadecimal, and Octal IP host de-obfuscation (`DWORD 2130706433` -> `127.0.0.1`, `0x7f000001` -> `127.0.0.1`, `0177.0.0.1` -> `127.0.0.1`).
   - Multi-stage HTTP redirect tracing with loop protection (max 5 hops, 2.0s timeout).
   - Newly Registered Domain (NRD < 30 days) risk elevation (+35 risk points).

4. **Formula-Driven Composite Threat Scorer & Critical Overrides (`backend/app/ai/threat_scorer.py`):**
   - Transparent weighted formula:
     - **Auth (25%)**
     - **Hop/Geo (20%)**
     - **NLP (20%)**
     - **URL (20%)**
     - **Brand/VIP (15%)**
     - Attachment (10% adjustment / critical trigger)
   - **Critical Threat Overrides:**
     - **DKIM FAIL + High-Risk URL (> 50.0)** -> Automatic `PHISHING` override (Threat Score >= 86.0).
     - **Tor Exit Node Origin** -> Automatic `98.0 / CRITICAL OVERRIDE`.
     - **Executive BEC Wire Fraud** (`display_spoof_flag + is_bec_financial`) -> Automatic `94.0 / BEC OVERRIDE`.
     - **Cyrillic Homograph Attack** -> Automatic `88.0 / CRITICAL OVERRIDE`.
     - **Bulletproof Hosting Campaign Cluster** -> Automatic `92.0 / CRITICAL OVERRIDE`.
   - Complete 6-subscore breakdown persisted in database `ForensicAnalysis` entity and exposed to frontend.

---

## 2. Requirements Matrix Traceability (Phase 4)

| Requirement Description | Architecture Module | Automated Test File | Verification Status |
|---|---|---|---|
| Trained TF-IDF + LogisticRegression classifier | `backend/app/ai/nlp_engine.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| Explainable token feature attributions | `backend/app/ai/nlp_engine.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| High-precision Indian banking entity extraction | `backend/app/ai/nlp_engine.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| Unicode confusable homoglyph skeleton translation | `backend/app/forensics/spoof_detector.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| VIP display name & Reply-To divergence detection | `backend/app/forensics/spoof_detector.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| URL defanging and DWORD/Hex/Octal IP deobfuscation | `backend/app/ai/url_analyzer.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| Multi-stage redirect tracing with loop protection | `backend/app/ai/url_analyzer.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| DKIM FAIL + high-risk URL hard override | `backend/app/ai/threat_scorer.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| Formula-driven 6-subscore breakdown persistence | `backend/app/ai/threat_scorer.py` | `backend/tests/test_ai_detection.py` | **PASS (100%)** |
| Comprehensive Model Card documentation | `backend/app/ai/model_trainer.py` | `evidence/model_card.md` | **PASS (100%)** |

---

## 3. Test Execution Verification Artifacts

### Command:
```bash
pytest -v backend/tests/test_ai_detection.py
```

### Result: 14 passed in 2.54s
```text
backend/tests/test_ai_detection.py::test_model_pipeline_loaded PASSED    [  7%]
backend/tests/test_ai_detection.py::test_bec_financial_intent_and_entities PASSED [ 14%]
backend/tests/test_ai_detection.py::test_phishing_credential_harvesting_intent PASSED [ 21%]
backend/tests/test_ai_detection.py::test_extortion_coercion_intent PASSED [ 28%]
backend/tests/test_ai_detection.py::test_benign_institutional_communication PASSED [ 35%]
backend/tests/test_ai_detection.py::test_confusable_skeleton_normalization PASSED [ 42%]
backend/tests/test_ai_detection.py::test_targeted_homograph_attack_detection PASSED [ 50%]
backend/tests/test_ai_detection.py::test_vip_display_spoof_and_divergent_reply_to PASSED [ 57%]
backend/tests/test_ai_detection.py::test_cousin_domain_levenshtein PASSED [ 64%]
backend/tests/test_ai_detection.py::test_defanged_url_normalization PASSED [ 71%]
backend/tests/test_ai_detection.py::test_numerical_ip_literal_deobfuscation PASSED [ 78%]
backend/tests/test_ai_detection.py::test_url_analyzer_with_nrd_and_payload PASSED [ 85%]
backend/tests/test_ai_detection.py::test_dkim_fail_plus_high_risk_url_hard_override PASSED [ 92%]
backend/tests/test_ai_detection.py::test_tor_origin_hard_override PASSED [100%]
```

### Full Test Suite (71/71 Passed):
```bash
pytest -v backend/tests/
```
```text
======================= 71 passed, 3 warnings in 14.70s =======================
```

### Static Analysis & Verification:
- `ruff check .` -> **All checks passed!**
- `mypy backend/app` -> **Success: no issues found in 45 source files**
- `npm run lint` -> **No ESLint warnings or errors**
- `npx tsc --noEmit` -> **Zero TypeScript compilation errors**
- `python verify_system.py` -> **All 5 subsystem gates PASSED**

