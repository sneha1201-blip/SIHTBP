# Forensic Model Card: Calibrated Multi-Class Email Threat Classifier
**Smart India Hackathon 2026 | Problem Statement 26106**
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**
**Execution Timestamp:** 2026-11-13T01:21:30.806661+00:00
**Model Architecture:** `TfidfVectorizer(max_features=5000, ngram=(1,2)) + CalibratedClassifierCV(LogisticRegression, method='sigmoid', cv=5)`
**Deterministic Seed:** `26106`
**Dataset Provenance:** Curated multi-source forensic corpus (Apache SpamAssassin easy_ham/hard_ham/spam, Jose Nazario Phishing Corpus, Enron Ham Slice, and Institutional Cyber Security Telemetry) deduplicated via 64-bit SimHash.
**Total Corpus Samples:** 2872 (Train: 2297, Holdout Test: 575)

---

## 1. Quantitative Evaluation Metrics (Stratified Holdout Test Set)

| Evaluation Metric | Score | Verification Status |
|---|---|---|
| **Holdout Test Accuracy** | **94.26%** | **VERIFIED (Empirical on Real Corpora)** |
| **Precision (Macro)** | **0.9119** | **VERIFIED** |
| **Recall (Macro)** | **0.7060** | **VERIFIED** |
| **F1-Score (Macro)** | **0.7731** | **VERIFIED** |
| **F1-Score (Weighted)** | **0.9382** | **VERIFIED** |
| **ROC-AUC (One-vs-Rest Macro)** | **0.9660** | **VERIFIED** |
| **PR-AUC (Average Precision Macro)** | **0.8239** | **VERIFIED** |
| **False Positive Rate @ 95% Recall** | **6.62%** | **VERIFIED** |
| **Expected Calibration Error (ECE)** | **0.0334 (95% CI: [0.0269, 0.0528])** | **VERIFIED (1,000 Bootstrap Resamples)** |

---

## 2. Confusion Matrix: Ground Truth vs Prediction (Holdout Set)

| True \ Pred | BEC_FINANCIAL | BENIGN | EXTORTION_COERCION | PHISHING |
|---|---|---|---|---|
| **BEC_FINANCIAL** | 6 | 1 | 0 | 2 |
| **BENIGN** | 0 | 433 | 1 | 4 |
| **EXTORTION_COERCION** | 0 | 3 | 4 | 6 |
| **PHISHING** | 0 | 16 | 0 | 99 |


---

## 3. Per-Class Precision, Recall & F1 Breakdown

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| `BEC_FINANCIAL` | 1.000 | 0.667 | 0.800 | 9 |
| `BENIGN` | 0.956 | 0.989 | 0.972 | 438 |
| `EXTORTION_COERCION` | 0.800 | 0.308 | 0.444 | 13 |
| `PHISHING` | 0.892 | 0.861 | 0.876 | 115 |


---

## 4. Explainability: Top Predictive Token Attributions
- **`BEC_FINANCIAL`**: `ifsc`, `wire`, `rs`, `000`, `account`, `transfer`, `beneficiary`, `urgent`
- **`BENIGN`**: `enron`, `2002`, `vince`, `wrote`, `thanks`, `fork`, `2000`, `kaminski`
- **`EXTORTION_COERCION`**: `hours`, `48`, `immediate`, `faculty`, `notice`, `final`, `police`, `databases`
- **`PHISHING`**: `http`, `remove`, `security`, `verify`, `click`, `update`, `paypal`, `font`


---

## 5. Reproduction Command
To retrain and reproduce this exact model artifact and metric evaluation:
```bash
python -m backend.app.ai.model_trainer
```

---

## 6. Composite Threat Architecture: 4-Class NLP Model to 5-Class Forensic Verdict Mapping

### 6.1 Architectural Principle
The machine learning pipeline is **not an uncalibrated end-to-end black box**. In high-stakes cyber forensic investigations governed by Section 63 Bharatiya Sakshya Adhiniyam (BSA), 2023, judicial admissibility mandates explainable provenance, deterministic reproducibility, and cryptographic certitude rather than opaque latent-space inference.

Accordingly, the system implements a **two-tier architecture**:
1. **Tier 1 (Probabilistic Semantic Intent Classification):**
   The NLP model (`storage/models/email_threat_classifier.joblib`) is trained and Platt-calibrated via 5-fold cross-validation on 4 linguistic classes:
   - `BENIGN`: Legitimate corporate and institutional correspondence.
   - `PHISHING`: Credential harvesting, urgent login verification, and fake brand lures.
   - `BEC_FINANCIAL`: Business Email Compromise, invoice redirection, wire fraud, and beneficiary tampering.
   - `EXTORTION_COERCION`: Blackmail, regulatory intimidation, subpoena threats, and cryptocurrency coercion.
   The model outputs calibrated posterior probabilities with low Expected Calibration Error ($ECE = 0.0334$, 95% CI: $[0.0269, 0.0528]$) and explicit token attributions.

2. **Tier 2 (Deterministic Forensic Synthesis & PS 26106 5-Class Verdict Mapping):**
   The runtime engine (`backend/app/ai/threat_scorer.py`) applies deterministic, court-auditable decision rules combining:
   - **Protocol Authentication (25%):** Cryptographic SPF, DKIM (RSA-SHA256), and DMARC alignment.
   - **Header Spoof Matrix (20%):** Display name impersonation, Cyrillic IDN homoglyphs, and envelope divergence.
   - **Calibrated NLP Subscore (20%):** Tier 1 semantic intent score and confidence.
   - **URL Reputation & Redirects (15%):** Multi-hop unshortening, brand lookalike domains, and SSRF filtering.
   - **OSINT & Threat Telemetry (10%):** Tor exit node detection, bulletproof ASNs, and Newly Registered Domains (NRDs).
   - **Weaponized Attachments (10%):** Macro-enabled Office files (.xlsm), double extensions, and archive bombs.

### 6.2 PS 26106 5-Class Verdict Decision Rules
The official SIH Problem Statement 26106 categorical verdicts map deterministically from composite score and forensic indicators:

| PS 26106 Verdict | Internal Verdict | Trigger Conditions & Decision Rules | Court Admissibility Basis |
|---|---|---|---|
| **legitimate** | `BENIGN` | Composite Score $< 25.0$, SPF=PASS, DKIM=PASS, DMARC=PASS, zero homoglyph or display spoof flags, no dangerous attachments. | Verified cryptographic origin and benign NLP intent. |
| **suspicious** | `SUSPICIOUS` | Composite Score $\ge 25.0$ and $< 60.0$, or single protocol failure (e.g. SPF SoftFail or newly registered domain $< 30$ days) without overt fraud intent. | Anomaly detected warranting secondary SOC inspection. |
| **impersonated** | `BEC` | Executive display spoof detected (`spoof_res.display_spoof_flag == True`) paired with personal webmail Reply-To diversion and/or financial wire intent (`nlp_res.is_bec_financial == True`). Critical override sets score $\ge 94.0$. | Intentional identity masquerade targeting institutional finance. |
| **phishing** | `PHISHING` | Composite Score $\ge 60.0$, or Cryptographic DKIM Failure (`FAIL`/`INVALID`/`BODY_HASH_MISMATCH`) paired with High-Risk URL Lure ($\ge 50.0$), or verified brand lookalike targeting protected institutions. | Deceptive credential harvesting or domain impersonation. |
| **fraud-related** | `MALICIOUS` | Bulletproof infrastructure origin ($\text{Score} \ge 90.0$), Weaponized macro attachments ($\text{Score} \ge 80.0$), or Originating MTA verified as an active Tor Exit Node (Critical override $\ge 98.0$). | Malicious operational infrastructure executing targeted cyber fraud. |
| **uncertain** | `UNCERTAIN` | Composite Score $35.0 \le \text{Score} \le 50.0$ and NLP model posterior confidence $< 0.45$. | Conservative safety mechanism flagging borderline cases for mandatory human triage. |

