# Forensic Model Card: Multi-Class Email Threat Classifier
**Smart India Hackathon 2026 | Problem Statement 26106**
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**
**Execution Timestamp:** 2026-11-12T03:31:06.822257+00:00
**Model Architecture:** Pipeline(TfidfVectorizer(ngram=(1,2), sublinear_tf=True, max_features=3000) + LogisticRegression(C=2.0, class_weight='balanced'))
**Deterministic Seed:** `26106`
**Dataset Provenance:** Curated multi-source forensic corpus (Nazario Phishing Corpus, Enron Academic Corpus, CEAS Spam/BEC Benchmark, and Institutional Cyber Security Telemetry)
**Total Corpus Samples:** 120 (Train: 96, Holdout Test: 24)

---

## 1. Intended Use & Forensic Scope
- **Primary Domain:** Automated triage and forensic intent classification for suspected institutional spear phishing, business email compromise (BEC wire fraud), credential lures, and regulatory extortion.
- **Explainability:** Model outputs per-class posterior probabilities and linear feature weight attributions for token-level highlight visualization in the analyst UI.
- **Section 63 BSA 2023 Compliance:** Deterministic, reproducible pipeline with frozen weights, explicit seed, and documented empirical metrics.
- **Zero-Hyping Policy:** Eliminates previous overfitted "100% accuracy" claims. All metrics are derived from stratified holdout testing and out-of-distribution evaluation.

---

## 2. Quantitative Evaluation Metrics (Stratified Holdout Test Set)

| Evaluation Metric | Score | Verification Status |
|---|---|---|
| **Holdout Test Accuracy** | **91.67%** | **VERIFIED** |
| **Precision (Macro)** | **0.9500** | **VERIFIED** |
| **Recall (Macro)** | **0.9000** | **VERIFIED** |
| **F1-Score (Macro)** | **0.9167** | **VERIFIED** |
| **F1-Score (Weighted)** | **0.9167** | **VERIFIED** |
| **ROC-AUC (One-vs-Rest Macro)** | **0.9980** | **VERIFIED** |
| **PR-AUC (Average Precision Macro)** | **0.9965** | **VERIFIED** |
| **False Positive Rate @ 95% Recall** | **12.50%** | **VERIFIED** |
| **5-Fold Stratified CV Accuracy** | **95.79% (+/- 3.94%)** | **VERIFIED** |

---

## 3. Confusion Matrix: Ground Truth vs Prediction (Holdout Set)

| True \ Pred | BEC_FINANCIAL | BENIGN | EXTORTION_COERCION | PHISHING |
|---|---|---|---|---|
| **BEC_FINANCIAL** | 4 | 1 | 0 | 0 |
| **BENIGN** | 0 | 8 | 0 | 0 |
| **EXTORTION_COERCION** | 0 | 1 | 4 | 0 |
| **PHISHING** | 0 | 0 | 0 | 6 |


---

## 4. Per-Class Precision, Recall & F1 Breakdown

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| `BEC_FINANCIAL` | 1.000 | 0.800 | 0.889 | 5 |
| `BENIGN` | 0.800 | 1.000 | 0.889 | 8 |
| `EXTORTION_COERCION` | 1.000 | 0.800 | 0.889 | 5 |
| `PHISHING` | 1.000 | 1.000 | 1.000 | 6 |


---

## 5. Independent Audit Benchmark (10 Real-World Unseen Emails)
Evaluation on the 10 unseen real-world email samples tested in `evidence/INDEPENDENT_AUDIT.md` (re-tested with zero false positives on routine invoices and password resets):

| Subject | Ground Truth | Predicted | Confidence | Verdict |
|---|---|---|---|---|
| Vendor Invoice INV-2026-889 Attached | `BENIGN` | `BENIGN` | 58.3% | **MATCH** |
| Password Reset Request | `BENIGN` | `BENIGN` | 50.3% | **MATCH** |
| Final Capstone Project Submission | `BENIGN` | `BENIGN` | 58.0% | **MATCH** |
| Weekly Sync Rescheduled | `BENIGN` | `BENIGN` | 57.9% | **MATCH** |
| Account Statement for October 2026 | `BENIGN` | `BENIGN` | 41.0% | **MATCH** |
| Action Required: Your mailbox is full | `PHISHING` | `PHISHING` | 64.6% | **MATCH** |
| URGENT: Wire Transfer | `BEC_FINANCIAL` | `BEC_FINANCIAL` | 74.2% | **MATCH** |
| Security Breached - You have 48 hours | `EXTORTION_COERCION` | `EXTORTION_COERCION` | 58.6% | **MATCH** |
| Microsoft 365: Re-authenticate MFA session | `PHISHING` | `PHISHING` | 62.2% | **MATCH** |
| Formal Notice of Copyright Infringement & Impending Litigation | `EXTORTION_COERCION` | `EXTORTION_COERCION` | 61.5% | **MATCH** |

**Audit Benchmark Accuracy:** **100.0%** (10/10)

---

## 6. Explainability: Top Predictive Token Attributions
- **`BEC_FINANCIAL`**: `wire`, `ifsc`, `transfer`, `000`, `account`, `rs`, `remittance`, `wire transfer`
- **`BENIGN`**: `2026`, `semester`, `attached`, `schedule`, `dear`, `annual`, `research`, `student`
- **`EXTORTION_COERCION`**: `notice`, `immediate`, `compliance`, `regulatory`, `non`, `hours`, `hearing`, `formal`
- **`PHISHING`**: `http`, `credentials`, `verify`, `sign`, `security`, `auth`, `login`, `portal`


---

## 7. Reproduction Command
To retrain and reproduce this exact model artifact and metric evaluation:
```bash
python -m backend.app.ai.model_trainer
```
