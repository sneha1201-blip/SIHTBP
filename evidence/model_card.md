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
