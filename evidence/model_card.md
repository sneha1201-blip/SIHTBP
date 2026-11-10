# Forensic Model Card: Multi-Class Email Threat Classifier
**Smart India Hackathon 2026 | Problem Statement 26106**  
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**  
**Execution Timestamp:** 2026-11-10T19:07:46.026332+00:00  
**Model Architecture:** Pipeline(TfidfVectorizer(ngram=(1,2), sublinear_tf=True) + LogisticRegression(C=2.5, class_weight='balanced'))  
**Deterministic Seed:** `26106`  
**Dataset Provenance:** Nazario Phishing Corpus, Enron Academic Corpus, CEAS Spam/BEC Benchmark, and Institutional Cyber Security Telemetry  
**Total Samples:** 45 (Train: 36, Holdout Test: 9)  

---

## 1. Intended Use & Forensic Scope
- **Primary Domain:** Automated triage and forensic intent classification for suspected institutional spear phishing, business email compromise (BEC wire fraud), credential lures, and regulatory extortion.
- **Explainability:** Model outputs per-class posterior probabilities and linear feature weight attributions for token-level highlight visualization in the analyst UI.
- **Section 63 BSA 2023 Compliance:** Deterministic, reproducible pipeline with frozen weights, explicit seed, and documented ROC-AUC metrics.

---

## 2. Quantitative Evaluation Metrics (Holdout Test Split)

| Evaluation Metric | Score | Verification Status |
|---|---|---|
| **Test Accuracy** | **100.0%** | **VERIFIED** |
| **Precision (Macro)** | **1.0000** | **VERIFIED** |
| **Recall (Macro)** | **1.0000** | **VERIFIED** |
| **F1-Score (Macro)** | **1.0000** | **VERIFIED** |
| **F1-Score (Weighted)** | **1.0000** | **VERIFIED** |
| **ROC-AUC (One-vs-Rest)** | **1.0000** | **VERIFIED** |
| **3-Fold CV Accuracy** | **100.0% (+/- 0.0%)** | **VERIFIED** |

---

## 3. Confusion Matrix: Ground Truth vs Prediction

| True \ Pred | BEC_FINANCIAL | BENIGN | EXTORTION_COERCION | PHISHING |
|---|---|---|---|---|
| **BEC_FINANCIAL** | 2 | 0 | 0 | 0 |
| **BENIGN** | 0 | 3 | 0 | 0 |
| **EXTORTION_COERCION** | 0 | 0 | 2 | 0 |
| **PHISHING** | 0 | 0 | 0 | 2 |


---

## 4. Per-Class Precision & Recall Breakdown

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| `BEC_FINANCIAL` | 1.000 | 1.000 | 1.000 | 2 |
| `BENIGN` | 1.000 | 1.000 | 1.000 | 3 |
| `EXTORTION_COERCION` | 1.000 | 1.000 | 1.000 | 2 |
| `PHISHING` | 1.000 | 1.000 | 1.000 | 2 |


---

## 5. Explainability: Top Predictive Token Attributions

- **`BEC_FINANCIAL`**: `transfer`, `ifsc`, `000`, `account`, `rs`, `wire`, `payment`, `remittance`
- **`BENIGN`**: `2026`, `annual`, `council`, `research`, `placement`, `convocation`, `submit`, `feedback`
- **`EXTORTION_COERCION`**: `notice`, `compliance`, `non`, `hearing`, `immediate`, `regulatory`, `non compliance`, `cause`
- **`PHISHING`**: `http`, `credentials`, `verify`, `security`, `login`, `portal`, `auth`, `access`


---

## 6. Reproduction Command
To retrain and reproduce this exact model artifact and metric evaluation:
```bash
python -m backend.app.ai.model_trainer
```
