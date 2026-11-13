# Forensic Threat Detection Dataset Provenance & Registry
**Execution Timestamp:** 2026-11-13T01:20:21.136776+00:00  
**Provenance Verification:** Cryptographic SHA-256 Archive Digests Calculated on Disk

---

## 1. Primary Corpus Provenance Registry

| Dataset Name | License | Source URL | Cryptographic SHA-256 Digest | Archive Size |
|:---|:---|:---|:---|:---|
| **Jose Nazario Phishing Corpus** | Public Domain / Academic Research | `https://monkey.org/~jose/phishing/phishing0.mbox` | `6184b0a34ed8cbbb252676e21c1eab9eac5fa4be89c61e30cc9954ebbb25d848` | 3,119,972 bytes |
| **Apache SpamAssassin Easy Ham 2** | Apache License 2.0 | `https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2` | `b4bd3dc5ae5b40f38e99a0e41ad7d16b428b56e818e3a6ffa07330d62004dd38` | 1,077,892 bytes |
| **Apache SpamAssassin Spam** | Apache License 2.0 | `https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2` | `c08debc32413804949a866be45ef78195cec2cbafd1da744ed76cdb860589743` | 1,183,768 bytes |
| **Apache SpamAssassin Hard Ham** | Apache License 2.0 | `https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2` | `ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9` | 1,029,898 bytes |
| **Enron Email Academic Corpus** | Public Domain | `https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip` | `e994ad3c09fd7528b397e1f921742da5dd59f19695bc25cdb3617eb3ded17634` | 15,642,124 bytes |
| **Tranco Top-1M Research List** | Creative Commons Attribution 4.0 | `https://tranco-list.eu/top-1m.csv.zip` | `e3ec5c22b344256766a3d0f917e747a554192086bddd22f24dd148a521228100` | 9,683,903 bytes |

---

## 2. Partition & Split Methodology
- **Lexical Deduplication:** 64-bit SimHash (Hamming distance threshold $\le 3$ bits) applied to eliminate duplicates.
- **Corpus Split:** 80% Stratified Training Partition (1080 samples) / 20% Held-Out Test Partition (271 samples).
- **Deterministic Seed:** Frozen seed `26106` ensures identical, reproducible fold splits.
- **Test Integrity:** Held-out test partition is used strictly for single-pass evaluation, never for hyperparameter tuning.

---

## 3. Calibrated Model Performance Baseline (Held-Out Test Set)
- **Holdout Test Accuracy:** **95.20%** (95% CI: [92.62%, 97.61%])
- **Macro F1-Score:** **0.9701** (95% CI: [0.9543, 0.9851])
- **ROC-AUC (Macro OvR):** **0.9959**
- **Expected Calibration Error (ECE):** **0.0848**
- **False Positive Rate @ 95% Recall:** **7.29%**
