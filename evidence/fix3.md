# Fix 3 Evidence: Campaign Clustering Multi-Signal Correlation & Evaluation

## Problem Statement & Audit Findings (Items F.20 & F.21)
During the independent hostile audit (`evidence/INDEPENDENT_AUDIT.md`), two major deficiencies in campaign clustering were identified:
1. **Item 20 (F.20): Naive ASN Clustering False Positives**  
   Any 3 emails traversing the same network ASN were collapsed into an attack campaign (e.g. 3 unrelated routine emails from Google AS15169 formed `Operation Infrastructure-AS15169`). In enterprise deployment, routine emails via Google, Microsoft 365, or AWS relays would be erroneously certified as coordinated cyber threats.
2. **Item 21 (F.21): Lack of Empirical Clustering Metrics**  
   Clustering accuracy was completely unmeasured. No Adjusted Rand Index (ARI), Normalized Mutual Information (NMI), or purity calculations existed in the codebase.
3. **Item 97: Invalid STIX 2.1 Schema Export**  
   Cyber Observable Objects (`email-message`, `ipv4-addr`) illegally included Domain Object properties (`spec_version`, `created`, `modified`) and referenced missing address identifiers.

---

## Architectural & Algorithmic Remediation

### 1. High-Fanout Filtering & Domain Guards (`backend/app/core/config.py`)
- Added `HIGH_FANOUT_ASNS = {15169, 16509, 14618, 8075, 13335, 32934, 20940, 54113, 2635, 46484, 36351, 16276, 24940, 63949}` (Google, AWS, Microsoft, Cloudflare, Meta, Akamai, Fastly, Yahoo, Hetzner, etc.).
- Added `HIGH_FANOUT_ASN_PATTERNS` regex and substring matching for provider organizations.
- Added `PUBLIC_MAIL_DOMAINS` to prevent shared webmail providers (`@gmail.com`, `@yahoo.com`, `@outlook.com`) from being treated as threat actor infrastructure.

### 2. Independent Feature Family Gate (`backend/app/forensics/campaign_clusterer.py`)
To prevent collinear false positives (e.g. ASN + Subnet in the same datacenter counting as two signals), correlation signals are categorized into 4 independent feature families:
- **`FAMILY_NETWORK`**: Shared non-fanout ASN or /24 subnet (excluding hyperscalers). Collinear features within this family count as at most 1 network signal.
- **`FAMILY_TEMPLATE`**: Locality-sensitive SimHash distance ($6..10$ bits = template overlap signal; $\le 5$ bits = deterministic near-duplicate link).
- **`FAMILY_ATTRIBUTION`**: Shared diversion Reply-To or non-public threat actor sender domain.
- **`FAMILY_IOC`**: Shared malicious URL, phishing domain, or identical attachment SHA-256 hash.

**Clustering Decision Boundary:**
Candidate emails are clustered if and only if:
$$\text{is\_deterministic} \lor |\text{matched\_families}| \ge 2$$
High-fanout ASNs (e.g. AS15169) yield 0 network signals and cannot link unrelated emails.

### 3. OASIS STIX 2.1 Schema Correction
- Removed `created` and `modified` properties from STIX Cyber-observable Objects (SCOs: `email-message`, `email-addr`, `ipv4-addr`, `ipv6-addr`).
- Created explicit `email-addr` SCO for sender addresses and referenced them cleanly via `from_ref`.

### 4. Ground-Truth Corpus (`backend/tests/fixtures/campaign_eval_corpus.py`)
Authored labeled dataset `CAMPAIGN_EVAL_CORPUS` containing 72 samples:
- `campaign_bec_payroll` (10 samples): SimHash template + Reply-To diversion.
- `campaign_aicte_audit` (10 samples): Bulletproof ASN 208294 + compliance lure.
- `campaign_credential_harvest` (10 samples): Microsoft 365 credential harvesting URL.
- `campaign_lottery_advance_fee` (10 samples): RBI escrow remittance advance-fee scam.
- `campaign_invoice_malware` (10 samples): Shared macro malware attachment SHA-256 hash.
- `campaign_tax_refund_fraud` (10 samples): Income tax refund phishing lure + domain.
- `noise` (12 unclustered samples): Includes 4 from Google AS15169, 4 from AWS AS16509, 2 from ERNET AS2687, and 2 from NIC AS9498.

---

## Verification & Empirical Metrics

### Raw Output: `scripts/evaluate_campaign_clustering.py`
```text
Initializing isolated evaluation database...
Ingesting and evaluating 72 corpus samples...

================ CLUSTERING EVALUATION REPORT ================
Evaluated Samples: 72
Adjusted Rand Index (ARI): 0.8766 (Gate: >= 0.85)
Normalized Mutual Info (NMI): 0.9037 (Gate: >= 0.85)
Clustering Purity: 1.0 (Gate: >= 0.90)
Pairwise F1 Score: 1.0
Noise False Positive Rate: 0.0%
Google AS15169 False Clusters: 0 / 4
AWS AS16509 False Clusters: 0 / 4
Report written to: evidence/cluster_eval.json
==============================================================
```

### Raw Output: `evidence/cluster_eval.json`
```json
{
  "metadata": {
    "evaluation_timestamp": "2026-11-11T00:58:09.174249+00:00",
    "git_commit": "1e41d602f3f7fd125436f240ed2aa7dddb20bca3",
    "corpus_size": 72,
    "campaign_classes_count": 6,
    "noise_samples_count": 12
  },
  "metrics": {
    "adjusted_rand_index_ari": 0.8766,
    "normalized_mutual_info_nmi": 0.9037,
    "clustering_purity": 1.0,
    "pairwise_precision": 1.0,
    "pairwise_recall": 1.0,
    "pairwise_f1": 1.0,
    "noise_false_positive_rate": 0.0
  },
  "hyperscaler_isolation_verification": {
    "google_as15169_samples_tested": 4,
    "google_as15169_incorrectly_clustered": 0,
    "google_clustered_ids": [],
    "aws_as16509_samples_tested": 4,
    "aws_as16509_incorrectly_clustered": 0,
    "aws_clustered_ids": [],
    "hyperscaler_clustering_status": "PASS"
  },
  "pairwise_confusion": {
    "true_positives": 270,
    "false_positives": 0,
    "false_negatives": 0,
    "true_negatives": 2286,
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0
  }
}
```

### Raw Output: `pytest backend/tests/test_campaign_clustering.py -v`
```text
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0 -- .venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, asyncio-1.4.1.post1
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=function, asyncio_default_test_loop_scope=function
collecting ... collected 6 items

backend/tests/test_campaign_clustering.py::test_dynamic_campaign_clustering_and_stix_bundle PASSED [ 16%]
backend/tests/test_campaign_clustering.py::test_campaign_graph_api_endpoint PASSED [ 33%]
backend/tests/test_campaign_clustering.py::test_unrelated_google_asn_emails_do_not_cluster PASSED [ 50%]
backend/tests/test_campaign_clustering.py::test_identical_bodies_different_asns_do_cluster PASSED [ 66%]
backend/tests/test_campaign_clustering.py::test_multi_signal_clustering_requires_two_signals PASSED [ 83%]
backend/tests/test_campaign_clustering.py::test_campaign_clustering_corpus_eval_gates PASSED [100%]

============================== 6 passed in 5.67s ==============================
```

### Raw Output: Full Test Suite (`pytest`)
```text
======================= 79 passed, 3 warnings in 17.37s =======================
```

### Raw Output: Static Analysis & Type Checking
```text
$ ruff check .
All checks passed!

$ mypy backend/app
Success: no issues found in 46 source files

$ npm run build
✓ Compiled successfully
✓ Generating static pages (4/4)
Finalizing page optimization ...
```
