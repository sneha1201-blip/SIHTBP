# Gate Script Revision & Modification Changelog

Per Rule R4 & R7:
> "Gate edits: `git log -p gates/` to list every edit since creation. For each post-creation edit, classify: (a) fixes a gate bug, (b) loosens a threshold or removes an assertion. Revert every (b). Create evidence/GATE_CHANGELOG.md listing every edit with reason; any gate edit not in it fails G00."

---

## Commit History & Edits to `gates/`

### 1. `8964610` — Initial Creation
- **Date:** 2026-11-12
- **Files:** `gates/common.py`, `gates/g00_hygiene.py` through `gates/g15_provable_claims.py`, `gates/run_all.py`
- **Classification:** Baseline Creation.

### 2. `a5fbb88` — `gates/g04_auth.py`
- **Classification:** (a) Fixes a gate bug (formatting & reporting of zero real fixtures).
- **Details:** Refined output table formatting when `tests/fixtures/real/` contained 0 files.
- **Audit Note:** Script still exited 0 despite 0 real files; needs Rule R3 BLOCKED enforcement.

### 3. `25ac19a` — `gates/g05_geo.py`
- **Classification:** (a) Fixes a gate bug (formatting & reporting of missing ground-truth CSV).
- **Details:** Handled missing `tests/fixtures/geo_ground_truth.csv` without crashing.
- **Audit Note:** Script still reported PASS despite missing ground-truth; needs Rule R3 BLOCKED enforcement.

### 4. `8c21ce9` — `gates/g06_hops.py`, `gates/g07_classifier.py`, `gates/run_all.py`
- **Classification:** (a) Fixes a gate bug (clarified dataset provenance check & logging).
- **Details:** Added check for `evidence/datasets.md` presence in G07; added step timing in `run_all.py`.

### 5. `897ccb8` — `gates/g13_performance.py`
- **Classification:** **(b) Loosens a threshold or removes an assertion.** [CRITICAL - MARKED FOR REVERSION]
- **Details:** Added dictionary `.get(..., 53.97)` fallbacks in G13 for latency numbers, allowing the gate to pass even if benchmark output lacked measured values.
- **Action Taken:** Marked for full reversion in Step 5 (G13 Repair) to enforce strict parsing without fallback numbers.

### 6. Working Tree Edit — `gates/g03_security.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Added real CycloneDX 1.6 JSON SBOM verification (`cyclonedx-py`).
  - Added npm audit execution and verification of `evidence/security/npm_audit_triage.md`.
  - Added host scanner checks for `gitleaks` and `trivy`, requiring documentation in `evidence/security/scanner_availability.md`.
  - Enforced Rule R3: marks G03 `BLOCKED` when required host scanners are missing rather than pretending they passed.

### 7. Working Tree Edit — `gates/g07_detection.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Removed previous hardcoded metrics (`roc_auc_baseline: 0.9980`, `holdout_accuracy: 0.9167`).
  - Added dynamic verification of `evidence/evaluation.json` generated from real 2,872-sample corpus.
  - Enforced empirical thresholds: ROC-AUC >= 0.95, ECE <= 0.10, dataset size >= 1000.
  - Records real measured numbers and 95% bootstrap CIs in `evidence/gates/g07.json`.

### 8. Working Tree Edit — `gates/g15_docs.py`
- **Classification:** (a) Fixes a gate bug.
- **Details:**
  - Replaced hardcoded string `"91.67"` with dynamic check against measured accuracy from `evidence/evaluation.json`.
  - Removed unmeasured latency string check `"53.97"` per Rule R2.

### 9. Working Tree Edit — `gates/g06_headers.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Replaced synthetic "210 diverse MTA headers" assertion with verification of `evidence/real_headers_eval.json` generated from 400 real headers from public corpora.
  - Dynamically records IP parse rate, timestamp parse rate, and failure taxonomy.

### 10. Working Tree Edit — `gates/g08_campaigns.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Removed previous hardcoded metrics (`ari: 0.8766`, `nmi: 0.9037`).
  - Added dynamic metric extraction and assertion from `evidence/cluster_eval.json`.
  - Replaced manually edited STIX bundle with script-generated `scripts/generate_campaign_bundle.py`.

### 11. Working Tree Edit — `gates/g13_performance.py`
- **Classification:** Reversion of loosening edit `897ccb8` / strictness enhancement.
- **Details:**
  - Completely reverted default fallback values (`53.97`, `2051.58`).
  - Strictly requires `p50_ms` and `p95_ms` in `evidence/benchmark_results.json`.
  - Enforced minimum sample count threshold (evaluated on >= 50 distinct nonced emails).
  - Enforces verification of all 4 failure injection test suites (`dns_timeout`, `db_locked`, `disk_full`, `geoip_missing`).
  - Enforces verification of physical disk throughput benchmark and hardware telemetry.

### 12. Working Tree Edit — `gates/g10_architecture.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement (enforces Rule R3).
- **Details:**
  - Enforced Rule R3: when Docker host daemon is unavailable, marks G10 status as `BLOCKED: awaiting Docker host daemon` rather than falsely asserting PASS.

### 13. Working Tree Edit — `gates/g12_coverage.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Removed previous static/hardcoded coverage dictionary.
  - Dynamically runs `pytest backend/tests/ --cov=backend/app --cov-report=json:evidence/coverage.json`.
  - Parses real measured coverage metrics and verifies overall >= 70.0% and core modules >= 80%.

### 14. Working Tree Edit — `gates/g05_geo.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Added verification of authentic Natural Earth 110m GeoJSON (177 sovereign country boundaries), strictly rejecting <=5 polygon mockups.
  - Enforced Rule R3: marks G05 status as `BLOCKED` when external MaxMind `.mmdb` and `ground_truth.csv` are unsupplied.

### 15. Working Tree Edit — `gates/g09_legal.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Enforced Rule R3: marks G09 status as `BLOCKED` awaiting official Section 63 BSA statute text and human signatory attestation.

### 16. Working Tree Edit — `gates/g00_hygiene.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement.
- **Details:**
  - Added verification ensuring every modified gate script has a documented audit entry in `evidence/GATE_CHANGELOG.md`.

### 17. Working Tree Edit — `gates/g04_auth.py`
- **Classification:** (a) Fixes a gate bug / strictness enhancement (enforces Rule R3).
- **Details:**
  - Enforced Rule R3: marks G04 status as `BLOCKED` awaiting external user input of >=20 real signed `.eml` fixtures in `tests/fixtures/real/`, rather than recording PASS while sub-checks are BLOCKED.


