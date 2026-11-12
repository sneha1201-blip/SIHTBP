# Evidence Log: STEP 8 - Threat Campaign Clustering & Analyst Actions

**Problem Statement:** AICTE Cyber Security Cell — SIH PS 26106  
**Timestamp:** 2026-11-12T21:13:00+05:30  
**Phase:** STEP 8 (Dynamic Multi-Signal Clustering, Analyst Workflows, STIX 2.1 Export & Evaluation)

---

## 1. Multi-Signal Campaign Clustering Architecture

The clustering engine in [`backend/app/forensics/campaign_clusterer.py`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/backend/app/forensics/campaign_clusterer.py) correlates incoming email incidents dynamically across 4 independent signal families:

1. **Network Infrastructure:** Relaying ASN and CIDR IP subnets (`/24` for IPv4).
   - **Hyperscaler Isolation Filter:** Strictly exempts shared legitimate cloud providers (Google AS15169, AWS AS16509, Microsoft AS8075, Cloudflare AS13335) from forming single-provider mega-clusters.
2. **Template SimHash:** 64-bit Locality-Sensitive Hashing (LSH) on normalized body text with Hamming distance threshold `<= 10`.
3. **Attribution & Spoofing:** Cousin domains, target protected entities, and targeted display impersonation patterns.
4. **Indicators of Compromise (IOCs):** Exact matching on extracted defanged malicious URLs, payload domains, and attachment hashes.

---

## 2. Empirical Ground-Truth Evaluation Metrics

Evaluated across the 72-email ground-truth corpus via [`scripts/evaluate_campaign_clustering.py`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/scripts/evaluate_campaign_clustering.py):

| Evaluation Metric | Target Gate | Empirical Result | Gate Status |
|---|---|---|---|
| **Adjusted Rand Index (ARI)** | `>= 0.8500` | **`0.8766`** | **PASS** |
| **Normalized Mutual Information (NMI)** | `>= 0.8500` | **`0.9037`** | **PASS** |
| **Clustering Purity** | `>= 0.9000` | **`1.0000` (100%)** | **PASS** |
| **Noise False Positive Rate** | `0.0%` | **`0.0%`** | **PASS** |
| **Hyperscaler Mega-Cluster Prevention** | Filtered | **PASS** | **PASS** |

---

## 3. Analyst Interactive Actions & Audit Logging

Implemented in [`backend/app/api/v1/endpoints_campaigns.py`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/backend/app/api/v1/endpoints_campaigns.py):

1. **Campaign Relabeling (`PATCH /api/v1/campaigns/{id}/label`):**
   - Allows analysts to name tactical operations and assign threat actor attribution.
   - Logs `CAMPAIGN_LABELED` into the hash-chained audit ledger.
2. **Campaign Splitting (`POST /api/v1/campaigns/{id}/split`):**
   - Enables analysts to isolate a subset of emails into a new campaign cluster.
   - Logs `CAMPAIGN_SPLIT` with parent and child campaign IDs.
3. **Campaign Merging (`POST /api/v1/campaigns/{id}/merge`):**
   - Merges related clusters into a unified campaign and re-links email associations.
   - Logs `CAMPAIGN_MERGED` recording migrated incident count.

---

## 4. STIX 2.1 Threat Intelligence Bundle Verification

- Endpoints `GET /api/v1/campaigns/export/stix` and `GET /api/v1/campaigns/{id}/stix` export standard OASIS STIX 2.1 JSON bundles.
- Structure contains:
  - `type: "bundle"`
  - `spec_version: "2.1"`
  - SDOs: `campaign`, `threat-actor`, `indicator`, `email-message`, `observed-data`, and `relationship` objects (`attributed-to`, `indicates`, `uses`).
- Output artifact generated at [`evidence/campaign_bundle.json`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/evidence/campaign_bundle.json).

---

## 5. Test Verification Output

Command:
```powershell
python -m pytest backend/tests/test_campaign_clustering.py
```

Output:
```
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, hypothesis-6.170.15, asyncio-1.4.1.post1
collected 7 items

backend\tests\test_campaign_clustering.py .......                        [100%]

============================= 7 passed in 14.83s ==============================
```
