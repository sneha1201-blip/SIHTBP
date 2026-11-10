# Forensic Verification Artifact: Phase 5 — Dynamic Campaign Clustering, Graph Telemetry & RFC STIX 2.1 Export

**Problem Statement:** Smart India Hackathon 2026 — PS ID 26106 (AICTE Cyber Security Cell)  
**System Title:** AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform  
**Target Standard:** RFC OASIS CTI STIX 2.1 Standard & Bharatiya Sakshya Adhiniyam (BSA), 2023 § 63  
**Phase:** 5 (Dynamic Cross-Incident Campaign Clustering, Interactive Graph Visualization & Threat Intelligence Export)  
**Execution Timestamp:** 2026-11-11T01:05:00Z  
**Previous Sealed Commit:** `66336c9`  

---

## 1. Executive Summary & Architectural Compliance

In Phase 5, the platform was brought from single-email threat triage to enterprise-grade, cross-incident threat campaign correlation and intelligence dissemination. In accordance with SIH Problem Statement 26106 and the Absolute Rules of the project, all static seeds and hardcoded groupings were replaced by a real-time dynamic clustering engine:

1. **Locality-Sensitive Hashing (SimHash 64-bit):** Ingested email bodies are vectorized into 64-bit SimHash fingerprints. Hamming distance evaluation ($D_H \le 10$ bits) links near-duplicate spear-phishing and extortion templates across victims even when recipient names, amounts, or timestamps are varied.
2. **Multi-Vector Infrastructure Correlation:** In addition to content fingerprints, incoming incidents are cross-correlated against:
   - Shared bulletproof / transit Autonomous System Number (ASN)
   - Shared network /24 IPv4 subnet or /48 IPv6 prefix
   - Shared diversionary `Reply-To` address or malicious threat sender domain
3. **Dynamic On-Ingestion Clustering:** Rather than requiring static database seeding or batch cron jobs, correlation executes dynamically in the ingestion pipeline (`cluster_email_dynamically()`). New emails immediately join existing campaign clusters or automatically spawn new campaigns.
4. **Interactive Graph Telemetry & Filters:** The `/api/v1/campaigns/graph` endpoint exposes multi-dimensional Cytoscape / D3 graph data with query filters (`min_threat_score`, `cluster_type`), campaign velocity metrics (emails/hour), targeted VIP lists, and interactive node drawers.
5. **RFC OASIS STIX 2.1 Threat Intelligence Bundle Generation:** Produces standards-compliant STIX 2.1 JSON bundles encompassing `threat-actor`, `campaign`, `email-message`, `ipv4-addr`, `indicator`, and `relationship` SDOs/SROs with ISO 8601 millisecond-precision UTC timestamps.

---

## 2. Dynamic Correlation Methodology

```
+-----------------------------------------------------------------------------------------+
|                               INCOMING EMAIL INGESTION                                  |
| (SimHash Body: 0x48298a38a8d49960, Origin IP: 185.220.101.12, Origin ASN: 208294, etc.) |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
|                  ACTIVE CAMPAIGN CHECK (Ordered by last_seen DESC)                     |
|  - SimHash Hamming Distance <= 10 bits? -> Similarity = 1.0 - (dist / 64.0)            |
|  - Shared Autonomous System Number (ASN)? -> Similarity = 0.90                          |
|  - Shared /24 Network Subnet? -> Similarity = 0.85                                      |
|  - Shared Reply-To Divergence or Sender Domain? -> Similarity = 0.95                    |
+-----------------------------------------------------------------------------------------+
       |                                                         |
       | Match Found                                             | No Match
       v                                                         v
+------------------------------------+   +------------------------------------------------+
| UPDATE EXISTING CAMPAIGN           |   | CHECK RECENT UNCLUSTERED EMAILS (limit 50)     |
| - Increment total_emails           |   | - Pairwise Hamming Distance <= 10 bits?        |
| - Update last_seen (UTC)           |   | - Shared Infrastructure ASN / Subnet?          |
| - Recompute velocity (emails/hour) |   | - Shared Diversion Reply-To / Sender Domain?   |
| - Append newly targeted VIPs       |   +------------------------------------------------+
| - Link CampaignEmail Association   |          | Match Found                 | Isolated
+------------------------------------+          v                             v
                                         +--------------------------+   +-----------------+
                                         | SPAWN NEW CAMPAIGN       |   | REMAINS ISOLATED|
                                         | - Set cluster_type & key |   | (No campaign    |
                                         | - Link both incidents    |   |  association)   |
                                         +--------------------------+   +-----------------+
```

---

## 3. RFC OASIS STIX 2.1 Specification Compliance

The generated STIX 2.1 bundles (`evidence/campaign_bundle.json`) conform to the OASIS Cyber Threat Intelligence (CTI) STIX Version 2.1 specification:

| Field / Object | Standard Requirement | SIHTBP Implementation | Status |
|:---|:---|:---|:---:|
| `type` | `"bundle"` | `"bundle"` | **PASS** |
| `spec_version` | `"2.1"` | `"2.1"` | **PASS** |
| `id` | `bundle--<UUIDv4>` | `bundle--<UUIDv4>` | **PASS** |
| `threat-actor` SDO | Threat Actor entity | SDO with type `threat-actor`, motivation `financial-gain` | **PASS** |
| `campaign` SDO | Campaign entity | SDO with type `campaign`, first/last seen timestamps | **PASS** |
| `email-message` SCO | Cyber Observable Object | SCO with type `email-message`, subject, body snippet | **PASS** |
| `ipv4-addr` SCO | IP Cyber Observable | SCO with type `ipv4-addr`, value `x.x.x.x` | **PASS** |
| `indicator` SDO | Threat indicator | SDO with type `indicator`, pattern `[ipv4-addr:value = '...']` | **PASS** |
| `relationship` SRO | SDO / SCO linkages | SROs linking `campaign` -> `threat-actor`, `indicator` -> `campaign` | **PASS** |

### Sample STIX 2.1 Bundle Snippet (`evidence/campaign_bundle.json`):
```json
{
  "type": "bundle",
  "id": "bundle--242bfeb4-5c9a-4e20-804d-62287cfeb9b2",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "threat-actor",
      "spec_version": "2.1",
      "id": "threat-actor--b6bc0148-18e4-42b7-a359-71577ffc26c1",
      "name": "Threat Actor: Operation FalconShield: AICTE Affiliation Extortion & Compliance Scams",
      "primary_motivation": "financial-gain"
    },
    {
      "type": "campaign",
      "spec_version": "2.1",
      "id": "campaign--3b366a6a-8b8a-4dbb-bdae-da8d32ec0b4e",
      "name": "Operation FalconShield: AICTE Affiliation Extortion & Compliance Scams",
      "objective": "Targeted Spear Phishing & BEC Remittance Fraud"
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--c5d0baec-e9da-412e-a5a8-4fbef834ff44",
      "relationship_type": "attributed-to",
      "source_ref": "campaign--3b366a6a-8b8a-4dbb-bdae-da8d32ec0b4e",
      "target_ref": "threat-actor--b6bc0148-18e4-42b7-a359-71577ffc26c1"
    }
  ]
}
```

---

## 4. Verification & Gate Execution

### A. Phase 5 Automated Test Execution
- **Command:** `pytest -v backend/tests/test_campaign_clustering.py`
```
backend/tests/test_campaign_clustering.py::test_dynamic_campaign_clustering_and_stix_bundle PASSED [ 50%]
backend/tests/test_campaign_clustering.py::test_campaign_graph_api_endpoint PASSED [100%]
============================== 2 passed in 2.04s ==============================
```

### B. Full Test Suite Regression Gate
- **Command:** `pytest -v backend/tests/`
```
======================= 73 passed, 3 warnings in 15.55s =======================
```

### C. Static Analysis & Type Checking
- **Command:** `ruff check backend/` -> `All checks passed!`
- **Command:** `mypy backend/app` -> `Success: no issues found in 46 source files`
- **Command:** `cd frontend && npx tsc --noEmit` -> `Exit code 0 (no errors)`
- **Command:** `cd frontend && npm run build` -> `Exit code 0 (✓ Compiled successfully, static pages generated)`

### D. Zero-Mock & Forbidden Keywords Verification (Rule 1)
- **Command:** `git grep -inE "mock|dummy|fake|placeholder|fallback|hardcoded|AS49870|HDFC|before 4:00 PM" backend/app frontend/src`
- **Result:** `Exit code 1 (0 matches found)`

### E. Full System Integration Verifier
- **Command:** `python verify_system.py`
```
================================================================================
ALL SUBSYSTEMS VERIFIED & OPERATIONAL (Section 63 BSA 2023 Compliant)
Ready for Live Demonstration before AICTE Cyber Security Cell Jury.
================================================================================
```

---

## 5. Artifact Ledger

| Artifact Path | Format | Description |
|:---|:---|:---|
| `backend/app/forensics/campaign_clusterer.py` | Python 3.12 | Dynamic SimHash, ASN, subnet & domain clustering engine |
| `backend/app/api/v1/endpoints_campaigns.py` | FastAPI | Graph API with filters & STIX 2.1 export endpoints |
| `frontend/src/components/CampaignGraph.tsx` | React / TypeScript | Multi-node graph visualization, drawer timeline & STIX exporter |
| `evidence/campaign_bundle.json` | JSON (STIX 2.1) | RFC OASIS STIX 2.1 threat intelligence export bundle |
| `backend/tests/test_campaign_clustering.py` | Pytest Asyncio | Dynamic clustering & STIX generation verification suite |
