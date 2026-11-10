# Phase 3 Evidence & Verification Baseline
**Smart India Hackathon 2026 | Problem Statement 26106**  
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**  
**Execution Timestamp:** 2026-11-10T19:05:00Z  
**Target System:** `SIHTBP` (FastAPI + SQLAlchemy async + SQLite WAL + Next.js 14)  
**Dataset Name:** `SIH-Forensic-OSINT-Hop-Corpus`  
**Dataset Version:** `3.0.0`  
**Deterministic Seed:** `26106`  
**Commit Baseline:** `68ada4e`  

---

## 1. Executive Summary & Objective

Phase 3 transitions the platform from hardcoded network mock tables and geographic approximations into an authoritative, zero-guess forensic intelligence subsystem:

1. **MaxMind GeoLite2-City Geolocation (`backend/app/osint/geo_resolver.py`):**
   - Official `maxminddb` / `geoip2` integration resolving public IPs to Country, City, Coordinates, and Accuracy Radius.
   - **Zero Guessing Policy strictly enforced:**
     - Purged all 30-prefix heuristic tables and Nagpur default coordinates (`20.5937, 78.9629`).
     - Any private (RFC 1918), loopback, link-local, or unresolvable IP returns `latitude=None, longitude=None` with status `UNRESOLVED` and explicit reason.
     - Reports accuracy radius in kilometers and MaxMind database build date; never presents city-level centroids as exact pinpoint coordinates.
     - Provided update automation: `scripts/update_geoip.sh` and `scripts/update_geoip.ps1` utilizing `MAXMIND_LICENSE_KEY`.

2. **MaxMind GeoLite2-ASN Telemetry (`backend/app/osint/asn_lookup.py`):**
   - Official ASN resolution via `GeoLite2-ASN.mmdb`.
   - Purged static `OFFLINE_ASN_DATABASE` and Cloudflare ASN 13335 defaults.
   - Automatically classifies Datacenter / Hosting / Cloud providers and flags bulletproof hosting providers (e.g. Alexhost, Alservice, Floki).

3. **RFC 5321 Hop Traversal & MTA Trust Boundary Analysis (`backend/app/forensics/hop_traversal.py`):**
   - Reverse hop-traversal algorithm parsing diverse real-world MTA header formats:
     - Microsoft Exchange / Office 365 (`Microsoft SMTP Server id ...`)
     - Postfix (`by mx... (Postfix) with ESMTPS ...`)
     - Google Workspace / Gmail (`by 2002:... with SMTP ...`)
     - Sendmail (`by mx... (8.14.4/8.14.4) ...`)
     - qmail (`(qmail ... invoked from network)`)
     - Exim (`with esmtp (Exim ...)`)
   - Robust IPv4 and IPv6 extraction handling bracketed (`[2001:db8::1]`), unbracketed, and `IPv6:` prefix formats.
   - Timestamp normalization converting diverse timezone offsets (`+0530`, `-0800 (PST)`, `+0100`) to UTC.
   - Anomaly detection:
     - **Clock Skew:** Flags negative delay < -300 seconds as temporal clock skew anomaly.
     - **Temporal Impossibility:** Flags hops claiming timestamps in the future relative to downstream receiving MTAs as `FORGED_OR_UNVERIFIED`.
     - **Syntax Anomaly:** Flags hops missing both identifying IP and sender MTA hostname.
   - Trust Boundary: Marks recipient edge gateway as trusted boundary; isolates lower hops below untrusted boundaries.
   - Extracts the Earliest Reliable Public Originating IP.

4. **Live Tor Exit Node Caching & Labeled Offline Snapshots (`backend/app/osint/tor_detector.py`):**
   - Fetches live bulk exit lists directly from `https://check.torproject.org/torbulkexitlist`.
   - Persists cache to `storage/tor/tor_exit_nodes_cache.json` with TTL validation.
   - Offline fallback maintains exact cache age in hours (`age_hours`) and telemetry source label (`LOCAL_CACHE` vs `OFFLINE_SNAPSHOT`).
   - Purged the static 25-IP list as sole source of truth.

5. **Asynchronous RFC 7483 RDAP Client (`backend/app/osint/whois_client.py`):**
   - Queries authoritative IANA bootstrap service `https://rdap.org/domain/{domain}`.
   - Extracts exact domain creation dates and computes exact domain age in days.
   - Automatically flags Newly Registered Domains (NRD < 30 days old) with elevated reputation risk (85.0/100).
   - Zero TLD-based guessing: unreachable or unallocated domains evaluate to `UNKNOWN` with explanatory reason.

6. **Real-Time DNSBL Reputation Client (`backend/app/osint/dnsbl_checker.py`):**
   - Performs reverse-octet DNS A-record queries against Spamhaus ZEN, SpamCop, and Barracuda Central.
   - Enforces 1.5s timeout guards for air-gapped / offline resiliency.
   - Immediately excludes RFC 1918 private IPs from DNSBL queries.

7. **Air-Gapped Vector Map Offline Mode (`frontend/src/components/GeoTraceMapInner.tsx`):**
   - Bundled continental vector map `frontend/public/data/world.geojson`.
   - Auto-detects offline state (`navigator.onLine === false`) or allows explicit manual air-gap simulation.
   - Renders mandatory alert banner: `OFFLINE MODE: tiles local, live OSINT disabled`.
   - Skips unresolved hops on the map canvas; hop timeline cards display `Unresolved (Private)` or `Unresolved` instead of invalid coordinates.

---

## 2. Requirements Matrix Traceability (Phase 3)

| Requirement Description | Architecture Module | Automated Test File | Verification Status |
|---|---|---|---|
| MaxMind GeoLite2-City zero-guess | `backend/app/osint/geo_resolver.py` | `backend/tests/test_osint_geoip.py` | **PASS (100%)** |
| MaxMind GeoLite2-ASN intelligence | `backend/app/osint/asn_lookup.py` | `backend/tests/test_osint_geoip.py` | **PASS (100%)** |
| RFC 5321 Hop Traversal (Exchange, Postfix, Gmail, Sendmail, qmail, Exim) | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | **PASS (100%)** |
| IPv6 bracketed/unbracketed unwrapping | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | **PASS (100%)** |
| Clock skew (< -300s) & out-of-order detection | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | **PASS (100%)** |
| Earliest reliable public origin IP extraction | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | **PASS (100%)** |
| Live Tor exit caching + age-labeled offline snapshot | `backend/app/osint/tor_detector.py` | `backend/tests/test_osint_geoip.py` | **PASS (100%)** |
| Async RDAP domain age & NRD (< 30d) detection | `backend/app/osint/whois_client.py` | `backend/tests/test_osint_geoip.py` | **PASS (100%)** |
| Real-time DNSBL queries with 1.5s timeout | `backend/app/osint/dnsbl_checker.py` | `backend/tests/test_osint_geoip.py` | **PASS (100%)** |
| Offline map auto-switch & banner | `frontend/src/components/GeoTraceMapInner.tsx` | Next.js Production Build | **PASS (100%)** |

---

## 3. Test Execution Verification Artifacts

### Command:
```bash
pytest -v backend/tests/test_hop_traversal.py backend/tests/test_osint_geoip.py
```

### Result: 20 passed in 1.08s
```text
backend/tests/test_hop_traversal.py::test_postfix_received_header PASSED [  5%]
backend/tests/test_hop_traversal.py::test_microsoft_exchange_received_header PASSED [ 10%]
backend/tests/test_hop_traversal.py::test_gmail_workspace_received_header PASSED [ 15%]
backend/tests/test_hop_traversal.py::test_sendmail_and_qmail_and_exim PASSED [ 20%]
backend/tests/test_hop_traversal.py::test_ipv6_address_variants PASSED   [ 25%]
backend/tests/test_hop_traversal.py::test_clock_skew_detection PASSED    [ 30%]
backend/tests/test_hop_traversal.py::test_trust_boundary_and_origin_extraction PASSED [ 35%]
backend/tests/test_hop_traversal.py::test_forged_hop_temporal_anomaly PASSED [ 40%]
backend/tests/test_osint_geoip.py::test_geoip_private_and_loopback_rejection PASSED [ 45%]
backend/tests/test_osint_geoip.py::test_geoip_fixture_resolution_with_accuracy PASSED [ 50%]
backend/tests/test_osint_geoip.py::test_geoip_unresolved_public_ip PASSED [ 55%]
backend/tests/test_osint_geoip.py::test_asn_private_ip_rejection PASSED  [ 60%]
backend/tests/test_osint_geoip.py::test_asn_fixture_resolution PASSED    [ 65%]
backend/tests/test_osint_geoip.py::test_tor_cache_loading_and_age PASSED [ 70%]
backend/tests/test_osint_geoip.py::test_rdap_parse_nrd_detection PASSED  [ 75%]
backend/tests/test_osint_geoip.py::test_rdap_parse_established_domain PASSED [ 80%]
backend/tests/test_osint_geoip.py::test_rdap_unreachable_returns_unknown PASSED [ 85%]
backend/tests/test_osint_geoip.py::test_dnsbl_reverse_ip_format PASSED   [ 90%]
backend/tests/test_osint_geoip.py::test_dnsbl_private_ip_bypass PASSED   [ 95%]
backend/tests/test_osint_geoip.py::test_dnsbl_fixture_threat_actor_listing PASSED [100%]
```

### Full Test Suite (57/57 Passed):
```bash
pytest -v backend/tests/
```
```text
======================= 57 passed, 3 warnings in 12.55s =======================
```

### Static Analysis & Type Checking:
- `ruff check .` -> **All checks passed!**
- `mypy backend/app` -> **Success: no issues found in 43 source files**
- `npm run lint` -> **No ESLint warnings or errors**
- `npx tsc --noEmit` -> **Zero TypeScript compilation errors**
- `npm run build` -> **Compiled successfully (Production build ready)**

### E2E System Verification (`python verify_system.py`):
```text
 [PASS] 1. Database & Cryptographic Vault                SQLite WAL Active | 9 Emails, 18 Hops, 9 Analyses, 29 IoCs in DB
 [PASS] 2. Air-Gapped & Offline Resilience               Zero-Guess GeoIP OK | Tor Snapshot Cache OK | DNS 1.5s Timeout Guard OK
 [PASS] 3. E2E Forensic Ingestion & Geo Coordinates      Case UUID: 29b64397... | Score: 94.0/100 | Verdict: BEC | 3 Geolocated Hops
 [PASS] 4. Section 63 BSA 2023 PDF Generation            Size: 6.1 KB | SHA-256: e2d0a6ba023a9438... | %PDF-1.4 Header Validated
 [PASS] 5. Campaign Cross-Incident Graph API             Graph Loaded: 16 Nodes, 15 Edges | Cytoscape / D3 Schema Valid

ALL SUBSYSTEMS VERIFIED & OPERATIONAL (Section 63 BSA 2023 Compliant)
```

