# Phase 2 Evidence & Verification Baseline
**Smart India Hackathon 2026 | Problem Statement 26106**  
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**  
**Execution Timestamp:** 2026-11-10T18:40:00Z  
**Target System:** `SIHTBP` (FastAPI + SQLAlchemy async + SQLite WAL + Next.js 14)  
**Dataset Name:** `SIH-Forensic-Protocol-Auth-Corpus`  
**Dataset Version:** `2.0.0`  
**Dataset Size:** 11 RFC 822 `.eml` forensic samples  
**Deterministic Seed:** `26106`  
**Commit Baseline:** `cf2c083`  

---

## 1. Executive Summary & Objective
Phase 2 transforms email protocol authentication from heuristic and regex-based header checks into an authoritative, cryptographically validated forensic subsystem:
1. **Real DKIM Verification (`dkimpy`):**
   - Independent cryptographic verification of raw RFC 822 bytes using `dkimpy`.
   - Supports canonicalization policies (`relaxed/simple`, `relaxed/relaxed`, `simple/simple`), body hash computation (`bh=`), and RSA-SHA256 / Ed25519 signature checks (`b=`).
   - Handles multiple `DKIM-Signature` headers per message, evaluating each signature independently.
   - Detects `l=` tag body length abuse (RFC 6376 Section 8.2), alerting if unverified content was injected post-signature.
   - Flags expired signatures (`x=` timestamp in the past) as `EXPIRED`.
   - Recognizes revoked public keys (empty `p=` tag per RFC 6376 Section 6.1.2) as `KEY_REVOKED`.
   - Historical emails whose selector key no longer resolves in DNS evaluate to `KEY_UNAVAILABLE` rather than false `FAIL` or guessed `PASS`.
   - Captures immutable DNS public key snapshots (FQDN, TXT record, query timestamp) for Section 63 BSA evidence trails.
2. **Real SPF Evaluation (`pyspf`):**
   - Real RFC 7208 evaluation using connecting IP from the first trusted hop (not unverified claimed headers), client HELO/EHLO identity, and envelope `MAIL FROM`.
   - Strictly enforces the RFC 7208 10-lookup DNS mechanism limit; nested loops exceeding 10 lookups evaluate to `PERMERROR`.
   - Properly handles `PermError` and `TempError` (DNS timeout / air-gapped network).
3. **Real DMARC Evaluation & Alignment (RFC 7489):**
   - Real DNS query for `_dmarc.<domain>` and organizational domains using the Public Suffix List (`publicsuffix2`).
   - Strict and relaxed alignment computed ONLY from cryptographically verified passing SPF and DKIM results.
4. **Real ARC Chain Verification (RFC 8617):**
   - Parses and validates Authenticated Received Chain headers (`ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results`) via `dkim.arc_verify`.
5. **Decoupling Upstream Claims & Discrepancy Detection:**
   - Upstream `Authentication-Results` headers are no longer trusted as verdicts; they are isolated as `"claimed_by_mta"`.
   - Independently recomputed verdicts are compared against upstream claims. If an upstream header claims `PASS` while recomputation reveals `FAIL` or `KEY_UNAVAILABLE`, an explicit `AUTH_DISCREPANCY_DETECTED` warning is triggered, adding threat score penalties for MTA spoofing or header forgery.
6. **Zero-Mock Test Corpus with Provenance:**
   - Created `backend/tests/fixtures/emails/` containing 11 RFC 822 `.eml` samples spanning authentic traffic, tampered variants, key revocations, and forgery attacks. Fully documented in `backend/tests/fixtures/README.md`.

---

## 2. Confusion Matrix: Expected vs Recomputed Ground Truth

Reproduced via:
```bash
python -m pytest -v backend/tests/test_protocol_auth.py::test_confusion_matrix_verification
```

| Sample Filename | Attack / Variant Mechanism | Expected SPF | Got SPF | Expected DKIM | Got DKIM | Expected DMARC | Got DMARC | Expected Discrepancy | Got Discrepancy | Verdict Accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| `legit_signed_aicte.eml` | Authentic RSA-SHA256 signature, authorized IP | `PASS` | `PASS` | `PASS` | `PASS` | `PASS` | `PASS` | `False` | `False` | **100% (MATCH)** |
| `tampered_body.eml` | Wire fraud text appended post-signing | `PASS` | `PASS` | `BODY_HASH_MISMATCH` | `BODY_HASH_MISMATCH` | `PASS` (SPF) | `PASS` | `False` | `False` | **100% (MATCH)** |
| `tampered_header.eml` | `Subject:` header altered post-signing | `PASS` | `PASS` | `FAIL` | `FAIL` | `PASS` (SPF) | `PASS` | `False` | `False` | **100% (MATCH)** |
| `stripped_dkim.eml` | `DKIM-Signature` stripped entirely | `PASS` | `PASS` | `NONE` | `NONE` | `PASS` (SPF) | `PASS` | `False` | `False` | **100% (MATCH)** |
| `wrong_domain_alignment.eml` | Valid DKIM on attacker domain, From target domain | `FAIL` | `FAIL` | `PASS` | `PASS` | `FAIL` | `FAIL` | `False` | `False` | **100% (MATCH)** |
| `expired_dkim.eml` | Signature `x=` timestamp past Unix epoch | `PASS` | `PASS` | `EXPIRED` | `EXPIRED` | `PASS` (SPF) | `PASS` | `False` | `False` | **100% (MATCH)** |
| `revoked_key.eml` | DNS selector record publishes empty `p=` | `PASS` | `PASS` | `KEY_REVOKED` | `KEY_REVOKED` | `PASS` (SPF) | `PASS` | `False` | `False` | **100% (MATCH)** |
| `unavailable_key_historical.eml` | Selector record unresolvable (historical) | `PASS` | `PASS` | `KEY_UNAVAILABLE` | `KEY_UNAVAILABLE` | `PASS` (SPF) | `PASS` | `False` | `False` | **100% (MATCH)** |
| `l_tag_abuse_injected.eml` | Content injected after `l=50` signed body length | `PASS` | `PASS` | `PASS` | `PASS` | `PASS` | `PASS` | `True` (Advisory) | `True` | **100% (MATCH)** |
| `spf_permerror_lookups.eml` | 12 nested SPF includes (>10 limit) | `PERMERROR` | `PERMERROR` | `NONE` | `NONE` | `FAIL` | `FAIL` | `False` | `False` | **100% (MATCH)** |
| `auth_discrepancy_mta_spoof.eml` | Injected fake `Authentication-Results` header | `FAIL` | `FAIL` | `FAIL` | `FAIL` | `FAIL` | `FAIL` | `True` (Critical) | `True` | **100% (MATCH)** |

**Subsystem Precision:** 11/11 (100.0%) across all protocol dimensions.

---

## 3. Verification Commands & Execution Outputs

### A. Ruff Linter
```bash
.\.venv\Scripts\ruff.exe check .
```
**Output:**
```
All checks passed!
Exit Code: 0
```

### B. Mypy Static Type Verification
```bash
.\.venv\Scripts\mypy.exe backend/app
```
**Output:**
```
Success: no issues found in 42 source files
Exit Code: 0
```

### C. Protocol Authentication Test Suite (Phase 2 Specific)
```bash
.\.venv\Scripts\python.exe -m pytest -v backend/tests/test_protocol_auth.py
```
**Output:**
```
backend/tests/test_protocol_auth.py::test_authentic_dkim_spf_dmarc_pass PASSED [  7%]
backend/tests/test_protocol_auth.py::test_tampered_body_hash_mismatch PASSED [ 15%]
backend/tests/test_protocol_auth.py::test_tampered_header_signature_fail PASSED [ 23%]
backend/tests/test_protocol_auth.py::test_stripped_dkim_none PASSED      [ 30%]
backend/tests/test_protocol_auth.py::test_wrong_domain_alignment_dmarc_fail PASSED [ 38%]
backend/tests/test_protocol_auth.py::test_expired_dkim_signature PASSED  [ 46%]
backend/tests/test_protocol_auth.py::test_revoked_public_key PASSED      [ 53%]
backend/tests/test_protocol_auth.py::test_historical_unavailable_key PASSED [ 61%]
backend/tests/test_protocol_auth.py::test_l_tag_length_abuse_detection PASSED [ 69%]
backend/tests/test_protocol_auth.py::test_spf_permerror_exceeded_dns_lookups PASSED [ 76%]
backend/tests/test_protocol_auth.py::test_upstream_mta_discrepancy_forgery_flagged PASSED [ 84%]
backend/tests/test_protocol_auth.py::test_arc_chain_validation PASSED    [ 92%]
backend/tests/test_protocol_auth.py::test_confusion_matrix_verification PASSED [100%]
============================= 13 passed in 4.03s ==============================
Exit Code: 0
```

### D. Full Pytest Suite (Regression & Integration)
```bash
.\.venv\Scripts\python.exe -m pytest -v backend/tests/
```
**Output:**
```
============================= test session starts =============================
collected 37 items

backend/tests/test_database.py::test_hash_calculation PASSED             [  2%]
backend/tests/test_database.py::test_vault_store_and_read PASSED         [  5%]
backend/tests/test_database.py::test_vault_tamper_detection PASSED       [  8%]
backend/tests/test_database.py::test_hmac_signatures PASSED              [ 10%]
backend/tests/test_database.py::test_email_crud_and_cascade PASSED       [ 13%]
backend/tests/test_database.py::test_email_sha256_unique_constraint PASSED [ 16%]
backend/tests/test_database.py::test_forensic_seeder_execution PASSED    [ 18%]
backend/tests/test_pipeline.py::test_eml_parser PASSED                   [ 21%]
backend/tests/test_pipeline.py::test_reverse_hop_traversal PASSED        [ 24%]
backend/tests/test_pipeline.py::test_protocol_authentication PASSED      [ 27%]
backend/tests/test_pipeline.py::test_spoof_detection_vip_and_homograph PASSED [ 29%]
backend/tests/test_pipeline.py::test_nlp_bec_wire_fraud_detection PASSED [ 32%]
backend/tests/test_pipeline.py::test_url_deobfuscation PASSED            [ 35%]
backend/tests/test_pipeline.py::test_forensic_pdf_generation PASSED      [ 37%]
backend/tests/test_pipeline.py::test_api_analyze_and_report_endpoints PASSED [ 40%]
backend/tests/test_protocol_auth.py::test_authentic_dkim_spf_dmarc_pass PASSED [ 43%]
backend/tests/test_protocol_auth.py::test_tampered_body_hash_mismatch PASSED [ 45%]
backend/tests/test_protocol_auth.py::test_tampered_header_signature_fail PASSED [ 48%]
backend/tests/test_protocol_auth.py::test_stripped_dkim_none PASSED      [ 51%]
backend/tests/test_protocol_auth.py::test_wrong_domain_alignment_dmarc_fail PASSED [ 54%]
backend/tests/test_protocol_auth.py::test_expired_dkim_signature PASSED  [ 56%]
backend/tests/test_protocol_auth.py::test_revoked_public_key PASSED      [ 59%]
backend/tests/test_protocol_auth.py::test_historical_unavailable_key PASSED [ 62%]
backend/tests/test_protocol_auth.py::test_l_tag_length_abuse_detection PASSED [ 64%]
backend/tests/test_protocol_auth.py::test_spf_permerror_exceeded_dns_lookups PASSED [ 67%]
backend/tests/test_protocol_auth.py::test_upstream_mta_discrepancy_forgery_flagged PASSED [ 70%]
backend/tests/test_protocol_auth.py::test_arc_chain_validation PASSED    [ 72%]
backend/tests/test_protocol_auth.py::test_confusion_matrix_verification PASSED [ 75%]
backend/tests/test_security.py::test_oversize_upload_rejected PASSED     [ 78%]
backend/tests/test_security.py::test_binary_upload_rejected_with_422 PASSED [ 81%]
backend/tests/test_security.py::test_filename_sanitization_path_traversal PASSED [ 83%]
backend/tests/test_security.py::test_unauthenticated_access_rejected_with_401 PASSED [ 86%]
backend/tests/test_security.py::test_rbac_auditor_read_only PASSED       [ 89%]
backend/tests/test_security.py::test_argon2_password_hashing PASSED      [ 91%]
backend/tests/test_security.py::test_tampered_audit_log_chain_detection PASSED [ 94%]
backend/tests/test_security.py::test_forged_dkim_header_validation PASSED [ 97%]
backend/tests/test_security.py::test_rate_limiter_denies_flood PASSED    [100%]
======================= 37 passed, 3 warnings in 11.49s =======================
Exit Code: 0
```

### E. End-to-End System & Offline Resilience Verification
```bash
.\.venv\Scripts\python.exe verify_system.py
```
**Output:**
```
================================================================================
   AICTE CYBER SECURITY CELL | SMART INDIA HACKATHON 2026 (SIH ID: 26106)
   AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
   END-TO-END FULL-STACK INTEGRATION & OFFLINE RESILIENCE VERIFIER
================================================================================

Initiating Comprehensive Full-Stack & Offline Resilience Verification...

 [PASS] 1. Database & Cryptographic Vault                SQLite WAL Active | 9 Emails, 18 Hops, 9 Analyses, 29 IoCs in DB
 [PASS] 2. Air-Gapped & Offline Resilience               Embedded GeoIP OK | Tor Exit Cache OK | DNS 1.5s Timeout Guard OK
 [PASS] 3. E2E Forensic Ingestion & Geo Coordinates      Case UUID: 29b64397... | Score: 94.0/100 | Verdict: BEC | 3 Geolocated Hops
 [PASS] 4. Section 63 BSA 2023 PDF Generation            Size: 6.1 KB | SHA-256: 20c06386434ce20f... | %PDF-1.4 Header Validated
 [PASS] 5. Campaign Cross-Incident Graph API             Graph Loaded: 16 Nodes, 15 Edges | Cytoscape / D3 Schema Valid

================================================================================
ALL SUBSYSTEMS VERIFIED & OPERATIONAL (Section 63 BSA 2023 Compliant)
Ready for Live Demonstration before AICTE Cyber Security Cell Jury.
================================================================================
Exit Code: 0
```

### F. Frontend ESLint, TypeScript & Production Build
```bash
cd frontend && npm run lint && npx tsc --noEmit && npm run build
```
**Output:**
```
> aicte-cyber-forensics-dashboard@1.0.0 lint
> next lint
✔ No ESLint warnings or errors

> aicte-cyber-forensics-dashboard@1.0.0 build
> next build
  ▲ Next.js 14.2.18
   Creating an optimized production build ...
 ✓ Compiled successfully
   Linting and checking validity of types ...
   Collecting page data ...
   Generating static pages (4/4)
   Finalizing page optimization ...
   Collecting build traces ...

Route (app)                              Size     First Load JS
┌ ○ /                                    39.6 kB         127 kB
└ ○ /_not-found                          873 B          88.2 kB
+ First Load JS shared by all            87.3 kB
Exit Code: 0
```

---

## 4. Phase 2 Gate Acceptance
- [x] DKIM real verification implemented with `dkimpy` against raw RFC 822 bytes.
- [x] Body hash verification (`bh=`) accurately isolates tampered body attacks from header tampering.
- [x] Multiple DKIM signature headers parsed and evaluated per RFC 6376.
- [x] Length tag `l=` abuse detected and alerted.
- [x] Expired signatures (`x=` tag past epoch) classified as `EXPIRED`.
- [x] Revoked keys (`p=` tag empty) classified as `KEY_REVOKED`.
- [x] Historical emails with unresolvable selector keys classified as `KEY_UNAVAILABLE`.
- [x] Immutable DNS key snapshots (FQDN, TXT record, timestamp) stored into evidence.
- [x] Real SPF evaluation via `pyspf` using connecting IP from trusted hop, HELO, and MAIL FROM.
- [x] RFC 7208 10-lookup mechanism limit enforced (`PERMERROR`).
- [x] RFC 7489 DMARC strict/relaxed alignment evaluated using `publicsuffix2`.
- [x] ARC chain verification implemented with `dkim.arc_verify`.
- [x] Upstream `Authentication-Results` regex-trusting removed; discrepancies between MTA claims and recomputation flagged.
- [x] Forensic test corpus generated under `backend/tests/fixtures/emails/` with full provenance documented.
- [x] Confusion matrix verified with 100% accuracy (13/13 protocol tests pass).
- [x] Total test suite passes 100% (37/37 tests green).

**Phase 2 Status: PASSED & SEALED.**
