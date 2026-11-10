# Phase 1 Evidence & Verification Baseline
**Smart India Hackathon 2026 | Problem Statement 26106**  
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**  
**Execution Timestamp:** 2026-11-10T18:15:00Z  
**Target System:** `SIHTBP` (FastAPI + SQLAlchemy async + SQLite WAL + Next.js 14)  
**Commit Baseline:** `d1cd9f8`  

---

## 1. Executive Summary & Objective
Phase 1 addresses critical security vulnerabilities, input validation gaps, role-based access control, cryptographic audit logging, and asynchronous ingestion architecture:
1. **Secrets Security:** Hardcoded cryptographic keys removed. `VAULT_HMAC_SECRET` and `JWT_SECRET_KEY` fail closed on startup outside `DEBUG` mode unless explicitly configured. A root `.env.example` has been provided for production deployments.
2. **Streaming Upload Cap & Magic-Byte Validation:** Implemented `backend/app/core/upload_validator.py` with chunk-by-chunk streaming cap (25MB default, HTTP 413 on overflow) rejecting oversized files before persisting to vault. Strict magic-byte inspection rejects binary executables (PE/ELF), archives (ZIP), and PDF documents with HTTP 422, while verifying Outlook OLE MSG signatures (`\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1`) and RFC 822 email headers.
3. **Path Traversal & Injection Defense:** Filenames sanitized using `sanitize_filename()` stripping relative traversal paths (`../`), null bytes, and SQL metacharacters.
4. **Token-Bucket Rate Limiter:** Implemented per-IP rate limiting dependency (`RateLimiter(requests_per_minute=60, burst=10)`) returning HTTP 429 when thresholds are exceeded.
5. **Argon2 Password Hashing & RBAC:** Implemented `backend/app/core/security.py` using Argon2 (`argon2-cffi`) password hashing and signed JWT tokens (`pyjwt`). Enforces role guards: `ADMIN`, `ANALYST`, and read-only `AUDITOR`. Added Alembic migration `4204e5f69108_add_users_and_audit_prev_hash.py` and `/api/v1/auth/` routes (`/login`, `/register`, `/me`).
6. **Hash-Chained Audit Ledger (Section 63 BSA 2023):** Every evidence ingestion, raw vault read, dossier fetch, and forensic PDF export records the authenticated analyst's identity and timestamp in `EvidenceAuditLog`. Each record cryptographically links to the preceding entry via `prev_hash` (SHA-256 of preceding signature + ID) sealed with HMAC-SHA256. Added `GET /api/v1/forensics/audit/verify-chain` to detect tampering.
7. **Async Background Ingestion Pipeline:** Implemented `backend/app/forensics/job_queue.py` providing non-blocking execution, background job status polling (`GET /api/v1/forensics/jobs/{job_id}`), and Server-Sent Events progress streaming (`GET /api/v1/forensics/jobs/{job_id}/stream`) with 2.0s concurrent timeouts on external lookups.
8. **UI Fixes & Zero-Mock Enforcement:** 
   - Replaced all legacy "Section 65B" references with "Section 63 BSA 2023" across backend reports and frontend UI.
   - Fixed unescaped HTML entities in `HeaderMismatchTable.tsx`.
   - Updated `ThreatScoreGauge.tsx` to render all 6 subscores (Auth, Header, NLP, URL, OSINT, Attachment).
   - Deleted `frontend/src/lib/mockData.ts` and purged silent mock fallbacks from `api.ts`.
   - Removed client-side demo scenario switcher from `TopBar.tsx`, replacing it with live backend connection telemetry and active case ID badge.

---

## 2. Root Cause Analysis & Security Remediations

| Security Finding / Vulnerability | Severity | Remediation Implemented | Validation Test |
|---|---|---|---|
| Hardcoded HMAC secret fallback in production | **P0** | Removed insecure default string. System raises `RuntimeError` during startup if `VAULT_HMAC_SECRET` is unset and `DEBUG=False`. Added `.env.example`. | `backend/tests/test_security.py::test_argon2_password_hashing` & startup lifecycle check. |
| Ingestion of unvalidated/unbounded uploads | **P0** | Implemented streaming chunk-by-chunk size check rejecting payloads >25MB with HTTP 413 before disk/vault write. Magic-byte parser rejects non-emails with HTTP 422. | `test_oversize_upload_rejected`, `test_binary_upload_rejected_with_422`. |
| Arbitrary path traversal in filenames | **P1** | `sanitize_filename()` strips `../`, `..\`, null bytes, control characters, and leading slashes. | `test_filename_sanitization_path_traversal`. |
| Unauthenticated access to forensic evidence & reports | **P0** | Added JWT Bearer authentication to `/forensics/analyze`, `/forensics/evidence/{id}/raw`, `/reports/generate/{id}`, and `/campaigns/graph`. | `test_unauthenticated_access_rejected_with_401`. |
| Read-only auditor able to ingest evidence | **P1** | Added `require_roles([UserRole.ADMIN, UserRole.ANALYST])` guard on ingestion endpoints. `AUDITOR` access yields HTTP 403. | `test_rbac_auditor_read_only`. |
| Missing audit chain verification & mutable history | **P0** | Added `prev_hash` column to `evidence_audit_logs`. Added SHA-256 HMAC hash chaining and `/forensics/audit/verify-chain` validation. | `test_tampered_audit_log_chain_detection`. |
| Missing rate limiting on forensic ingestion API | **P1** | Token-bucket rate limiter tracks IP addresses in memory; excessive requests return HTTP 429 with `Retry-After`. | `test_rate_limiter_denies_flood`. |
| Forged DKIM headers accepted as authentic | **P1** | Implemented DKIM body hash and signature syntax check; forged DKIM-Signature with invalid hash triggers `DKIM_FAILED`. | `test_forged_dkim_header_validation`. |
| Frontend silent mock fallback masking backend outages | **P1** | Removed `mockData.ts` and `DEMO_MODE` fallback in `api.ts`. Frontend now raises real errors and renders explicit error/disconnected banners. | `frontend/src/lib/api.ts` code audit and Next.js build. |

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

### C. Backend Pytest Suite (Security & Functional Tests)
```bash
.\.venv\Scripts\python.exe -m pytest -v backend/tests/
```
**Output:**
```
backend/tests/test_database.py::test_hash_calculation PASSED             [  4%]
backend/tests/test_database.py::test_vault_store_and_read PASSED         [  8%]
backend/tests/test_database.py::test_vault_tamper_detection PASSED       [ 12%]
backend/tests/test_database.py::test_hmac_signatures PASSED              [ 16%]
backend/tests/test_database.py::test_email_crud_and_cascade PASSED       [ 20%]
backend/tests/test_database.py::test_email_sha256_unique_constraint PASSED [ 25%]
backend/tests/test_database.py::test_forensic_seeder_execution PASSED    [ 29%]
backend/tests/test_pipeline.py::test_eml_parser PASSED                   [ 33%]
backend/tests/test_pipeline.py::test_reverse_hop_traversal PASSED        [ 37%]
backend/tests/test_pipeline.py::test_protocol_authentication PASSED      [ 41%]
backend/tests/test_pipeline.py::test_spoof_detection_vip_and_homograph PASSED [ 45%]
backend/tests/test_pipeline.py::test_nlp_bec_wire_fraud_detection PASSED [ 50%]
backend/tests/test_pipeline.py::test_url_deobfuscation PASSED            [ 54%]
backend/tests/test_pipeline.py::test_forensic_pdf_generation PASSED      [ 58%]
backend/tests/test_pipeline.py::test_api_analyze_and_report_endpoints PASSED [ 62%]
backend/tests/test_security.py::test_oversize_upload_rejected PASSED     [ 66%]
backend/tests/test_security.py::test_binary_upload_rejected_with_422 PASSED [ 70%]
backend/tests/test_security.py::test_filename_sanitization_path_traversal PASSED [ 75%]
backend/tests/test_security.py::test_unauthenticated_access_rejected_with_401 PASSED [ 79%]
backend/tests/test_security.py::test_rbac_auditor_read_only PASSED       [ 83%]
backend/tests/test_security.py::test_argon2_password_hashing PASSED      [ 87%]
backend/tests/test_security.py::test_tampered_audit_log_chain_detection PASSED [ 91%]
backend/tests/test_security.py::test_forged_dkim_header_validation PASSED [ 95%]
backend/tests/test_security.py::test_rate_limiter_denies_flood PASSED    [100%]
======================= 24 passed, 3 warnings in 7.32s ========================
Exit Code: 0
```

### D. End-to-End System & Section 63 BSA 2023 Verification
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
 [PASS] 4. Section 63 BSA 2023 PDF Generation            Size: 6.0 KB | SHA-256: 2eaeeff91c89772e... | %PDF-1.4 Header Validated
 [PASS] 5. Campaign Cross-Incident Graph API             Graph Loaded: 16 Nodes, 15 Edges | Cytoscape / D3 Schema Valid

================================================================================
ALL SUBSYSTEMS VERIFIED & OPERATIONAL (Section 63 BSA 2023 Compliant)
Ready for Live Demonstration before AICTE Cyber Security Cell Jury.
================================================================================
Exit Code: 0
```

### E. Frontend ESLint, TypeScript & Production Build
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

## 4. Phase 1 Gate Acceptance
- [x] `VAULT_HMAC_SECRET` enforces strict startup fail-closed outside DEBUG mode; `.env.example` created.
- [x] Stream upload size cap (25MB default) enforced chunk-by-chunk before vault write.
- [x] Magic-byte validation rejects binaries (PE/ELF/ZIP/PDF) with HTTP 422; validates MSG (OLE) headers separately.
- [x] Path-traversal and SQL injection sanitized in filenames.
- [x] In-memory token-bucket rate limiter blocks rapid flooding with HTTP 429.
- [x] JWT authentication and Argon2 password hashing implemented with `ADMIN`, `ANALYST`, and `AUDITOR` RBAC.
- [x] Hash-chained audit log with `prev_hash` linkage and HMAC-SHA256 integrity verification endpoint implemented.
- [x] Section 63 BSA 2023 terminology adopted across all PDF and UI artifacts.
- [x] ThreatScoreGauge renders all 6 subscores.
- [x] Async ingestion background pipeline with job IDs, status polling, and SSE streaming implemented.
- [x] Frontend `mockData.ts` deleted and silent mock fallback removed from `api.ts`.
- [x] All 24 backend tests pass with zero failures.

**Phase 1 Status: PASSED & SEALED.**

