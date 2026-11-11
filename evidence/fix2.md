# Fix 2: Forensic PDF Export Vault Integrity & SHA-512 Verification

**Scope:** Prevent certification of corrupted/tampered vault evidence; add SHA-512 and OSINT telemetry to PDF dossiers.  
**Associated Audit Item:** B.9, I.26  

---

## 1. Root Cause & Changes Made

### 1.1 Pre-Export Vault Re-Hashing & 409 Rejection
- In `backend/app/api/v1/endpoints_reports.py`, added mandatory physical evidence verification before invoking PDF generation:
  - Re-reads raw vault bytes from the immutable storage vault (`{sha256}.raw`).
  - Recomputes SHA-256, SHA-512, and MD5 digests.
  - Verifies that computed SHA-256 matches the registered database ground truth.
  - Verifies that computed HMAC-SHA256 seal matches using constant-time comparison (`verify_hmac_signature`).
  - On any mismatch, physical corruption, or missing file:
    - Writes an `INTEGRITY_FAILURE` entry into `EvidenceAuditLog` with `integrity_check=False` and failure details.
    - Aborts immediately with `HTTP 409 Conflict` (`Cryptographic integrity violation! Stored vault evidence hash does not match registered evidence hash`).

### 1.2 PDF Dossier & Certificate Enhancements
- Updated `backend/app/reporting/pdf_generator.py`:
  - Section 1 now records both **SHA-256** and **SHA-512** digests.
  - Relabeled MD5 as `MD5 Digest (Legacy SIEM)` to reflect modern NIST/BSA standards.
  - Added `Forensic Tool Versions`: ReportLab 4.x, dkimpy 1.0.5, pyspf 2.0.14, scikit-learn 1.5.x.
  - Added `OSINT Data Sources` telemetry reporting live Tor cache status/age, GeoIP install state, and RDAP live resolution.
  - Updated Section 63 BSA statutory declaration text to explicitly cite dual SHA-256 and SHA-512 verification.

### 1.3 Automated Verification Test
- Added `test_pdf_report_aborts_with_409_on_vault_tamper` in `backend/tests/test_pipeline.py`:
  - Ingests a valid email and verifies standard PDF export succeeds (HTTP 200).
  - Flips one byte in the physical `.raw` vault file.
  - Asserts `GET /api/v1/forensics/evidence/{id}/report` aborts with `HTTP 409 Conflict`.
  - Asserts an `INTEGRITY_FAILURE` row is appended to the hash-chained audit ledger with `actor="analyst"` and `integrity_check=False`.
  - Restores vault file integrity.

---

## 2. Verification Commands & Raw Output

### 2.1 Vault Tamper Test Execution
```text
$ pytest -v backend/tests/test_pipeline.py -k test_pdf_report_aborts_with_409_on_vault_tamper
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, asyncio-1.4.1.post1
collected 9 items / 8 deselected / 1 selected

backend/tests/test_pipeline.py::test_pdf_report_aborts_with_409_on_vault_tamper PASSED [100%]
================= 1 passed, 8 deselected, 1 warning in 2.25s ==================
```

### 2.2 Ruff & Mypy Quality Gates
```text
$ ruff check .
All checks passed!

$ mypy backend/app
Success: no issues found in 46 source files
```
