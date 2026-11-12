# Evidence Log: STEP 9 - Reporting & Section 63 BSA Legal Admissibility

**Problem Statement:** AICTE Cyber Security Cell — SIH PS 26106  
**Timestamp:** 2026-11-12T21:16:20+05:30  
**Phase:** STEP 9 (Section 63 BSA Certificate, Dual/Triple Hashing, Export-Time Vault Re-Hashing, Offline Verification)

---

## 1. Statutory Alignment: Section 63 BSA 2023 Schedule Certificate

The PDF generator in [`backend/app/reporting/pdf_generator.py`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/backend/app/reporting/pdf_generator.py) strictly partitions automated system parameters from mandatory human legal declarations:

1. **Part A (Automated Technical Certification):**
   - Output produced continuously during ordinary course of lawful activities.
   - Dual-hash SHA-256 and SHA-512 cryptographic digests + MD5 legacy SIEM label.
   - Exact physical file size in bytes, server OS profile, and tool versions (Python 3.12, ReportLab 4.x, dkimpy 1.0.5, pyspf 2.0.14, scikit-learn 1.5.x).
   - Ingestion and report timestamps normalized to UTC.
2. **Part B (Human Custody Attestation):**
   - Mandatory signature and designation block for the authorized examiner/officer in lawful charge of the computer system.
   - Statutory notice: Unknown fields marked `[NEEDS LEGAL REVIEW]` in running footer and legal attestation block.
3. **Running Security Canvas:**
   - Running header with `SIH ID: 26106` and evidence SHA-256 watermark.
   - Running footer: `"CONFIDENTIAL - SEC 63 BSA 2023 CERTIFICATE | UNKNOWN FIELDS MARKED NEEDS LEGAL REVIEW"`.

---

## 2. Vault Re-Hashing & Export-Time Tamper Guard

1. **Physical Disk Verification at Export:**
   - At the instant of PDF generation, `export_forensic_dossier_pdf` loads the physical `.raw` vault file from disk, recalculates its SHA-256 and SHA-512 digests, and verifies them against the database record.
   - If a single bit differs, export immediately aborts with `HTTP 409 Conflict`, logs `INTEGRITY_FAILURE` to the hash-chained audit ledger, and prevents court submission of corrupted records.
2. **Chain-of-Custody Table:**
   - Populated directly from `EvidenceAuditLog` ledger entries showing step-by-step actions (`VAULT_SEALED`, `INTEGRITY_VERIFIED`, `EXPORTED`), examiner IDs, HMAC seals, and cryptographic link to `prev_hash`.

---

## 3. Offline Independent Verification Script (`scripts/verify_report.py`)

Provides offline proof for judicial examiners and defense counsel without requiring database or server connectivity:
- Recalculates physical SHA-256 and SHA-512 digests.
- Verifies HMAC signature with secret.
- Exits with return code 0 on verified match, code 1 on tamper.

---

## 4. Test Verification Output

Command:
```powershell
python -m pytest backend/tests/test_pipeline.py -k "offline_verify or tamper"
```

Output:
```
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, hypothesis-6.170.15, asyncio-1.4.1.post1
collected 14 items / 12 deselected / 2 selected

backend\tests\test_pipeline.py ..                                        [100%]

======================= 2 passed, 12 deselected in 1.48s =======================
```

Full Test Suite:
```powershell
python -m pytest backend/tests/test_pipeline.py
======================= 14 passed, 3 warnings in 13.66s =======================
```
