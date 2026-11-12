# Fix 5: Removal of Demo Residues, Database Seeding Isolation & Corpus Ingestion Tool

**Date:** 2026-11-12  
**Commit:** Pending Fix 5 commit  
**Scope:** Remediation of audit items A.1, A.4, frontend header presets, silent exception handlers, and corpus ingestion CLI.  

---

## 1. Executive Summary & Root Causes Remediated

In the hostile independent audit (`evidence/INDEPENDENT_AUDIT.md`), several demo-mode residues, keyword renames, and silent handlers were identified:
1. **Item A.1 (Grep-gaming & False Parse Claims):** `fallback_ascii_msg_scanner` was previously renamed to `salvage_ascii_msg_scanner` in `backend/app/parsers/msg_parser.py`, while continuing to inject hardcoded dummy recipients (`["forensics-triage@institution.ac.in"]`) and synthetic senders (`"unknown-sender@corrupted.msg"`).
2. **Item A.4 (Database Seeding Isolation):** `backend/app/database/init_db.py` defaulted to `seed=True`, populating 5 synthetic emails on blank database initializations unless `--no-seed` was explicitly remembered.
3. **Frontend Header Presets:** `frontend/src/components/HeaderPasteModal.tsx` contained hardcoded `SAMPLE_BEC_HEADERS` and `SAMPLE_HOMOGRAPH_HEADERS` with "Load BEC Wire Fraud" and "Load Cyrillic Homograph" buttons.
4. **Silent Exception Handlers:** 17 instances of unhandled `except ...: pass` existed across `backend/app/`, including artificial default fallbacks (`roc_auc = 1.0` in `model_trainer.py`).
5. **Corpus Ingestion CLI:** Lack of an authenticated CLI tool to ingest arbitrary directories of `.eml` and `.msg` email artifacts into the forensic platform.

---

## 2. Technical Modifications

### A. Partial Stream Best-Effort Carving (`backend/app/parsers/msg_parser.py`)
- Replaced `salvage_ascii_msg_scanner` with `carve_partial_msg_stream`.
- Removed all synthetic fallback values:
  - `recipient_list`: Set strictly to parsed addresses extracted from the stream (defaults to empty list `[]`, never synthetic triage addresses).
  - `sender_raw` / `sender_email`: Extracted from stream or empty string/None; never `unknown-sender@corrupted.msg`.
  - Added explicit forensic parsing tag: `headers_dict={"X-Forensic-Parsing-Status": ["PARTIAL_PARSE_CORRUPT_OLE_STREAM"]}`.
  - Logs `logger.warning("Corrupted or invalid OLE compound file '%s': executing partial ASCII carving. Forensic status: PARTIAL_PARSE.", filename)`.
- Updated Tier 2 EML parsing to verify extracted metadata before accepting, ensuring corrupt binary OLE files proceed to partial carving instead of silent empty MIME parsing.

### B. Database Seeding Isolation (`backend/app/database/init_db.py` & `run_platform.py`)
- Modified `initialize_and_verify` and `init_db_and_verify` in `backend/app/database/init_db.py`:
  - Default `seed: bool = False`.
  - Added CLI flag `--seed` (default: `False`) for opt-in demonstration/test seeding.
  - Retained `--no-seed` for backward compatibility.
  - Running `python backend/app/database/init_db.py` on a fresh database creates all schemas and foundational RBAC accounts (Admin, Analyst, Auditor) with **0 emails and 0 campaigns**.
- Aligned `run_platform.py` to parse `--seed` and pass `seed=should_seed` into `init_db_and_verify`.

### C. Removal of Header Presets (`frontend/src/components/HeaderPasteModal.tsx`)
- Deleted `SAMPLE_BEC_HEADERS` and `SAMPLE_HOMOGRAPH_HEADERS`.
- Removed preset buttons ("Load BEC Wire Fraud", "Load Cyrillic Homograph").
- Replaced with clean forensic triage guidance banner:
  - "RFC 822 / MIME Header Triage: Paste unedited headers directly from your email client."
- Verified `frontend/src` contains zero matches for `SAMPLE_`.

### D. Silent Exception Handlers Elimination (17/17 Resolved)
Replaced all silent `except ...: pass` occurrences across `backend/app/` with narrowed exceptions and explicit logger invocations:
1. `backend/app/ai/url_analyzer.py` (lines 82, 91, 99): Narrowed to `except (ValueError, OverflowError, OSError) as exc: logger.debug(...)`.
2. `backend/app/database/session.py` (line 108): `except Exception as exc: logger.warning("Failed configuring SQLite pragmas: %s", exc)`.
3. `backend/app/database/vault.py` (lines 196, 204): Narrowed to `except OSError as exc: logger.debug(...)`.
4. `backend/app/forensics/auth_validator.py` (lines 338, 358): Narrowed to `except (ValueError, TypeError) as exc: logger.debug(...)`.
5. `backend/app/forensics/hop_traversal.py` (line 257): Narrowed to `except (TypeError, ValueError, OverflowError) as exc: logger.debug(...)`.
6. `backend/app/forensics/ioc_extractor.py` (lines 92, 126): Replaced with explicit `logger.debug(...)`.
7. `backend/app/forensics/job_queue.py` (line 264): Replaced with `logger.debug("Domain WHOIS lookup skipped or timed out...")`.
8. `backend/app/osint/tor_detector.py` (lines 69, 75, 83, 197, 219): Replaced with descriptive debug logs for CIDR parsing and cache timestamps.
9. `backend/app/osint/whois_client.py` (line 66): Narrowed to `except (ValueError, TypeError) as exc: logger.debug(...)`.
10. `backend/app/ai/model_trainer.py` (line 115): Removed invented `roc_auc = 1.0` fallback on exception; sets `roc_auc = 0.0` and logs warning.
11. `backend/app/reporting/pdf_generator.py` (line 183): Replaced synthetic SHA-256 seal fallback with `vault_hmac = "UNAVAILABLE"` and logs warning.
12. `backend/app/parsers/eml_parser.py` (line 44): Replaced silent date parsing exception with `logger.debug(...)`.

Verified via AST script:
```python
Total silent except pass in backend/app: 0
```

### E. Corpus Ingestion CLI Tool (`scripts/ingest_corpus.py`)
Implemented full-featured CLI and programmatic ingestion module:
- CLI options: `corpus_dir`, `--dir`, `--api-url`, `--username`, `--password`, `--token`, `--sync`, `--recursive`, `--json-out`.
- Performs OAuth2 password grant authentication against `/api/v1/auth/token` to obtain JWT Bearer credentials.
- Discovers and ingests `.eml` and `.msg` files with multipart streaming to `/api/v1/forensics/analyze`.
- Formats and displays an ASCII summary table displaying Case UUID, SHA-256 prefix, Threat Score, and Forensic Verdict.
- Exports optional machine-readable JSON telemetry.
- Exposes `ingest_corpus(...)` function supporting custom test clients for automated testing.

---

## 3. Automated Verification & Test Results

### Pytest Full Suite
```text
$ .venv\Scripts\pytest -q
........................................................................ [ 85%]
............                                                             [100%]
84 passed, 5 warnings in 29.41s
```

### New Tests Added to `backend/tests/test_pipeline.py`:
1. `test_corrupt_msg_partial_carving_no_invented_data`: Verifies corrupt binary OLE streams undergo partial ASCII carving, populate `X-Forensic-Parsing-Status: PARTIAL_PARSE_CORRUPT_OLE_STREAM`, and do NOT invent dummy recipients or synthetic senders.
2. `test_init_db_zero_seed_mode`: Verifies `initialize_and_verify(reset=True, seed=False)` initializes all tables and user accounts while leaving the database with exactly 0 emails and 0 campaigns.
3. `test_corpus_ingestion_cli_helper`: Verifies `scripts/ingest_corpus.py` ingests `.eml` files through the REST API, recording case IDs, SHA-256 digests, and threat scores.

### Static Analysis & Type Checking
```text
$ ruff check .
All checks passed!

$ mypy backend/app
Success: no issues found in 46 source files

$ mypy scripts/ingest_corpus.py
Success: no issues found in 1 source file
```

### Frontend Production Build
```text
$ npm run build
  ▲ Next.js 14.2.18
   Creating an optimized production build ...
 ✓ Compiled successfully
   Linting and checking validity of types ...
   Collecting page data ...
   Generating static pages (5/5)
 ✓ Generating static pages (5/5)
   Finalizing page optimization ...
   Collecting build traces ...

Route (app)                              Size     First Load JS
┌ ○ /                                    18.8 kB         129 kB
├ ○ /_not-found                          873 B          88.2 kB
└ ○ /login                               4.12 kB         114 kB
+ First Load JS shared by all            87.3 kB
```

---

## 4. Audit Checklist Alignment

| Check | Requirement | Result |
|---|---|---|
| **A.1** | Replace `salvage` scanner with documented partial parse; zero dummy recipients | **PASS** |
| **A.4** | Production default `--no-seed`; fresh DB starts with 0 emails | **PASS** |
| **Frontend** | Remove `SAMPLE_` presets and buttons from HeaderPasteModal | **PASS** |
| **Handlers** | Replace 17 silent `except: pass` handlers with narrowed exceptions + logging | **PASS** (0 remaining) |
| **Ingest CLI** | Implement `scripts/ingest_corpus.py` with auth, table display & JSON output | **PASS** |

