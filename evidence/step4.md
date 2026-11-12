# Evidence Log: STEP 4 - Authentication Depth (SPF, DKIM, DMARC, ARC)

**Problem Statement:** AICTE Cyber Security Cell — SIH PS 26106  
**Timestamp:** 2026-11-12T20:57:00+05:30  
**Phase:** STEP 4 (Cryptographic Protocol Authentication, Multi-Sig Key Rotation, Negative DNS Caching, Confusion Matrix)

---

## 1. Authentication Depth Architecture & Implementation

1. **Multi-Signature DKIM & Key Rotation:**
   - Evaluates all `DKIM-Signature:` headers independently using `dkimpy`.
   - Supports key rotation scenarios where a message carries an older expired or revoked selector signature alongside an active, valid selector signature.
   - Preserves individual signature breakdowns (`dkim_signatures` list) with statuses: `PASS`, `FAIL`, `INVALID`, `EXPIRED`, `KEY_REVOKED`, `KEY_UNAVAILABLE`, `BODY_HASH_MISMATCH`.
   - Satisfies DMARC DKIM alignment if *any* cryptographically valid (`PASS`) signature aligns with the RFC 5322 `From:` domain per RFC 7489 Section 3.1.1.

2. **SPF with Trusted Boundary Connecting IP:**
   - Evaluates SPF via `pyspf` using the connecting IP from the first trustworthy MTA hop outside the administrative domain.
   - Enforces the RFC 7208 10-lookup mechanism limit (returning `PERMERROR` if exceeded).
   - Discernment of private/loopback/link-local RFC 1918 IPs (returning `UNVERIFIABLE`).

3. **DMARC with Public Suffix List (PSL) Alignment:**
   - Discovers DMARC policies at `_dmarc.<domain>` and falls back to organizational domain via `publicsuffix2`.
   - Strict (`aspf=s`, `adkim=s`) and Relaxed (`aspf=r`, `adkim=r`) alignment modes enforced.
   - DMARC alignment is only granted if the underlying protocol cryptographically verified.

4. **ARC Chain Validation (RFC 8617):**
   - Independent verification of `ARC-Seal`, `ARC-Message-Signature`, and `ARC-Authentication-Results`.
   - Traverses multiple instances (`i=1, i=2, ...`) and validates chain integrity across intermediaries.

5. **DNS Resolver: Per-Lookup Timeout, In-Memory Negative Cache, Concurrent Async:**
   - Aggressive per-lookup timeout (`1.5s`) for resilience in high-latency or air-gapped environments.
   - Thread-safe `DNSNegativeCache` storing negative results (`NXDOMAIN`, timeouts) with a 60s TTL and positive results with a 300s TTL.
   - Concurrent async resolution helper (`async_resolve_txt_concurrent`) resolving multiple TXT records concurrently without blocking the async event loop.
   - Cryptographic public key snapshots stored with each evidence artifact for court-admissible Section 63 BSA records.

---

## 2. Confusion Matrices

### Table 4.1: Synthetic / Generated Forensic Corpus (12 Cases)
Ground truth evaluated across SPF, DKIM, DMARC, and Upstream MTA Discrepancy Detection:

| Sample Name | Connecting IP | Expected SPF | Got SPF | Expected DKIM | Got DKIM | Expected DMARC | Got DMARC | Discrepancy Expected | Discrepancy Got | Verdict Match |
|---|---|---|---|---|---|---|---|---|---|---|
| `legit_signed_aicte.eml` | 198.51.100.10 | PASS | PASS | PASS | PASS | PASS | PASS | False | False | **MATCH** |
| `tampered_body.eml` | 198.51.100.10 | PASS | PASS | BODY_HASH_MISMATCH | BODY_HASH_MISMATCH | PASS | PASS | False | False | **MATCH** |
| `tampered_header.eml` | 198.51.100.10 | PASS | PASS | FAIL | FAIL | PASS | PASS | False | False | **MATCH** |
| `stripped_dkim.eml` | 198.51.100.10 | PASS | PASS | NONE | NONE | PASS | PASS | False | False | **MATCH** |
| `wrong_domain_alignment.eml` | 203.0.113.88 | FAIL | FAIL | PASS | PASS | FAIL | FAIL | False | False | **MATCH** |
| `expired_dkim.eml` | 198.51.100.10 | PASS | PASS | EXPIRED | EXPIRED | PASS | PASS | False | False | **MATCH** |
| `revoked_key.eml` | 198.51.100.10 | PASS | PASS | KEY_REVOKED | KEY_REVOKED | PASS | PASS | False | False | **MATCH** |
| `unavailable_key_historical.eml` | 198.51.100.10 | PASS | PASS | KEY_UNAVAILABLE | KEY_UNAVAILABLE | PASS | PASS | False | False | **MATCH** |
| `l_tag_abuse_injected.eml` | 198.51.100.10 | PASS | PASS | PASS | PASS | PASS | PASS | True (l= abuse) | True (l= abuse) | **MATCH** |
| `spf_permerror_lookups.eml` | 198.51.100.99 | PERMERROR | PERMERROR | NONE | NONE | FAIL | FAIL | False | False | **MATCH** |
| `auth_discrepancy_mta_spoof.eml` | 203.0.113.88 | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | True | True | **MATCH** |
| `multi_sig_rotation.eml` | 198.51.100.10 | PASS | PASS | PASS | PASS | PASS | PASS | False | False | **MATCH** |

**Corpus Evaluation Summary:**
- Total Samples: 12
- Correctly Predicted: 12 / 12 (100.0%)
- False Positives: 0
- False Negatives: 0

---

### Table 4.2: Real-World Ingested Corpus (`tests/fixtures/real/`)

| Metric | Value |
|---|---|
| Ingested File Count | 0 |
| Evaluation Status | **`BLOCKED: awaiting user input`** |
| Reason | Zero external `.eml` files supplied in `tests/fixtures/real/`. In accordance with the prompt's integrity directives, synthetic or simulated files are strictly prohibited from masquerading as real signed third-party mail. |
| Ingestion Command | `python scripts/ingest_corpus.py --corpus-dir tests/fixtures/real/` |

---

## 3. Test Verification Command Output

```powershell
python -m pytest backend/tests/test_protocol_auth.py
```

```
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, asyncio-1.4.1.post1
collected 15 items

backend\tests\test_protocol_auth.py ...............                      [100%]

============================= 15 passed in 5.81s ==============================
```

```powershell
python -m pytest
======================= 94 passed, 5 warnings in 26.84s =======================
```
