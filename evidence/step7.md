# Evidence Log: STEP 7 - Detection Quality & Adversarial Robustness

**Problem Statement:** AICTE Cyber Security Cell — SIH PS 26106  
**Timestamp:** 2026-11-12T21:07:20+05:30  
**Phase:** STEP 7 (Attachment Forensic Triage, SSRF Protection, Data-Driven Lookalikes, Calibrated AI & Adversarial Tests)

---

## 1. Attachment Security Analysis (`backend/app/forensics/attachment_analyzer.py`)

1. **Microsoft Office OLE Macro Analysis:**
   - Deep inspection using `oletools.olevba` and `olefile`.
   - Identifies presence of VBA macros, auto-execution triggers (`AutoOpen`, `Document_Open`, `Workbook_Open`), and execution API keywords (`Shell`, `WScript`, `PowerShell`, `cmd.exe`).
2. **Double Extension Evasion Detection:**
   - Detects compound filenames concealing executable payloads behind innocent decoy extensions (e.g. `.pdf.exe`, `.xlsx.scr`, `.docx.vbs`).
3. **Archive Nesting & Zip Bomb Anomaly:**
   - Traverses zip archives to discover nested archives (`.zip` inside `.zip`) and concealed binary scripts (`.vbs`, `.ps1`, `.bat`).
   - Flags zip bombs when decompression expansion ratio exceeds safe threshold (`> 100x` expansion ratio or `> 50MB` from tiny archive).
4. **HTML Smuggling & Client-Side Dropper Detection:**
   - Detects base64 application/octet-stream drops, `URL.createObjectURL`, and `msSaveOrOpenBlob` signatures in `.html`, `.htm`, and `.svg` attachments.

---

## 2. URL Analysis & SSRF Protection (`backend/app/ai/url_analyzer.py`)

1. **SSRF Mitigation on Redirect Tracing:**
   - Blocks candidate URLs resolving to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `localhost`, `::1`), link-local, and AWS/Cloud metadata (`169.254.169.254`).
   - Tracing aborts immediately with HTTP 403 SSRF blocked status.
2. **Data-Driven Brand Lookalike Detection:**
   - Decoupled from hardcoded constants; driven by external data configuration file [`backend/app/ai/protected_brands.json`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/backend/app/ai/protected_brands.json) covering key institutional and financial domains (`aicte-india.org`, `gov.in`, `sbi.co.in`, `hdfcbank.com`, `paypal.com`).
   - Flags unauthorized cousin domains and brand squatting (e.g. `aicte-india-login.online`).

---

## 3. Calibrated Scoring, UNCERTAIN State & Adversarial Robustness

1. **Calibrated Scoring & UNCERTAIN State:**
   - Implemented in [`backend/app/ai/threat_scorer.py`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/backend/app/ai/threat_scorer.py).
   - In accordance with calibration directives, when intermediate threat scores (`35.0 <= score <= 50.0`) coincide with low model posterior confidence (`confidence < 0.45`) in the absence of critical overrides, the system assigns `is_uncertain=True` and categorical verdict `UNCERTAIN`.
2. **Adversarial Robustness Evaluation:**
   - **Zero-Width Character Evasion:** Evaluated against zero-width spaces (`\u200b`, `\u200c`, `\u200d`) injected into credential phishing lures; verified the model maintains `PHISHING` intent classification.
   - **Homoglyph Impersonation:** Tested against Cyrillic homoglyphs (`а`, `е`, `о`) matching against protected institutional domains; verified detection and 88.0 critical override.

---

## 4. Test Verification Output

Command:
```powershell
python -m pytest backend/tests/test_ai_detection.py
```

Output:
```
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, hypothesis-6.170.15, asyncio-1.4.1.post1
collected 22 items

backend\tests\test_ai_detection.py ......................                [100%]

============================= 22 passed in 4.20s ==============================
```
