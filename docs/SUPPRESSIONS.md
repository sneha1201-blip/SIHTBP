# Approved Static Analysis Suppressions & Exception Handlers

Per Rule R4:
> "Never weaken a test, gate, threshold, or script to make it pass. Never skip/xfail. Never add `# type: ignore`, `# noqa`, or `except: pass` without a logged, justified reason in docs/SUPPRESSIONS.md."

This document serves as the authoritative, audited ledger of all permitted type ignores, lint exemptions, and exception handlers.

---

## 1. Approved Type Ignores (`# type: ignore`)

| File | Line | Code | Reason & Safety Proof | Approved By |
|---|---|---|---|---|
| `backend/app/forensics/auth_validator.py` | 582 | `q.dns_txt = patched_dns_txt  # type: ignore[assignment]` | Third-party library `pyspf` (`spf.query`) declares `dns_txt` method dynamically. Overriding with mock/custom DNS resolution function during hermetic testing requires assignment to the instance method slot. Safe at runtime because `pyspf` dynamically invokes `self.dns_txt`. | Security Lead |

---

## 2. Approved Linter Exemptions (`# noqa`)

*Zero active entries. Codebase enforces strict ruff and flake8 compliance without inline `# noqa` comments.*

---

## 3. Approved Exception Blocks

| File | Line | Exception Type | Justified Behavior | Approved By |
|---|---|---|---|---|
| `backend/app/ai/url_analyzer.py` | 134 | `except ValueError:` | Invalid integer conversion when attempting to parse non-numeric host segments as DWORD/Octal IP literals. The parser falls through to standard hostname evaluation. | Forensics Lead |
| `backend/app/forensics/attachment_analyzer.py` | 74 | `except zipfile.BadZipFile:` | Corrupt or non-standard zip headers in attachments. The analyzer logs the condition and continues scanning subsequent payload structures. | Forensics Lead |
| `backend/app/osint/threat_feeds.py` | 98 | `except Exception:` | Best-effort parsing of diverse threat feed formats during feed synchronization. | OSINT Lead |
