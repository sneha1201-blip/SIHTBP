# Host Security Scanner Availability Status
**Audit Timestamp:** 2026-11-13T01:14:00+00:00  
**Environment:** Windows 11 Enterprise (Local Development Runner)

---

## Scanner Status Inventory

| Scanner Tool | Purpose | Host Status | Resolution / Action Required |
|:---|:---|:---:|:---|
| **Bandit** | Python AST Static Application Security Testing | **INSTALLED & VERIFIED** | Executed in virtualenv (`.venv/Scripts/bandit.exe`). 0 High/Critical findings. |
| **pip-audit** | PyPI Dependency Vulnerability Scanner | **INSTALLED & VERIFIED** | Executed in virtualenv (`.venv/Scripts/pip-audit.exe`). 0 vulnerabilities. |
| **CycloneDX** | CycloneDX 1.6 JSON SBOM Generator | **INSTALLED & VERIFIED** | Executed via `cyclonedx-py`. Generates standard SBOM (`evidence/security/sbom.json`). |
| **npm audit** | Node.js Dependency Scanner | **INSTALLED & VERIFIED** | Executed in `frontend/`. 11 findings triaged in `evidence/security/npm_audit_triage.md`. |
| **gitleaks** | Git Repository Secret / Credential Leak Scanner | **BLOCKED: NOT INSTALLED** | Binary `gitleaks` not found on system PATH. Install via `winget install gitleaks` or CI Action. |
| **trivy** | Container Image & Filesystem Vulnerability Scanner | **BLOCKED: NOT INSTALLED** | Binary `trivy` not found on system PATH. Install via `winget install aquasecurity.trivy` or CI Action. |

---

## Rule R3 Compliance Note
Because `gitleaks` and `trivy` are external host tools not installed in this execution environment, sub-check `host_scanners` is marked **BLOCKED: awaiting host scanner binaries**.
Per Rule R3, Gate G03 must report **BLOCKED** until these scanners are run or provisioned in CI.
