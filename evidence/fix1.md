# Fix 1: Docker Startup & Secrets Configuration

**Scope:** Fix confirmed startup failures and committed secrets in `docker-compose.yml`.  
**Associated Audit Item:** B.5, J.27  

---

## 1. Root Cause & Changes Made

### 1.1 Docker Compose Environment Alignment & Secret Decoupling
- In `docker-compose.yml`, replaced hardcoded credentials (`VAULT_HMAC_SECRET=aicte_sec63...`, `SECRET_KEY=aicte_jwt...`) with `env_file: - .env`.
- Corrected the variable name required by `backend/app/core/config.py`: changed `SECRET_KEY` to `JWT_SECRET_KEY`.
- Ensured zero default fallback secrets exist in `docker-compose.yml`, `backend/Dockerfile`, or `frontend/Dockerfile`.
- Updated `.env.example` to provide placeholders for `VAULT_HMAC_SECRET`, `JWT_SECRET_KEY`, and `NEXT_PUBLIC_API_URL`.

### 1.2 Startup Refusal Test
- Added `test_startup_refusal_when_secrets_missing` in `backend/tests/test_security.py`.
- Asserts that outside `DEBUG` mode, omitting `VAULT_HMAC_SECRET` causes an immediate `RuntimeError` refusing application startup.
- Asserts that providing `VAULT_HMAC_SECRET` but omitting `JWT_SECRET_KEY` outside `DEBUG` causes an immediate `RuntimeError` refusing application startup.
- Asserts that providing valid 32+ character secrets allows clean application startup.

### 1.3 Host Docker Availability & CI Smoke Test
- Host environment check: Docker CLI is not installed locally on this Windows host (`docker: The term 'docker' is not recognized`).
- Rather than falsely claiming local Docker verification, added a dedicated `docker-smoke-test` job in `.github/workflows/ci.yml` that executes on `ubuntu-latest`:
  - Prepares `.env` from `.env.example`.
  - Runs `docker compose up -d --build`.
  - Polls container health check (`curl -f http://localhost:8000/health`) until healthy.
  - Automatically captures logs on failure and tears down containers.

---

## 2. Verification Commands & Raw Output

### 2.1 Startup Refusal Pytest
```text
$ pytest -v backend/tests/test_security.py -k test_startup_refusal_when_secrets_missing
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, asyncio-1.4.1.post1
collected 10 items / 9 deselected / 1 selected

backend/tests/test_security.py::test_startup_refusal_when_secrets_missing PASSED [100%]
======================= 1 passed, 9 deselected in 3.95s =======================
```

### 2.2 Ruff & Mypy Quality Gates
```text
$ ruff check .
All checks passed!

$ mypy backend/app
Success: no issues found in 46 source files
```

### 2.3 Full Pytest Suite
```text
$ pytest -v backend/tests
======================= 74 passed, 3 warnings in 16.80s =======================
```
