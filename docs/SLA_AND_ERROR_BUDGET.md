# Service Level Agreement (SLA) & Error Budget

**Platform:** AICTE Cyber Security Cell Forensic Email Platform  
**Target Availability:** 99.9% Uptime (Three Nines)  
**Problem Statement ID:** 26106  

---

## 1. Service Level Objectives (SLOs)

| Metric | Target | Measurement Method |
| :--- | :--- | :--- |
| **Availability** | $\ge 99.9\%$ monthly uptime | Ratio of successful HTTP 2xx/3xx/4xx requests to total requests (excluding 5xx server errors). |
| **P95 Ingestion Latency** | $\le 3,500\text{ ms}$ | Time from upload receipt to completed dossier generation, including DNS authentication checks. |
| **P50 Ingestion Latency** | $\le 1,200\text{ ms}$ | Steady-state median end-to-end processing. |
| **Vault Write Reliability** | $100\%$ zero-loss | Physical `fsync` on every raw file write; dual-hash verification before database commit. |
| **Audit Verification** | $100\%$ tamper detection | Any break in the cryptographic hash chain triggers an immediate operational alert. |

---

## 2. Monthly Error Budget

At 99.9% availability:
- **Allowable Unplanned Downtime**: $43\text{ minutes and }49\text{ seconds}$ per 30-day month.
- **Error Budget Consumption**:
  - Unhandled 500 Internal Server Errors consume the error budget.
  - Expected client errors (400 Bad Request, 401 Unauthorized, 403 Forbidden, 413 Payload Too Large, 422 Unprocessable Content, 429 Too Many Requests) **do not** consume the error budget.

---

## 3. Health & Observability Endpoints

- **Liveness Probe**: `GET /health` returns HTTP 200 with platform build metadata.
- **Readiness Probe**: `GET /ready` actively tests database queries, physical vault directory write access, and AI model pipeline initialization.
- **Metrics**: `GET /metrics` exports real-time Prometheus telemetry counters (`forensic_emails_total`, `forensic_audit_records_total`, `forensic_vault_files_total`).
