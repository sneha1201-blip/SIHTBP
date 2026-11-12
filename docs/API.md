# REST API & WebSocket Specification

**Platform:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Authority:** AICTE Cyber Security Cell | Smart India Hackathon (Problem Statement ID: 26106)  
**OpenAPI Specification:** Available in machine-readable JSON at [`docs/openapi.json`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/docs/openapi.json)

---

## 1. Authentication & Security Headers

All operational endpoints (except `/health`, `/ready`, `/metrics`, and `/api/v1/auth/login`) require Bearer Token authorization:

```http
Authorization: Bearer <jwt_access_token>
```

### Global Response Security Headers:
- `Content-Security-Policy`: `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';`
- `X-Content-Type-Options`: `nosniff`
- `X-Frame-Options`: `DENY`
- `Strict-Transport-Security`: `max-age=31536000; includeSubDomains`
- `X-Request-ID`: UUIDv4 tracking identifier injected on every request and logged across system traces.

---

## 2. API Endpoints Catalog

### Authentication & User Administration (`/api/v1/auth`)

| Method | Endpoint | Access Role | Description |
|:---|:---|:---|:---|
| `POST` | `/api/v1/auth/login` | Public | Authenticates credentials with Argon2id; returns access token (24h) and refresh token (7d). Enforces account lockout (5 failed attempts / 15m). |
| `POST` | `/api/v1/auth/refresh` | Public | Exchanges a valid refresh token for a fresh access token without re-entering credentials. |
| `GET` | `/api/v1/auth/me` | Authenticated | Retrieves current authenticated user profile, assigned role (`ADMIN`, `ANALYST`, `AUDITOR`), and permissions. |
| `POST` | `/api/v1/auth/register` | `ADMIN` only | Provisions a new analyst or auditor account with role assignment and audit logging. |
| `GET` | `/api/v1/auth/users` | `ADMIN` only | Lists all provisioned platform accounts, lock status, and last login timestamps. |
| `PATCH`| `/api/v1/auth/users/{user_id}/status` | `ADMIN` only | Enables, disables, or unlocks an administrative/analyst account. |

---

### Ingestion & Forensic Processing (`/api/v1/forensics`)

| Method | Endpoint | Access Role | Description |
|:---|:---|:---|:---|
| `POST` | `/api/v1/forensics/analyze` | `ANALYST`, `ADMIN` | Streaming multipart upload of `.eml` / `.msg` file. Enforces 25 MB limit, magic byte validation, dual-hashing, and spawns asynchronous pipeline worker. |
| `GET` | `/api/v1/forensics/jobs/{job_id}` | Authenticated | Polls asynchronous job processing state, stage breakdown, and completion status. |
| `GET` | `/api/v1/forensics/jobs/{job_id}/stream` | Authenticated | Server-Sent Events (SSE) streaming progress endpoint for real-time progress bar animation (`0%` -> `100%`). |
| `GET` | `/api/v1/forensics/evidence/{evidence_id}` | Authenticated | Retrieves comprehensive forensic dossier: composite score, auth results, attachments, and URLs. |
| `GET` | `/api/v1/forensics/evidence/{evidence_id}/raw` | Authenticated | Retrieves original unaltered raw email payload from the cryptographic evidence vault. |
| `GET` | `/api/v1/forensics/evidence/{evidence_id}/hops` | Authenticated | Retrieves parsed RFC 5321 hops with vendor MTA classification, clock skew, and confidence scores. |
| `POST` | `/api/v1/forensics/vault/sweep` | `AUDITOR`, `ADMIN` | Initiates background physical vault integrity sweep, comparing on-disk SHA-256 against database manifests. |
| `GET` | `/api/v1/forensics/audit/verify-chain` | `AUDITOR`, `ADMIN` | Computes SHA-256 hash-chain verification across all audit records and returns cryptographic validity proof. |

---

### Threat Intelligence & Campaigns (`/api/v1/campaigns`)

| Method | Endpoint | Access Role | Description |
|:---|:---|:---|:---|
| `GET` | `/api/v1/campaigns/` | Authenticated | Lists all correlated threat campaigns, sample counts, threat actors, and cluster metrics. |
| `GET` | `/api/v1/campaigns/graph` | Authenticated | Returns Cytoscape/ForceGraph-compatible node-link representation of infrastructure clusters. |
| `GET` | `/api/v1/campaigns/export/stix` | Authenticated | Exports all threat clusters formatted as an OASIS STIX 2.1 JSON Bundle. |
| `GET` | `/api/v1/campaigns/{campaign_id}/stix`| Authenticated | Exports a single targeted campaign as an OASIS STIX 2.1 bundle with threat actor attribution. |
| `PATCH`| `/api/v1/campaigns/{campaign_id}/label`| `ANALYST`, `ADMIN` | Updates campaign label and threat actor tag; appends signed event to immutable audit chain. |
| `POST` | `/api/v1/campaigns/{campaign_id}/merge`| `ANALYST`, `ADMIN` | Merges two correlated campaigns; preserves constituent evidence links and writes audit log. |
| `POST` | `/api/v1/campaigns/{campaign_id}/split`| `ANALYST`, `ADMIN` | Splits selected email nodes into a distinct campaign cluster with analyst justification. |

---

### Court-Admissible Reporting (`/api/v1/forensics/evidence/{evidence_id}/report`)

| Method | Endpoint | Access Role | Description |
|:---|:---|:---|:---|
| `GET` | `/api/v1/forensics/evidence/{evidence_id}/report` | Authenticated | Generates and streams Section 63 BSA 2023 Schedule Certificate PDF with dual SHA-256/SHA-512 hashes. Re-hashes on-disk vault file before rendering (returns `409 Conflict` on tamper). |

---

### System Observability & Probes

| Method | Endpoint | Access Role | Description |
|:---|:---|:---|:---|
| `GET` | `/health` | Public | Liveness probe: returns `{"status": "ok", "app": "SIHTBP Forensic Platform"}`. |
| `GET` | `/ready` | Public | Readiness probe: verifies SQLite/PostgreSQL connection and evidence vault read/write access. Returns 503 if degraded. |
| `GET` | `/metrics` | Public | Prometheus-compatible exposition format exposing pipeline latency, request counts, and error counters. |

---

## 3. Sample API Requests & Responses

### Ingest & Analyze Email (`POST /api/v1/forensics/analyze`)

```bash
curl -X POST "http://localhost:8000/api/v1/forensics/analyze" \
  -H "Authorization: Bearer <TOKEN>" \
  -F "file=@suspicious_wire_transfer.eml"
```

**Response (HTTP 202 Accepted):**
```json
{
  "job_id": "job-8f92b710-d8a2-47ef-b753-9bfa099182bc",
  "status": "QUEUED",
  "evidence_id": "ev-01d8e412-257a-4ec9-b883-fa919c00b21a",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  "stream_url": "/api/v1/forensics/jobs/job-8f92b710-d8a2-47ef-b753-9bfa099182bc/stream"
}
```

### Verify Hash-Chained Audit Ledger (`GET /api/v1/forensics/audit/verify-chain`)

```bash
curl -X GET "http://localhost:8000/api/v1/forensics/audit/verify-chain" \
  -H "Authorization: Bearer <TOKEN>"
```

**Response (HTTP 200 OK):**
```json
{
  "is_chain_valid": true,
  "total_records_verified": 142,
  "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "latest_hash": "a4b2c198f39120e8b209d84c17e6518a209e8f710928374a5b6c7d8e9f012345",
  "tamper_detected_at": null,
  "verification_timestamp": "2026-11-12T21:27:00+05:30"
}
```
