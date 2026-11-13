# Forensic Ingestion Queue Architecture: In-Process vs. Redis RQ/Celery Trade-Off Analysis

**Smart India Hackathon 2026 | Problem Statement ID: 26106**  
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**  
**Statutory Framework: Section 63 Bharatiya Sakshya Adhiniyam, 2023 (BSA)**

---

## 1. Architectural Overview

The platform processes email files (`.eml`, `.msg`) through a multi-stage forensic analysis pipeline:
1. **Intake & Cryptographic Vault Storage** (Dual SHA-256 + SHA-512 WORM hashing)
2. **MIME / RFC 5322 Normalization** (simhash, attachment carving, header extraction)
3. **Hop Traversal & OSINT Geolocation** (Reverse MTA parsing, MaxMind GeoLite2, ASN, Tor exit nodes)
4. **Protocol Authentication** (DKIM RSA/Ed25519, SPF, DMARC alignment, ARC validation)
5. **Brand Impersonation & Spoof Detection** (IDN homoglyph, display spoofing, Levenshtein distance)
6. **Multi-Class Threat Classification & Calibration** (TF-IDF + Calibrated Logistic Regression, Platt sigmoid)
7. **Multi-Signal Threat Campaign Correlation** (ARI/NMI clustering, STIX 2.1 intelligence bundle generation)
8. **Statutory Admissibility Reporting** (Section 63 BSA Part A/B PDF generation, hash-chained audit logging)

Because stages 3 and 4 involve concurrent DNS and network OSINT queries, and stage 6/7 perform CPU-bound token analysis, forensic jobs are decoupled from synchronous HTTP request/response loops.

---

## 2. Queue Model Comparison: In-Process vs. Distributed Redis Queue

| Dimension | In-Process Async Worker Queue (`backend/app/forensics/job_queue.py`) | Distributed Redis Queue (Celery / RQ / Arq) |
|---|---|---|
| **Architecture** | Native Python `asyncio` task queue within the FastAPI process worker. | External Redis broker with separate worker processes / containers. |
| **Operational Footprint** | **Zero external dependencies.** Runs on standalone workstations, field laptops, and air-gapped forensic VMs. | Requires active Redis server daemon and container orchestration (Docker/Kubernetes). |
| **Concurrency Model** | Cooperative async I/O (`asyncio.gather`) with bounded semaphore concurrency (`asyncio.Semaphore(10)`). | Multi-process worker pool (`prefork` or `gevent`/`asyncio` worker threads). |
| **Memory Isolation** | Shared process memory space. Memory leaks in third-party parsers affect the main process. | Process isolation per worker; crashing workers do not compromise the web API. |
| **State Persistence** | Job metadata stored in memory with database checkpointing (`backend/app/database/models.py`). | Persistent task state in Redis broker with pub/sub and Redis stream persistence. |
| **Real-Time Client Telemetry** | Server-Sent Events (SSE) `/api/v1/jobs/{job_id}/events` stream stage progress directly from memory. | SSE or WebSocket proxy querying Redis pub/sub channel. |
| **Dead-Letter Handling (DLQ)** | On fatal pipeline exception, job transitions to `FAILED`, persists error traceback in DB, and generates an audit record. | Automatic dead-letter queue routing with exponential backoff retries. |
| **Statutory Custody & Timing** | Zero network transmission of raw evidence bytes between servers; intake occurs locally on physical disk. | Raw evidence bytes or vault paths must be shared via shared volume (NFS/EFS) or object store. |

---

## 3. Production Deployment Recommendation

### Single-Node / Air-Gapped Deployment (Default)
For standard hackathon, lab demonstration, and single-server forensic workstation setups, the **In-Process Async Worker Queue** is the recommended runtime:
- **No external infrastructure requirement**: Runs entirely within Python 3.12 without requiring Redis daemon or background Docker workers.
- **Strict WORM custody**: Vault files (`storage/vault/<sha256>.raw`) are written with read-only (`0o440`) permissions directly to local physical disk before processing begins.
- **Direct SSE streaming**: Real-time progress updates (0% to 100%) delivered to the Next.js frontend with low latency (<5ms).

### Distributed Multi-Node Deployment (Enterprise / Cloud)
When scaling to enterprise-grade throughput (>100 emails/second):
1. Configure `REDIS_URL=redis://redis:6379/0` in `.env`.
2. Launch Celery or Arq workers via `docker-compose.yml`:
   ```bash
   docker compose up -d redis worker api
   ```
3. Use shared distributed storage (e.g., Ceph, AWS EFS, or read-only S3 gateway) mounted at `/app/storage/vault` to preserve the Section 63 BSA physical chain-of-custody invariant across nodes.

---

## 4. Failure Recovery & Idempotency Invariants

1. **Idempotent Ingestion**: Re-uploading an email with identical SHA-256 hash immediately returns the existing evidence record (`409 Conflict` or existing dossier redirect) without re-executing analysis or duplicating vault entries.
2. **Transaction Rollback**: If a pipeline stage throws an unhandled exception after vault storage, the database transaction is rolled back, the error is recorded in `EvidenceAuditLog`, and the vault file is preserved for subsequent examination.
3. **Queue Health Probes**: `/health` and `/ready` endpoints report queue worker status and active job counts for orchestrator health checking.

