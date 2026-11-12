# System Operations, Maintenance & Runbook

**Platform:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Authority:** AICTE Cyber Security Cell | Smart India Hackathon (Problem Statement ID: 26106)

---

## 1. System Requirements & Prerequisites

- **Operating System:** Ubuntu 22.04 LTS / Debian 12 / Windows Server 2022
- **Python Runtime:** Python 3.12.x (Virtual environment managed via `uv` or `venv`)
- **Node.js Runtime:** Node.js 18.x or 20.x LTS (npm 9+)
- **Storage:** High-performance SSD/NVMe storage formatted with ext4/NTFS for low-latency physical fsync operations.
- **Network Access:** Outbound DNS (UDP/TCP 53) for SPF/DKIM/DMARC resolution; outbound HTTPS (443) for MaxMind/Threat feed updates.

---

## 2. Environment Configuration Reference

Production environment variables must be populated in `.env`:

```ini
# Core Environment
ENVIRONMENT=production
DEBUG=false
API_V1_PREFIX=/api/v1

# Security Secrets (Must be distinct, 32+ characters, cryptographically random)
VAULT_HMAC_SECRET=c8f9b2a14e6d3f8a0b5c7e9d2a4f6b8c1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0
JWT_SECRET_KEY=9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Database Configuration
DATABASE_URL=sqlite:///./storage/forensics.db
# For PostgreSQL:
# DATABASE_URL=postgresql://forensic_user:SecretPassword123@localhost:5432/sihtbp_forensics

# Evidence Vault & Storage Paths
STORAGE_VAULT_PATH=storage/vault
STORAGE_EXPORT_PATH=storage/exports
STORAGE_BACKUP_PATH=storage/backups

# OSINT Feeds & GeoIP
MAXMIND_LICENSE_KEY=<YOUR_MAXMIND_LICENSE_KEY>
GEOIP_DB_DIR=storage/geoip
TOR_EXIT_LIST_URL=https://check.torproject.org/torbulkexitlist
ENABLE_LIVE_THREAT_FEEDS=true

# Upload Restrictions
MAX_UPLOAD_SIZE_BYTES=26214400 # 25 MB
RATE_LIMIT_PER_MINUTE=60
```

---

## 3. Database Backup & Disaster Recovery

The platform includes a zero-dependency, automated backup utility that generates a timestamped snapshot of the database accompanied by a cryptographic SHA-256 manifest.

### Executing an Online Backup:
```bash
python scripts/db_backup_restore.py backup --db storage/forensics.db --out storage/backups
```
*Output:* Creates `storage/backups/forensics_backup_<timestamp>.db` and `storage/backups/forensics_backup_<timestamp>.db.sha256`.

### Verifying & Restoring a Backup:
```bash
python scripts/db_backup_restore.py restore \
  --backup storage/backups/forensics_backup_<timestamp>.db \
  --target storage/forensics.db
```
The restore command verifies the physical file digest against the `.sha256` manifest before touching the live database. If any byte mismatch is detected, the restore aborts immediately.

---

## 4. Evidence Vault Integrity Audits

Per Section 63 BSA guidelines, the evidence vault must be periodically swept to detect bit rot or unauthorized modifications:

### Via API Endpoint:
```bash
curl -X POST "http://localhost:8000/api/v1/forensics/vault/sweep" \
  -H "Authorization: Bearer <ADMIN_OR_AUDITOR_TOKEN>"
```

### Via CLI Maintenance Command:
```bash
python -m backend.app.database.vault sweep
```
Any corrupted file is immediately flagged in the database and logged to the immutable `EvidenceAuditLog` ledger.

---

## 5. Threat Intelligence Feed Synchronization

To update external IP reputation, Tor exit node lists, and PhishTank feeds:

```bash
python -m backend.app.osint.threat_feeds update
```
- Downloaded feeds are stamped with a SHA-256 manifest in `storage/threat_feeds/manifest.json`.
- In air-gapped environments, the system falls back seamlessly to the versioned local snapshots.

---

## 6. Cryptographic Secret & Key Rotation Runbook

1. **Rotating JWT Secret (`JWT_SECRET_KEY`):**
   - Update `JWT_SECRET_KEY` in `.env`.
   - Active user sessions will be required to log in again upon access token expiration (max 24h). Refresh tokens will fail validation gracefully.
2. **Rotating Vault HMAC Secret (`VAULT_HMAC_SECRET`):**
   - The vault HMAC is used for integrity verification of session cookies and secondary signatures. Updating it does not invalidate stored file SHA-256 digests.
3. **Database Schema Migrations:**
   - Execute Alembic upgrade commands:
   ```bash
   alembic upgrade head
   ```

---

## 7. Service Monitoring & Health Probes

| Probe Endpoint | Expected Response | Check Frequency | Failure Action |
|:---|:---|:---|:---|
| `GET /health` | `HTTP 200 {"status": "ok"}` | Every 10s | Restart container if 3 consecutive failures. |
| `GET /ready` | `HTTP 200 {"status": "ready"}` | Every 30s | Checks DB and Vault mount writeability. Drain traffic if 503. |
| `GET /metrics` | Prometheus metrics text | Scraped every 15s | Ingest into Prometheus/Grafana dashboard. |
