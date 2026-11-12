# Data Retention and Evidence Custody Policy

**Target Entity:** AICTE Cyber Security Cell  
**Problem Statement ID:** 26106 (SIH26106)  
**Governing Standard:** Section 63 of Bharatiya Sakshya Adhiniyam, 2023  

---

## 1. Scope & Objective
This policy defines the lifecycle, retention windows, physical storage safeguards, and cryptographic verification routines for all digital email evidence ingested into the AICTE Forensic Intelligence Platform.

---

## 2. Retention Tiers & Schedule

| Data Category | Primary Storage | Retention Period | Destruction / Purge Protocol |
| :--- | :--- | :--- | :--- |
| **Raw Evidence Streams (`.raw`)** | WORM Vault (`storage/vault/`) | **Permanent / Indefinite** (during active litigation/inquiry) | Files are write-once, read-many (chmod 0444). Manual or programmatic deletion is disabled in the application runtime. |
| **Relay Hops & Metadata** | Relational DB (`forensic_platform.db`) | **7 Years** from ingestion date | Archived to cold encrypted storage following statutory limitation periods. |
| **Cryptographic Audit Ledger** | Append-only `EvidenceAuditLog` table | **Permanent / Indefinite** | Chained HMAC hashes are permanent; truncation breaks the cryptographic verification chain. |
| **Extracted Threat Indicators (IoCs)** | Structured IoC Database | **3 Years** (rolling threat intelligence window) | Deprecated or expired IoCs are archived for cross-campaign historical graph queries. |
| **Exported Court Certificates (PDFs)** | Ephemeral / On-demand | **Dynamic Generation** | Re-generated on demand directly from validated vault bytes to prevent stale or tampered reports. |

---

## 3. Storage Security & Verification Safeguards
1. **WORM Vault Immutability**: All ingested raw streams are stored under `{sha256}.raw` and immediately flushed to physical disk with `os.fsync()`.
2. **Periodic Integrity Sweeps**: The system provides an automated and scheduled cryptographic sweep endpoint (`POST /api/v1/forensics/vault/sweep`) to re-hash all vault files and detect offline tampering or physical disk bit-rot.
3. **Audit Logging of Access**: Every read access to the raw vault (`GET /api/v1/forensics/evidence/{id}/raw`) generates a tamper-evident audit record documenting the actor, timestamp, and purpose.
