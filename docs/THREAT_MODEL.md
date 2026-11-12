# Platform Threat Model & Security Controls

**Platform:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Authority:** AICTE Cyber Security Cell | Smart India Hackathon (Problem Statement ID: 26106)  
**Standard:** STRIDE Methodology & Section 63 BSA 2023 Evidentiary Integrity

---

## 1. System Assets & Protection Objectives

| Critical Asset | Sensitivity | Impact of Compromise | Primary Protection Mechanism |
|:---|:---|:---|:---|
| **Raw Evidence Files (`.raw`)** | Critical / Legal | Evidence dismissed in court under Section 63 BSA | Cryptographic vault dual-hashing (SHA-256 + SHA-512), read-only disk permissions (`0o440`), export-time physical re-hash. |
| **Audit Log Ledger** | Critical / Legal | Concealment of unauthorized tampering | Cryptographic hash chaining (`parent_hash -> current_hash`), append-only DB constraints, chain verification API. |
| **User & Analyst Credentials** | High | Unauthorized case access, dossier falsification | Argon2id password hashing, JWT access/refresh lifecycle, 5-attempt lockout per 15 minutes. |
| **Threat Intelligence & Campaigns** | High | Leaked attribution, adversary counter-operations | Role-Based Access Control (`ADMIN`, `ANALYST`, `AUDITOR`), sanitized STIX 2.1 exports. |
| **Backend Compute Infrastructure**| High | Denial of Service (DoS), lateral movement | Magic byte validation, 25 MB stream caps, SSRF IP blocking, memory-bound parsing. |

---

## 2. Threat Analysis & Mitigations (STRIDE Matrix)

### A. Spoofing (Identity Impersonation)
- **Threat Vector 1: Display Name & Cousin Domain Spoofing.** Adversaries send emails appearing as AICTE executives using Lookalike Cyrillic characters (e.g., `аісtе-іndіа.оrg`).
  - **Mitigation:** Unicode confusable skeleton normalization (UTS#39) compares canonical Latin skeletons against high-value domains and flags cousin domain discrepancies with a high threat subscore.
- **Threat Vector 2: Direct Protocol Spoofing.** Forged envelope sender domains bypassing standard filters.
  - **Mitigation:** Cryptographic multi-signature DKIM verification, RFC 7208 SPF evaluation against the trusted connecting MTA, and strict DMARC alignment against the Public Suffix List.

### B. Tampering (Evidence Modification & Anti-Forensics)
- **Threat Vector 1: Post-Ingestion Alteration of Raw Evidence.** Adversary or insider modifies stored `.eml` payload to clear incriminating data.
  - **Mitigation:** Raw files are saved in `storage/vault/<sha256>.raw` with strict `0440` read-only permissions. Prior to generating any Section 63 BSA Certificate, the file is re-read from physical disk and re-hashed; any divergence returns `HTTP 409 Conflict` and logs a critical tampering incident.
- **Threat Vector 2: Tampering with Historical Audit Logs.** Insider deletes or alters rows in the database to conceal unauthorized evidence exports.
  - **Mitigation:** The `EvidenceAuditLog` utilizes an immutable SHA-256 hash chain (`parent_hash` chained into each record). The audit verification endpoint (`GET /api/v1/forensics/audit/verify-chain`) verifies the entire ledger from the genesis block in $O(N)$ time.

### C. Repudiation (Denial of Legal Authenticity)
- **Threat Vector 1: Defense Challenges Electronic Admissibility in Court.** Defense counsel argues that evidence was modified by automated scripts or that system specs are falsified.
  - **Mitigation:** Strict compliance with Section 63 BSA 2023. The platform generates a legally partitioned PDF clearly separating automated machine parameters (Part A) from human officer lawful custody (Part B). Third parties can verify the output independently via `scripts/verify_report.py`.

### D. Information Disclosure (Sensitive Data Leakage)
- **Threat Vector 1: Server-Side Request Forgery (SSRF) via URL Tracing.** Malicious email contains redirect URLs targeting internal AWS/GCP metadata (`169.254.169.254`) or internal subnets (`10.0.0.0/8`, `192.168.0.0/16`).
  - **Mitigation:** Multi-stage SSRF protection (`is_ssrf_forbidden_host`) resolves all redirect targets to physical IP addresses and strictly forbids requests to loopback, private RFC 1918 ranges, link-local, multicast, and cloud metadata endpoints.
- **Threat Vector 2: Sensitive Data in HTTP Responses & Headers.**
  - **Mitigation:** Strict CSP (`frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and automated scrubbing of sensitive tracebacks in production mode.

### E. Denial of Service (DoS & Resource Exhaustion)
- **Threat Vector 1: Oversized Email Uploads & Zip Bombs.** Adversary transmits a 500 MB file or deeply nested archive to exhaust server RAM.
  - **Mitigation:** Streaming validator aborts uploads exceeding 25 MB (`HTTP 413 Content Too Large`) without spooling to memory. Attachment inspector restricts archive extraction depth (maximum 3 levels, 50 MB total uncompressed limit).
- **Threat Vector 2: ReDoS via Complex Regular Expressions.**
  - **Mitigation:** All URL and header regexes are bounded and fuzz-tested with Hypothesis to prevent catastrophic backtracking.

### F. Elevation of Privilege (RBAC Bypass)
- **Threat Vector 1: Analyst Escalating to Administrator.**
  - **Mitigation:** Role verification is enforced cryptographically inside JWT claims (`role: ADMIN | ANALYST | AUDITOR`). Administrative endpoints (user registration, status toggle) strictly require the `ADMIN` role dependency.
- **Threat Vector 2: Brute-Force Password Attacks.**
  - **Mitigation:** Argon2id password hashing with explicit salt and time cost. Account lockout automatically disables accounts after 5 consecutive failures for a 15-minute cooldown period.
