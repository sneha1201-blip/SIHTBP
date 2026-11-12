# Design Note 01: Problem Statement Scope, Gap Analysis & Resolution Architecture

**SIH Problem Statement ID:** 26106 (SIH26106)  
**Target Organization:** AICTE Cyber Security Cell  
**Theme:** Blockchain & Cybersecurity  

---

## 1. Context & Architectural Mandate

SIH Problem Statement 26106 requires a unified platform that bridges the gap between surface-level spam filtering and deep forensic tracing. Traditional spam gateways drop or quarantine emails without reconstructing the underlying threat infrastructure, leaving incident response teams blind to origin MTAs, lookalike infrastructure campaigns, and legal chain of custody.

The platform architecture resolves this via four core pipelines:
1. **Raw Ingestion & Evidentiary Vault**: Accepts raw `.eml` and `.msg` streams, enforcing size caps (25MB) and MIME validity, storing the payload in an append-only Write-Once-Read-Many (WORM) vault named by `{sha256}.raw` with physical `fsync` and SHA-512 dual hashing.
2. **Forensic Discrepancy & Hop Engine**: Parses RFC 5321 `Received` hops in reverse chronological order across heterogeneous MTA dialects (Exchange, Postfix, Sendmail, Exim, Gmail), computes inter-hop transit delays and clock skew, identifies trust boundaries, and extracts the authentic originating public IP.
3. **Authentication & Identity Correlation**: Recomputes DKIM signatures using `dkimpy` against public DNS records, verifies SPF using `pyspf`, evaluates RFC 7489 DMARC alignment, inspects ARC chains, and flags discrepancies where internal MTA headers claim authentication that fails cryptographic verification.
4. **AI Threat Intelligence & Campaign Graph**: Evaluates content intent via a calibrated multi-class classifier (Benign, Phishing, BEC, Extortion) trained on 120 curated forensic samples; extracts Indian banking coordinates and coercive deadlines; clusters related incidents into campaigns using four independent feature families (`NETWORK`, `TEMPLATE`, `ATTRIBUTION`, `IOC`); and exports STIX 2.1 intelligence bundles.

---

## 2. Gap Analysis & Resolution

| PS Requirement Area | Pre-Remediation Gap | Resolution Implemented | Verification Gate |
| :--- | :--- | :--- | :--- |
| **Relay Path Correlation** | Generic single-hop assumption; could be spoofed by downstream MTAs. | Reconstructed full relay path with trust-boundary discrimination, discarding private/forged hops. | `test_hop_traversal.py` (8/8 pass) |
| **Authentication Discrepancies** | Mock authentication fallbacks. | Real DNS resolution with `dkimpy`, `pyspf`, Public Suffix List alignment, and DNS snapshot recording. | `test_protocol_auth.py` (13/13 pass) |
| **Campaign Infrastructure** | False positive clustering on Google/AWS cloud ASNs. | Multi-signal clustering requiring $\ge 2$ independent feature families and filtering cloud providers. | `test_campaign_clustering.py` (ARI: 0.8766, NMI: 0.9037) |
| **Evidence Admissibility** | PDF export generated without verifying physical vault bytes. | Export-time vault re-hashing against database hash and HMAC signature; aborts with 409 Conflict on tamper. | `test_pipeline.py` (Vault tamper test passes) |
| **Zero Mock Policy** | Client-side scenario switcher and fake header presets. | Deleted all preset mock scenarios; database starts with 0 emails and 0 campaigns. | `test_database.py::test_zero_seed_default` |
