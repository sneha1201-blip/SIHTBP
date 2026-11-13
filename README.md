# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
**AICTE Cyber Security Cell | Smart India Hackathon (SIH Problem Statement ID: 26106)**

---

## 🛡️ Executive Summary

This platform delivers an enterprise-grade, zero-compromise forensic intelligence solution engineered for the **AICTE Cyber Security Cell** to detect, trace, and dismantle targeted email threats across higher technical institutions in India.

Built strictly according to **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023** for court-admissible electronic evidence, the platform replaces speculative heuristics with cryptographically verified protocol authentication (DKIM via `dkimpy`, SPF via `pyspf`, DMARC via Public Suffix List, and ARC chain inspection), RFC 5321 reverse hop-traversal with precision MaxMind GeoLite2 geolocation, a fine-tuned scikit-learn intent classifier with explainable token attribution, dynamic cross-incident campaign clustering, and standards-compliant RFC OASIS STIX 2.1 threat intelligence export.

---

## 📋 Documentation & System Specifications

Complete enterprise documentation is maintained in the `docs/` and `evidence/` directories:

| Specification Document | Purpose & Key Topics |
|:---|:---|
| [**Architecture & Design**](docs/ARCHITECTURE.md) | Technical architecture, pipeline sequence diagrams, dual-hashing, and database schemas. |
| [**Threat Model (STRIDE)**](docs/THREAT_MODEL.md) | STRIDE security analysis, SSRF filtering, homoglyph normalization, and tamper protections. |
| [**REST API Reference**](docs/API.md) | Complete OpenAPI 3.1 endpoint catalog, JWT auth, security headers, and SSE streaming. |
| [**System Operations & Runbook**](docs/OPERATIONS.md) | Deployment runbook, environment configs, DB backup/restore (`scripts/db_backup_restore.py`), key rotation. |
| [**SOC Analyst User Manual**](docs/USER_MANUAL.md) | Web UI guide, ingestion dropzone, dossier review, reverse hop maps, and campaign graph workflows. |
| [**Known Limitations & Boundaries**](docs/KNOWN_LIMITATIONS.md) | Candid disclosures: IP GeoIP vs device GPS, historical DKIM, NLP model boundaries, Section 63 BSA legal attestation bounds. |
| [**Requirements Traceability Matrix**](docs/REQUIREMENTS_MATRIX.md) | Line-by-line mapping of all SIH PS 26106 requirements to implementation modules, tests, and evidence. |
| [**Master Forensic Release Audit**](evidence/FINAL_AUDIT.md) | Comprehensive audit of all 13 remediation steps, 110 passing tests, and release sign-off. |

---

## 📋 Requirements Traceability Matrix

Every single functional requirement of SIH Problem Statement 26106 is mapped to implementation modules, automated pytest suites, and verifiable evidence artifacts:

| PS 26106 Requirement | Implementation Module | Automated Test Suite | Evidence Artifact |
|:---|:---|:---|:---|
| **Cryptographic Evidence Vault** | `backend/app/database/vault.py` | `backend/tests/test_database.py` | `evidence/step3.md` |
| **Streaming Upload Validator & Rate Limiter** | `backend/app/core/upload_validator.py` | `backend/tests/test_security.py` | `evidence/step3.md` |
| **RBAC & Argon2 Password Hashing** | `backend/app/core/security.py` | `backend/tests/test_security.py` | `evidence/step3.md` |
| **Tamper-Evident Hash-Chained Audit Ledger** | `backend/app/database/audit_service.py` | `backend/tests/test_security.py` | `evidence/step3.md` |
| **Cryptographic DKIM Verification** | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | `evidence/step4.md` |
| **Connecting IP SPF Evaluation (RFC 7208)** | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | `evidence/step4.md` |
| **DMARC PSL & ARC Chain Inspection** | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | `evidence/step4.md` |
| **MaxMind GeoIP & ASN Resolution** | `backend/app/osint/geo_resolver.py` | `backend/tests/test_osint_geoip.py` | `evidence/step5.md` |
| **RFC 5321 Hop Traversal & Skew Detection** | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | `evidence/step6.md` |
| **Live Tor Caching & Offline Snapshots** | `backend/app/osint/tor_detector.py` | `backend/tests/test_osint_geoip.py` | `evidence/step5.md` |
| **Async RDAP & NRD Classification** | `backend/app/osint/whois_client.py` | `backend/tests/test_osint_geoip.py` | `evidence/step5.md` |
| **Trained AI Multi-Class Threat Classifier** | `backend/app/ai/nlp_engine.py` | `backend/tests/test_ai_detection.py` | `evidence/step7.md`, `evidence/model_card.md` |
| **Attachment OLE Macro Deep Scanner** | `backend/app/forensics/attachment_analyzer.py`| `backend/tests/test_ai_detection.py`| `evidence/step7.md` |
| **Confusable Cyrillic Homoglyph & Cousin Domain** | `backend/app/forensics/spoof_detector.py` | `backend/tests/test_ai_detection.py` | `evidence/step7.md` |
| **URL Deobfuscation & SSRF Filter** | `backend/app/ai/url_analyzer.py` | `backend/tests/test_ai_detection.py` | `evidence/step7.md` |
| **Composite Threat Scoring Formula** | `backend/app/ai/threat_scorer.py` | `backend/tests/test_ai_detection.py` | `evidence/step7.md` |
| **Dynamic SimHash & Infrastructure Clustering** | `backend/app/forensics/campaign_clusterer.py`| `backend/tests/test_campaign_clustering.py`| `evidence/step8.md` |
| **RFC OASIS STIX 2.1 Intelligence Export** | `backend/app/forensics/campaign_clusterer.py`| `backend/tests/test_campaign_clustering.py`| `evidence/campaign_bundle.json` |
| **Court-Admissible PDF (Section 63 BSA 2023)** | `backend/app/reporting/pdf_generator.py` | `backend/tests/test_pipeline.py` | `evidence/step9.md` |
| **Offline Third-Party Verifier Script** | `scripts/verify_report.py` | `backend/tests/test_pipeline.py` | `evidence/step2.md`, `evidence/step9.md` |
| **Blind Evaluation Runner** | `scripts/evaluate_blind_corpus.py` | `backend/tests/test_ai_detection.py` | `evidence/step12.md` |

*Full matrix specification available at [docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).*

---

## 📁 System Architecture & Repository Layout

```
SIHTBP/
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   │   ├── nlp_engine.py             # Trained ML classifier & token attribution
│   │   │   ├── model_trainer.py          # Offline model training pipeline
│   │   │   ├── threat_scorer.py          # Composite weighted threat formula (6 subscores)
│   │   │   ├── training_data.py          # Curated multi-class benchmark corpus
│   │   │   └── url_analyzer.py           # Multi-stage URL deobfuscation & NRD check
│   │   ├── api/v1/
│   │   │   ├── endpoints_auth.py         # JWT authentication & session issuance
│   │   │   ├── endpoints_campaigns.py    # Filtered graph API & STIX 2.1 exporter
│   │   │   ├── endpoints_forensics.py    # Streaming upload, pipeline worker & dossiers
│   │   │   ├── endpoints_reports.py      # Section 63 BSA 2023 PDF streaming
│   │   │   └── router.py                 # Centralized v1 API router
│   │   ├── core/
│   │   │   ├── config.py                 # Pydantic v2 settings & security enforcement
│   │   │   ├── security.py               # Argon2 password hashing & JWT RBAC
│   │   │   └── upload_validator.py       # Streaming size limiter & magic-byte validator
│   │   ├── database/
│   │   │   ├── audit_service.py          # HMAC-SHA256 hash-chained audit ledger
│   │   │   ├── init_db.py                # Schema migration & foundational RBAC initialization
│   │   │   ├── models.py                 # SQLAlchemy 2.0 async ORM models
│   │   │   ├── session.py                # Async session maker (SQLite WAL / PostgreSQL)
│   │   │   └── vault.py                  # Cryptographic WORM evidence vault
│   │   ├── forensics/
│   │   │   ├── auth_validator.py         # Real dkimpy, pyspf, publicsuffix2 & ARC
│   │   │   ├── campaign_clusterer.py     # Dynamic SimHash, ASN, subnet & STIX 2.1 clusterer
│   │   │   ├── hop_traversal.py          # RFC 5321 Received header parser & clock skew
│   │   │   ├── ioc_extractor.py          # Automated defanging (hxxps://, [.])
│   │   │   ├── job_queue.py              # Async background processing pipeline
│   │   │   └── spoof_detector.py         # Unicode confusable skeleton & homoglyphs
│   │   ├── osint/
│   │   │   ├── asn_lookup.py             # MaxMind GeoLite2-ASN reader
│   │   │   ├── dnsbl_checker.py          # Spamhaus / SpamCop reverse IP client
│   │   │   ├── geo_resolver.py           # MaxMind GeoLite2-City reader
│   │   │   ├── tor_detector.py           # Live Tor bulk exit list client & cache
│   │   │   └── whois_client.py           # Async RDAP client for domain age & NRD
│   │   ├── parsers/
│   │   │   ├── eml_parser.py             # RFC 822 MIME parser
│   │   │   ├── mime_normalizer.py        # 64-bit SimHash & text canonicalizer
│   │   │   └── msg_parser.py             # Outlook OLE (.msg) binary parser
│   │   ├── reporting/
│   │   │   └── pdf_generator.py          # Section 63 BSA 2023 certified PDF generator
│   │   └── main.py                       # FastAPI entrypoint, CORS & health endpoints
│   ├── tests/                            # 73 automated pytest verification suites
│   ├── Dockerfile                        # Multi-stage Python 3.12 container
│   └── requirements.txt                  # Pinned dependencies
├── frontend/
│   ├── src/
│   │   ├── app/                          # Next.js 14 App Router dashboard
│   │   ├── components/                   # Leaflet map, graph inspector, IOC tables
│   │   └── lib/                          # Direct backend API client (zero canned fallbacks)
│   └── Dockerfile                        # Node 20 Next.js production container
├── evidence/                             # Verifiable forensic artifacts & benchmarks
│   ├── benchmark_results.json            # End-to-end pipeline latency & throughput audit
│   ├── campaign_bundle.json              # RFC OASIS STIX 2.1 intelligence export
│   ├── model_card.md                     # AI classifier metrics (Accuracy, F1, ROC-AUC)
│   ├── phase0.md through phase5.md       # Incremental phase verification ledgers
├── scripts/
│   ├── benchmark_e2e.py                  # End-to-end pipeline benchmark runner
│   ├── update_geoip.sh                   # MaxMind GeoLite2 database updater (Linux/macOS)
│   └── update_geoip.ps1                  # MaxMind GeoLite2 database updater (Windows)
├── docker-compose.yml                    # Multi-container orchestration
└── verify_system.py                      # Master system verification runner (5 gates)
```

---

## 🧮 Composite Threat Scoring Formula

The platform computes an explainable, composite risk score ($0.0$ to $100.0$) using the weighted vector:

$$\text{Threat Score} = \min\left(100.0, 0.25 \times \text{Auth} + 0.20 \times \text{Hop} + 0.20 \times \text{NLP} + 0.20 \times \text{URL} + 0.15 \times \text{Brand/VIP} + \text{Overrides}\right)$$

### Critical Threat Overrides:
1. **DKIM Signature FAIL + High-Risk URL**: Immediate verdict override to `PHISHING` ($\ge 90.0$).
2. **Tor Exit Node Originating MTA**: Verified active exit node overrides score to $\ge 98.0$, Verdict = `PHISHING`.
3. **Executive BEC Wire Fraud**: VIP display spoofing with divergent webmail `Reply-To` $\ge 94.0$, Verdict = `BEC`.
4. **IDN Cyrillic Homoglyph Attack**: Punycode domain disguising non-ASCII glyphs $\ge 88.0$, Verdict = `PHISHING`.
5. **Bulletproof Hosting Origin**: Infrastructure registered under hostile bulletproof ASNs $\ge 92.0$, Verdict = `MALICIOUS`.

---

## 🤖 AI Model & Classification Benchmark

Empirical metrics evaluated on stratified holdout test set (provenance in `evidence/model_card.md` and `evidence/datasets.md`):

| Evaluation Metric | Score | Verification Status |
|---|---|---|
| **Holdout Test Accuracy** | **94.26%** | **VERIFIED (Empirical on Real Corpora)** |
| **ROC-AUC (One-vs-Rest Macro)** | **0.9660** | **VERIFIED** |
| **PR-AUC (Average Precision Macro)** | **0.8239** | **VERIFIED** |
| **F1-Score (Macro / Weighted)** | **0.7731 / 0.9382** | **VERIFIED** |
| **Expected Calibration Error (ECE)** | **0.0334 (95% CI: [0.0269, 0.0528])** | **VERIFIED** |
| **False Positive Rate @ 95% Recall** | **6.62%** | **VERIFIED** |

---

## ⚖️ Statutory Legal Admissibility (Section 63 BSA, 2023)

Every generated forensic dossier contains a statutory certificate compliant with **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023** (which supersedes Section 65B of the repealed Indian Evidence Act, 1872):
- **Cryptographic Dual-Hash**: Simultaneous SHA-256 (64-char hex) and SHA-512 (128-char hex) digests generated at intake, plus legacy MD5 label.
- **Physical Vault Verification**: Export-time physical re-hash directly from physical disk to ensure zero post-ingestion tampering (`409 Conflict` on tamper).
- **Statutory Partition**:
  - **Part A (Automated Parameters)**: Operating system, software version, dual hashes, byte counts, and NTP timestamps legitimately self-certified by the automated tool.
  - **Part B (Lawful Custody Attestation)**: Mandates signature and designation of the human officer in lawful custody. Unknown fields are labeled `[NEEDS LEGAL REVIEW]` and never fabricated.
- **WORM Chain of Custody**: Write-Once-Read-Many physical storage under `storage/vault/<sha256>.raw` with read-only (`0o440`) permissions.
- **Hash-Chained Audit Ledger**: Every vault read, write, export, or campaign split/merge is cryptographically chained (`parent_hash -> current_hash`).
- **Offline Third-Party Verifier**: Standalone Python script (`scripts/verify_report.py`) enables judges and defense counsel to independently verify any `.raw` file against a Section 63 BSA PDF certificate offline.

---

## ⚡ Performance Benchmark & Throughput

Measured across empirical NVMe SSD storage with SQLite WAL mode and fsync enabled (`scripts/benchmark_e2e.py`) and persisted in `evidence/benchmark_results.json`:

| Forensic Pipeline Stage | P50 (Median) | P95 Latency | Cold Start | Cache Hit Rate |
|:---|:---:|:---:|:---:|:---:|
| **Dual-Hashing & Vault Storage** | 1.84 ms | 5.21 ms | 3.12 ms | 0.0% |
| **MIME Parsing & Carving** | 2.11 ms | 3.84 ms | 3.50 ms | 0.0% |
| **RFC 5321 Hop Traversal & MaxMind**| < 0.10 ms | 0.12 ms | 0.15 ms | 0.0% |
| **Protocol Authentication (DKIM/SPF)**| 42.10 ms | 1980.50 ms*| 2104.20 ms*| 0.0% |
| **Attachment OLE Macro Scan** | 0.85 ms | 1.42 ms | 1.80 ms | 0.0% |
| **URL Deobfuscation & SSRF Filter**| 0.12 ms | 0.25 ms | 0.30 ms | 0.0% |
| **AI NLP Intent & Explainability** | 4.82 ms | 8.15 ms | 425.10 ms | 0.0% |
| **Campaign Multi-Signal Clustering**| 1.15 ms | 2.40 ms | 3.10 ms | 0.0% |
| **Section 63 BSA 2023 PDF Generation**| 24.30 ms | 48.60 ms | 52.10 ms | 0.0% |
| **End-to-End Ingestion (Physical Disk)**| **53.97 ms** | **2126.35 ms**| **2557.10 ms**| **0.0%** |

*\*Note: Protocol authentication latency on cold queries is bounded by external DNS lookup timeouts (1.5s per concurrent lookup guard). Median warm latency is 42.10 ms.*

---

## 🚀 Quickstart & Deployment

### Option A: Docker Compose (Recommended for Production)

Run the entire platform (FastAPI backend + Next.js frontend + persistent storage) with one command:
```bash
docker-compose up --build -d
```
- **SOC Analyst Command Center**: `http://localhost:3000`
- **FastAPI OpenAPI Interactive Docs**: `http://localhost:8000/docs`
- **Backend Health Check**: `http://localhost:8000/health`
- **Readiness Probe**: `http://localhost:8000/ready`
- **Prometheus Metrics**: `http://localhost:8000/metrics`

To inspect container logs:
```bash
docker-compose logs -f
```

---

### Option B: Local Development Execution

#### 1. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# Install pinned dependencies
pip install -r requirements.txt

# Configure environment secrets
export VAULT_HMAC_SECRET="aicte_sec63_bsa_production_hmac_secret_2026_super_secure_vault_key"
export JWT_SECRET_KEY="aicte_jwt_secret_key_production_2026_argon2_super_secure"
export DEBUG="true"

# Start the FastAPI server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000` to interact with the live SOC Analyst dashboard.

---

### 3. Verification & Test Suite Execution

Run the comprehensive 110-test automated pytest suite:
```bash
pytest -v backend/tests/
```
Expected output:
```
====================== 110 passed, 5 warnings in 26.85s =======================
```

Run the offline report integrity verifier:
```bash
python scripts/verify_report.py --raw storage/vault/<hash>.raw --pdf storage/exports/<report>.pdf
```

Run database backup and restore test:
```bash
python scripts/db_backup_restore.py backup --db storage/forensics.db --out storage/backups
python scripts/db_backup_restore.py restore --backup storage/backups/forensics_backup_*.db --target storage/forensics.db
```

Run linter, type checks, and production builds:
```bash
ruff check backend/
mypy backend/app
cd frontend && npx tsc --noEmit && npm run build
git grep -inE "mock|dummy|fake|placeholder|fallback|hardcoded|AS49870|HDFC|before 4:00 PM" backend/app frontend/src
```
*(All linters, type checks, and Next.js 14 production builds pass with 0 errors; forbidden keywords check returns 0 matches in runtime paths).*
