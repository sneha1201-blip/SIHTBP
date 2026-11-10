# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
**AICTE Cyber Security Cell | Smart India Hackathon (SIH Problem Statement ID: 26106)**

---

## 🛡️ Executive Summary

This platform delivers an enterprise-grade, zero-compromise forensic intelligence solution engineered for the **AICTE Cyber Security Cell** to detect, trace, and dismantle targeted email threats across higher technical institutions in India.

Built strictly according to **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023** for court-admissible electronic evidence, the platform replaces speculative heuristics with cryptographically verified protocol authentication (DKIM via `dkimpy`, SPF via `pyspf`, DMARC via Public Suffix List, and ARC chain inspection), RFC 5321 reverse hop-traversal with precision MaxMind GeoLite2 geolocation, a fine-tuned scikit-learn intent classifier with explainable token attribution, dynamic cross-incident campaign clustering, and standards-compliant RFC OASIS STIX 2.1 threat intelligence export.

---

## 📋 Requirements Traceability Matrix

Every single functional requirement of SIH Problem Statement 26106 is mapped to implementation modules, automated pytest suites, and verifiable evidence artifacts:

| PS 26106 Requirement | Implementation Module | Automated Test Suite | Evidence Artifact |
|:---|:---|:---|:---|
| **Cryptographic Evidence Vault** | `backend/app/database/vault.py` | `backend/tests/test_database.py` | `evidence/phase1.md` |
| **Streaming Upload Validator & Rate Limiter** | `backend/app/core/upload_validator.py` | `backend/tests/test_security.py` | `evidence/phase1.md` |
| **RBAC & Argon2 Password Hashing** | `backend/app/core/security.py` | `backend/tests/test_security.py` | `evidence/phase1.md` |
| **Tamper-Evident Hash-Chained Audit Ledger** | `backend/app/database/audit_service.py` | `backend/tests/test_security.py` | `evidence/phase1.md` |
| **Cryptographic DKIM Verification** | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | `evidence/phase2.md` |
| **Connecting IP SPF Evaluation (RFC 7208)** | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | `evidence/phase2.md` |
| **DMARC PSL & ARC Chain Inspection** | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | `evidence/phase2.md` |
| **MaxMind GeoIP & ASN Resolution** | `backend/app/osint/geo_resolver.py` | `backend/tests/test_osint_geoip.py` | `evidence/phase3.md` |
| **RFC 5321 Hop Traversal & Skew Detection** | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | `evidence/phase3.md` |
| **Live Tor Caching & Offline Snapshots** | `backend/app/osint/tor_detector.py` | `backend/tests/test_osint_geoip.py` | `evidence/phase3.md` |
| **Async RDAP & NRD Classification** | `backend/app/osint/whois_client.py` | `backend/tests/test_osint_geoip.py` | `evidence/phase3.md` |
| **Trained AI Multi-Class Threat Classifier** | `backend/app/ai/nlp_engine.py` | `backend/tests/test_ai_detection.py` | `evidence/model_card.md` |
| **Confusable Cyrillic Homoglyph & Cousin Domain** | `backend/app/forensics/spoof_detector.py` | `backend/tests/test_ai_detection.py` | `evidence/phase4.md` |
| **URL Deobfuscation & Hex/Octal/DWORD Decoding** | `backend/app/ai/url_analyzer.py` | `backend/tests/test_ai_detection.py` | `evidence/phase4.md` |
| **Composite Threat Scoring Formula** | `backend/app/ai/threat_scorer.py` | `backend/tests/test_ai_detection.py` | `evidence/phase4.md` |
| **Dynamic SimHash & Infrastructure Clustering** | `backend/app/forensics/campaign_clusterer.py`| `backend/tests/test_campaign_clustering.py`| `evidence/phase5.md` |
| **RFC OASIS STIX 2.1 Intelligence Export** | `backend/app/forensics/campaign_clusterer.py`| `backend/tests/test_campaign_clustering.py`| `evidence/campaign_bundle.json` |
| **Court-Admissible PDF (Section 63 BSA 2023)** | `backend/app/reporting/pdf_generator.py` | `backend/tests/test_pipeline.py` | `evidence/phase6.md` |

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

## ⚖️ Statutory Legal Admissibility (Section 63 BSA, 2023)

Every generated forensic dossier contains a statutory certificate compliant with **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023** (which supersedes Section 65B of the repealed Indian Evidence Act, 1872):
- **Cryptographic Dual-Hash**: Simultaneous SHA-256 and MD5 digests generated at intake.
- **WORM Chain of Custody**: Write-Once-Read-Many physical storage under `storage/vault/raw/{sha256}.eml`.
- **HMAC-SHA256 Vault Seal**: Non-repudiation signature computed over raw evidence bytes.
- **Hash-Chained Audit Ledger**: Every vault read, write, or export is cryptographically chained (`prev_hash`).
- **Analyst Cryptographic Token**: Unique non-repudiation token generated from examiner credentials, evidence hash, and timestamp.
- **MTA Discrepancy Flagging**: Visual and textual advisories when upstream receiving headers disagree with recomputed cryptographic verdicts.

---

## ⚡ Performance Benchmark & Throughput

Measured across the 11 real test corpus samples (3 iterations, 33 total evaluations) using `scripts/benchmark_e2e.py` and persisted in `evidence/benchmark_results.json`:

| Forensic Pipeline Stage | Mean Latency | P95 Latency | Min Latency | Max Latency |
|:---|:---:|:---:|:---:|:---:|
| **Dual-Hashing & Vault Storage** | 1.90 ms | 5.51 ms | 0.79 ms | 5.62 ms |
| **MIME / RFC 822 Parsing** | 2.56 ms | 4.17 ms | 0.91 ms | 4.21 ms |
| **RFC 5321 Hop Traversal & MaxMind**| < 0.10 ms | < 0.10 ms | 0.00 ms | 0.05 ms |
| **Protocol Authentication (DKIM/SPF)**| 2744.69 ms* | 3030.51 ms*| 1503.91 ms | 3058.84 ms |
| **Spoofing & Homoglyph Detection** | 0.72 ms | 0.98 ms | 0.42 ms | 1.08 ms |
| **IOC Extraction & URL Deobfuscation**| 0.08 ms | 0.18 ms | 0.04 ms | 0.45 ms |
| **AI NLP Intent & Entity Extraction**| 51.55 ms | 6.64 ms | 2.97 ms | 1587.62 ms |
| **Threat Scoring Formula** | 0.02 ms | 0.04 ms | 0.02 ms | 0.05 ms |
| **Section 63 BSA 2023 PDF Generation**| 29.62 ms | 51.04 ms | 24.63 ms | 55.27 ms |
| **End-to-End Ingestion (Synchronous)**| 983.96 ms | 3619.98 ms | 9.92 ms | 4103.51 ms |

*\*Note: Protocol authentication latency is bounded by real-time DNS queries against authoritative name servers and historical key lookup timeouts (3.0s query timeout guard).*

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

Run the comprehensive 73-test pytest suite:
```bash
pytest -v backend/tests/
```
Expected output:
```
======================= 73 passed, 3 warnings in 15.55s =======================
```

Run the end-to-end full-stack integration and offline resilience verifier:
```bash
python verify_system.py
```
Expected output:
```
================================================================================
   AICTE CYBER SECURITY CELL | SMART INDIA HACKATHON 2026 (SIH ID: 26106)
   AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
   END-TO-END FULL-STACK INTEGRATION & OFFLINE RESILIENCE VERIFIER
================================================================================

 [PASS] 1. Database & Cryptographic Vault                SQLite WAL Active | 9 Emails, 18 Hops, 9 Analyses, 29 IoCs in DB
 [PASS] 2. Air-Gapped & Offline Resilience               Zero-Guess GeoIP OK | Tor Snapshot Cache OK | DNS 1.5s Timeout Guard OK
 [PASS] 3. E2E Forensic Ingestion & Geo Coordinates      Case UUID: ... | Score: 94.0/100 | Verdict: BEC | 3 Geolocated Hops
 [PASS] 4. Section 63 BSA 2023 PDF Generation            Size: 6.1 KB | %PDF-1.4 Header Validated
 [PASS] 5. Campaign Cross-Incident Graph API             Graph Loaded: 16 Nodes, 15 Edges | Cytoscape / D3 Schema Valid

================================================================================
ALL SUBSYSTEMS VERIFIED & OPERATIONAL (Section 63 BSA 2023 Compliant)
Ready for Live Demonstration before AICTE Cyber Security Cell Jury.
================================================================================
```

Run linter, type checks, and forbidden keywords check:
```bash
ruff check backend/
mypy backend/app
cd frontend && npx tsc --noEmit && npm run build
git grep -inE "mock|dummy|fake|placeholder|fallback|hardcoded|AS49870|HDFC|before 4:00 PM" backend/app frontend/src
```
*(All linters, type checks, and production builds pass; forbidden keywords check returns 0 matches).*
