# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
**AICTE Cyber Security Cell | Smart India Hackathon (SIH Problem Statement ID: 26106)**

---

## 🛡️ Executive Summary

This platform delivers an enterprise-grade forensic intelligence solution for the **AICTE Cyber Security Cell** to detect, trace, and dismantle targeted email threats (BEC, spear-phishing, VIP impersonation, cousin domains, and multi-vector infrastructure campaigns) across higher technical institutions in India.

---

## 📁 System Architecture

```
SIHTBP/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── config.py             # Pydantic global settings, weights, VIP rosters
│   │   │   └── security.py           # HMAC tokens, nonce generation, constant-time compare
│   │   ├── database/
│   │   │   ├── models.py             # 6 Relational & Graph ORM models
│   │   │   ├── session.py            # SQLAlchemy 2.0 async engine (SQLite WAL & PG16)
│   │   │   ├── vault.py              # WORM evidence vault & HMAC-SHA256 ledger
│   │   │   ├── seed_data.py          # Realistic forensic mock generator (5 test cases)
│   │   │   └── init_db.py            # Database schema builder & verification runner
│   │   ├── parsers/
│   │   │   ├── eml_parser.py         # RFC 822 MIME parser with attachment checksumming
│   │   │   ├── msg_parser.py         # Microsoft Outlook (.msg) binary parser
│   │   │   └── mime_normalizer.py    # ParsedEmailData model & 64-bit SimHash engine
│   │   ├── forensics/
│   │   │   ├── hop_traversal.py      # Reverse Hop-Traversal Algorithm (RFC 5321/5322)
│   │   │   ├── auth_validator.py     # SPF, DKIM, and DMARC RFC 7489 Alignment
│   │   │   ├── spoof_detector.py     # VIP display spoofing, cousin domains, Cyrillic homographs
│   │   │   └── ioc_extractor.py      # IOC extractor with automatic defanging (`hxxps://`, `[.]`)
│   │   ├── osint/
│   │   │   ├── geo_resolver.py       # MaxMind GeoIP2 + intelligent offline forensic fallback
│   │   │   ├── asn_lookup.py         # Autonomous system and bulletproof/datacenter flags
│   │   │   ├── tor_detector.py       # Tor exit node & commercial VPN/proxy detector
│   │   │   └── whois_client.py       # Async WHOIS lookup & newly registered domain (NRD) check
│   │   ├── ai/
│   │   │   ├── nlp_engine.py         # BEC wire fraud (IFSC/IBAN/SWIFT) & psychological coercion
│   │   │   ├── url_analyzer.py       # De-obfuscate hex/octal/dword IPs & credential lures
│   │   │   └── threat_scorer.py      # Composite 0–100 threat score formula & verdict engine
│   │   ├── reporting/
│   │   │   └── pdf_generator.py      # Section 63 BSA 2023 court-admissible PDF dossier
│   │   ├── api/v1/
│   │   │   ├── endpoints_forensics.py # Ingestion, pipeline execution, GeoJSON hops
│   │   │   ├── endpoints_campaigns.py # Cytoscape/D3 graph relationships & clustering
│   │   │   ├── endpoints_reports.py   # Streaming PDF report downloads
│   │   │   └── router.py             # Master API router
│   │   └── main.py                   # FastAPI app factory, CORS, lifespan handler
│   ├── tests/
│   │   ├── test_database.py          # Phase 1 Database & Vault test suite
│   │   └── test_pipeline.py          # Phase 2 End-to-end pipeline & REST API test suite
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx            # Dark cyber theme provider & Leaflet CSS
│   │   │   ├── globals.css           # Radar pulse animations & custom scrollbars
│   │   │   └── page.tsx              # Master SOC Analyst Command Center dashboard
│   │   ├── components/
│   │   │   ├── TopBar.tsx            # Case ID, SHA-256 copy, Section 65B PDF action, scenario switcher
│   │   │   ├── ThreatScoreGauge.tsx  # SVG circular progress gauge (0-100) & subscore breakdown
│   │   │   ├── AuthBadges.tsx        # Interactive SPF/DKIM/DMARC RFC 7489 alignment badges
│   │   │   ├── HeaderMismatchTable.tsx # From / Return-Path / Reply-To spoofing & homograph flags
│   │   │   ├── GeoTraceMap.tsx       # Dynamic Leaflet wrapper with timeline cards
│   │   │   ├── GeoTraceMapInner.tsx  # CartoDB Dark Matter map with Great Circle flight paths
│   │   │   ├── NlpIntentViewer.tsx   # Email body renderer with colored AI entity highlights
│   │   │   ├── IocDataTable.tsx      # Filterable IoC table with safe defanging (`hxxps://`, `[.]`)
│   │   │   ├── CampaignGraph.tsx     # Threat cluster node-and-edge visual graph & inspector
│   │   │   ├── AuditLedgerTable.tsx  # Section 63 BSA 2023 tamper-evident HMAC audit trail
│   │   │   ├── FileDropzone.tsx      # Drag-and-drop .eml/.msg with WebCrypto SHA-256 hashing
│   │   │   ├── HeaderPasteModal.tsx  # Raw RFC 822 MIME headers paste with demo presets
│   │   │   └── IngestionModal.tsx    # Tabbed intake modal container
│   │   └── lib/
│   │       ├── types.ts              # Unified TypeScript definitions & schemas
│   │       ├── utils.ts              # Defanging, formatting, and clipboard helpers
│   │       ├── mockData.ts           # 5 complete forensic demo scenarios & graph linkages
│   │       └── api.ts                # Axios backend integration with intelligent offline fallback
│   ├── package.json
│   ├── tsconfig.json
│   └── tailwind.config.js
├── storage/
│   ├── vault/                        # Immutable raw evidence vault (.eml/.msg files)
│   └── forensic_platform.db          # Zero-setup local SQLite 3 database (WAL)
├── requirements.txt
└── README.md
```

---

## 🧮 Composite Threat Scoring Formula

The platform computes an explainable, composite risk score ($0.0$ to $100.0$) using the weighted vector:

$$\text{Threat Score} = \min\left(100, 0.25 \times \text{Auth} + 0.20 \times \text{Header} + 0.20 \times \text{NLP} + 0.15 \times \text{URL} + 0.10 \times \text{OSINT} + 0.10 \times \text{Attach} + \text{Overrides}\right)$$

### Critical Threat Overrides:
1. **Tor Exit Node Originating MTA**: Automatically overrides score to $\ge 98.0$, Verdict = `PHISHING`.
2. **Executive BEC Wire Fraud**: VIP Display Name spoofing with unauthenticated webmail Reply-To diverter $\ge 94.0$, Verdict = `BEC`.
3. **IDN Cyrillic Homograph Attack**: Punycode domain disguising non-ASCII glyphs $\ge 88.0$, Verdict = `PHISHING`.
4. **Bulletproof Infrastructure Cluster**: Multi-institution spear-phishing from high-risk ASN $\ge 92.0$, Verdict = `MALICIOUS`.

---

## ⚖️ Statutory Legal Admissibility (Section 63 BSA, 2023)

Every generated forensic dossier contains a statutory certificate compliant with **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023** (formerly Section 65B of the Indian Evidence Act, 1872):
- **Cryptographic Watermark**: Dual SHA-256 and MD5 digests computed at instant of ingestion.
- **WORM Chain of Custody**: Write-Once-Read-Many physical storage under `storage/vault/{sha256}.raw`.
- **HMAC-SHA256 Audit Signatures**: Mathematically verifiable non-repudiation ledger entries.
- **Examiner Sign-off Block**: Complete with examiner designation, date, institutional seal, and certification text.

---

## 🌐 REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/forensics/analyze` | Ingests multipart file (`.eml`/`.msg`) or raw text headers; runs full forensic pipeline; persists to database & vault; returns full dossier JSON. |
| `GET` | `/api/v1/forensics/evidence/{id}` | Retrieves complete stored forensic dossier by evidence UUID. |
| `GET` | `/api/v1/forensics/evidence/{id}/hops` | Returns transit hops formatted as a GeoJSON `FeatureCollection` with Point and LineString flight-path geometries for frontend mapping. |
| `GET` | `/api/v1/forensics/evidence/{id}/report` | Streams the court-admissible Section 63 BSA 2023 forensic PDF dossier. |
| `GET` | `/api/v1/campaigns/graph` | Returns Cytoscape / D3.js compatible `nodes` and `edges` for multi-incident relationship graph visualization. |
| `GET` | `/api/v1/campaigns/` | Lists all detected campaign clusters, pivot criteria, and attributed emails. |
| `GET` | `/api/v1/health` | Health-check endpoint reporting database engine and vault status. |

---

## 🚀 Quickstart & Verification

### 1. Initialize Database & Seed Forensic Cases
```bash
python backend/app/database/init_db.py --reset
```

### 2. Start the FastAPI Application
```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```
- Interactive Swagger UI: `http://localhost:8000/docs`
- Redoc UI: `http://localhost:8000/redoc`

### 3. Run Automated Backend Test Suite (15 Tests)
```bash
pytest -v backend/tests/
```
Output:
```
backend/tests/test_database.py::test_hash_calculation PASSED
backend/tests/test_database.py::test_vault_store_and_read PASSED
backend/tests/test_database.py::test_vault_tamper_detection PASSED
backend/tests/test_database.py::test_hmac_signatures PASSED
backend/tests/test_database.py::test_email_crud_and_cascade PASSED
backend/tests/test_database.py::test_email_sha256_unique_constraint PASSED
backend/tests/test_database.py::test_forensic_seeder_execution PASSED
backend/tests/test_pipeline.py::test_eml_parser PASSED
backend/tests/test_pipeline.py::test_reverse_hop_traversal PASSED
backend/tests/test_pipeline.py::test_protocol_authentication PASSED
backend/tests/test_pipeline.py::test_spoof_detection_vip_and_homograph PASSED
backend/tests/test_pipeline.py::test_nlp_bec_wire_fraud_detection PASSED
backend/tests/test_pipeline.py::test_url_deobfuscation PASSED
backend/tests/test_pipeline.py::test_forensic_pdf_generation PASSED
backend/tests/test_pipeline.py::test_api_analyze_and_report_endpoints PASSED
======================== 15 passed in 6.83s ========================
```

---

## 🖥️ Phase 3 — Next.js 14 SOC Analyst Dashboard

The frontend dashboard provides a military-grade, dark-themed cyber defense cockpit designed for institutional security operations centers.

### 🌟 Key Dashboard Features:
1. **CartoDB Dark Matter Leaflet Geotrace Map (`GeoTraceMap.tsx`)**:
   - Visualizes MTA transit relays with Great Circle flight path lines.
   - Distinct markers: Originating Gateway (Pulsing Red Radar), Transit Relays (Amber), Destination MX (Green Shield).
   - Interactive popups with reverse IP geolocation, AS number, and transit delay ($\Delta t$).
2. **Explainable Composite Threat Gauge (`ThreatScoreGauge.tsx`)**:
   - Animated SVG circular gauge transitioning smoothly between green (Benign), yellow (Suspicious), orange (BEC/Phish), and red (Malicious).
   - Granular breakdown of 6 subscores: Auth (25%), Header (20%), NLP (20%), URL (15%), OSINT (10%), Attach (10%).
3. **Authentication Verification Badges (`AuthBadges.tsx`)**:
   - Real-time status indicators for SPF, DKIM, and DMARC with click-to-expand DNS record details and RFC 7489 alignment checks.
4. **Header Mismatch Matrix (`HeaderMismatchTable.tsx`)**:
   - Side-by-side alignment comparison of `From:`, `Return-Path:`, and `Reply-To:` headers.
   - Automated alerts for VIP display impersonation and Cyrillic homograph attacks.
5. **AI NLP Intent Viewer (`NlpIntentViewer.tsx`)**:
   - Highlights wire transfer requests (IFSC/IBAN), psychological coercion cues, and credential lures directly within email body text.
6. **Defanged IoC Table (`IocDataTable.tsx`)**:
   - Filterable indicator table with safe one-click defanging (`hxxps://`, `[.]`) and export to clipboard.
7. **Campaign & Cluster Relationship Graph (`CampaignGraph.tsx`)**:
   - Multi-node network graph linking related phishing incidents by shared ASN subnet, SimHash lexical fingerprint, or C2 domain.
8. **Statutory Audit Ledger (`AuditLedgerTable.tsx`)**:
   - Displays Section 63 BSA 2023 tamper-evident append-only ledger entries and HMAC-SHA256 non-repudiation signatures.
9. **Interactive Ingestion Modal (`IngestionModal.tsx`)**:
   - Drag-and-drop `.eml` and `.msg` file uploader with client-side WebCrypto SHA-256 calculation.
   - Raw RFC 822 MIME headers paste box with one-click demo case presets.

### Running the Frontend Dashboard:
```bash
cd frontend
npm install
npm run dev
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser to interact with the live SOC Analyst Dashboard.
*(Note: The frontend operates smoothly in standalone demo mode with built-in realistic mock cases even when the backend is offline).*

---

## ⚡ Phase 4 — Full-Stack Integration, One-Command Launch & Offline Resilience

### 1. Zero-Friction One-Command Startup
Launch the entire system (FastAPI backend + Next.js frontend + SQLite WAL database + automated browser launch) with a single command:

**On Windows:**
```cmd
start.bat
```
*or:*
```bash
python run_platform.py
```

**On Linux / macOS:**
```bash
chmod +x start.sh
./start.sh
```

### 2. Air-Gapped & Hackathon Offline Resilience
The platform is engineered to operate reliably in disconnected, air-gapped environments or behind strict institutional Wi-Fi firewalls:
- **Aggressive 1.5s DNS Timeout Protection (`auth_validator.py`)**: If DNS ports (UDP/TCP 53) are blocked or internet is absent, live DNS queries time out cleanly within 1.5s and fall back gracefully to pre-existing `Authentication-Results` and `Received-SPF` headers stamped inside the email.
- **Embedded Offline GeoIP Database (`geo_resolver.py`)**: Includes high-fidelity geolocation coordinates for Indian national institutions (NIC, ERNET, NKN, IITs, NITs), major Indian telecom ISPs, and known threat infrastructure so the Leaflet map renders reliably even without MaxMind `.mmdb` files.
- **Bundled Tor Exit Cache (`tor_exit_nodes.json` & `tor_detector.py`)**: Loads hundreds of active Tor exit nodes and bulletproof subnets directly from disk for 100% offline anonymizer triage.

### 3. Resolution of Top 6 Real-World Failure Points
| Failure Point | Cause in Typical Apps | Platform Bulletproof Resolution |
| :--- | :--- | :--- |
| **Fix 1: SSR Hydration** | Leaflet imports `window` on server render | Dynamic client-only import (`dynamic(..., { ssr: false })`) with custom loading skeletons in Next.js 14. |
| **Fix 2: Leaflet Grey Grid Tiles** | Sizing glitch inside CSS flex/grid cards | Bundled `leaflet/dist/leaflet.css` in globals + mounted `map.invalidateSize()` lifecycle hook. |
| **Fix 3: FastAPI CORS Rejections** | Browser blocking cross-origin API calls | Explicit `CORSMiddleware` configuration with origin regex and exposed Section 63 BSA headers. |
| **Fix 4: Corrupted Outlook .msg** | `extract-msg` raising unhandled exceptions | 3-tier resilient parser: OLE Compound -> EML MIME -> Fallback raw ASCII/UTF-8 regex scanner. |
| **Fix 5: Forged Header Attribution** | Attackers spoofing initial `Received:` lines | Reverse Hop-Traversal verifies downstream MTA trust boundaries and flags handoff discontinuities. |
| **Fix 6: PDF Download Incompatibilities** | Browser blocking blob URLs or octet streams | Standardized `StreamingResponse` with `application/pdf`, filename disposition, and exposed headers. |

### 4. End-to-End System Verification
Run the comprehensive verification suite at any time to validate the entire platform:
```bash
python verify_system.py
```
Expected Output:
```
================================================================================
   AICTE CYBER SECURITY CELL | SMART INDIA HACKATHON 2026 (SIH ID: 26106)
   AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
   END-TO-END FULL-STACK INTEGRATION & OFFLINE RESILIENCE VERIFIER
================================================================================

 [PASS] 1. Database & Cryptographic Vault                SQLite WAL Active | 9 Emails, 18 Hops, 9 Analyses, 29 IoCs in DB
 [PASS] 2. Air-Gapped & Offline Resilience               Embedded GeoIP OK | Tor Exit Cache OK | DNS 1.5s Timeout Guard OK
 [PASS] 3. E2E Forensic Ingestion & Geo Coordinates      Case UUID: bf1bf5e6... | Score: 94.0/100 | Verdict: BEC | 3 Geolocated Hops
 [PASS] 4. Section 63 BSA 2023 PDF Generation            Size: 6.1 KB | SHA-256: a705750a... | %PDF-1.4 Header Validated
 [PASS] 5. Campaign Cross-Incident Graph API             Graph Loaded: 16 Nodes, 15 Edges | Cytoscape / D3 Schema Valid

================================================================================
ALL SUBSYSTEMS VERIFIED & OPERATIONAL (Section 63 BSA 2023 Compliant)
Ready for Live Demonstration before AICTE Cyber Security Cell Jury.
================================================================================
```
