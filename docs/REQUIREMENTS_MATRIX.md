# Requirements Traceability Matrix (SIH Problem Statement ID: 26106)

**Problem Statement Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Organization:** AICTE Cyber Security Cell  
**Theme:** Blockchain & Cybersecurity  
**Standard of Compliance:** Section 63 of Bharatiya Sakshya Adhiniyam (BSA), 2023 / Section 65B Indian Evidence Act (IEA)

---

## 1. Traceability Matrix

| Req ID | Problem Statement Requirement | Implementing Module(s) | Verification Test(s) | Evidence File | Gate / Phase | Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **REQ-ING-01** | RFC 822 / MIME (.eml) parsing and structured extraction of headers, bodies, parts | `backend/app/parsers/eml_parser.py`, `mime_normalizer.py` | `backend/tests/test_pipeline.py::test_eml_parser` | `evidence/phase2.md` | Phase 2 | In Progress |
| **REQ-ING-02** | Microsoft Outlook (.msg) OLE compound stream parsing and fallback scanner | `backend/app/parsers/msg_parser.py` | `backend/tests/test_parsers.py::test_msg_parser` | `evidence/phase2.md` | Phase 2 | Planned |
| **REQ-ING-03** | Stream upload with strict file-size enforcement (max 25MB) before disk write | `backend/app/api/v1/endpoints_forensics.py` | `backend/tests/test_security.py::test_oversized_upload_rejected` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-ING-04** | Magic-byte and RFC 822 header validation; non-email binaries rejected with HTTP 422 | `backend/app/api/v1/endpoints_forensics.py`, `eml_parser.py` | `backend/tests/test_security.py::test_binary_upload_rejected` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-VLT-01** | Write-Once-Read-Many (WORM) physical storage under `{sha256}.raw` | `backend/app/database/vault.py` | `backend/tests/test_database.py::test_vault_store_and_read` | `evidence/phase0.md` | Phase 0 | Completed |
| **REQ-VLT-02** | Dual cryptographic checksumming (SHA-256 + SHA-512, MD5 legacy labeled) | `backend/app/database/vault.py` | `backend/tests/test_database.py::test_hash_calculation` | `evidence/phase0.md` | Phase 0 | Completed |
| **REQ-VLT-03** | Enforce uncompromised `VAULT_HMAC_SECRET` (refuse launch in non-DEBUG without key) | `backend/app/core/config.py`, `vault.py` | `backend/tests/test_security.py::test_vault_secret_enforced` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-AUD-01** | Hash-chained audit logging (each entry includes `prev_hash` + HMAC signature) | `backend/app/database/models.py`, `vault.py` | `backend/tests/test_security.py::test_hash_chained_audit_log` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-AUD-02** | Endpoint and verification script to detect audit log tampering or break in chain | `backend/app/api/v1/endpoints_forensics.py` | `backend/tests/test_security.py::test_tampered_audit_chain_detection` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-SEC-01** | JWT Authentication & Role-Based Access Control (ANALYST, ADMIN, AUDITOR) | `backend/app/core/security.py`, `backend/app/api/v1/endpoints_auth.py` | `backend/tests/test_security.py::test_rbac_permissions` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-SEC-02** | Sanitization against SQLi, Path Traversal (`file_name`), and Header Injection | `backend/app/api/v1/endpoints_forensics.py` | `backend/tests/test_security.py::test_path_traversal_sanitization` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-AUT-01** | Real DKIM verification using `dkimpy` against raw bytes and live DNS TXT keys | `backend/app/forensics/auth_validator.py` | `backend/tests/test_auth.py::test_dkimpy_real_verification` | `evidence/phase2.md` | Phase 2 | Planned |
| **REQ-AUT-02** | Real SPF evaluation using `pyspf` from trusted originating hop IP with HELO/MAIL FROM | `backend/app/forensics/auth_validator.py` | `backend/tests/test_auth.py::test_pyspf_real_evaluation` | `evidence/phase2.md` | Phase 2 | Planned |
| **REQ-AUT-03** | Real DMARC RFC 7489 evaluation with strict/relaxed alignment & Public Suffix List | `backend/app/forensics/auth_validator.py` | `backend/tests/test_auth.py::test_dmarc_rfc7489_alignment` | `evidence/phase2.md` | Phase 2 | Planned |
| **REQ-AUT-04** | Historical DNS key handling: explicit `KEY_UNAVAILABLE` status, DNS snapshot stored | `backend/app/forensics/auth_validator.py` | `backend/tests/test_auth.py::test_historical_key_handling` | `evidence/phase2.md` | Phase 2 | Planned |
| **REQ-HOP-01** | Full RFC 5321 `Received:` parsing across MTA variants (Exchange, Postfix, Gmail, qmail) | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_pipeline.py::test_reverse_hop_traversal` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-HOP-02** | Trust boundary evaluation: flag forged hops injected downstream/upstream | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hops.py::test_forged_hop_discrimination` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-HOP-03** | Originating IP extraction: true public IP after boundary, normalized timezone delays | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hops.py::test_originating_ip_extraction` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-GEO-01** | MaxMind GeoLite2-City & ASN resolution with accuracy radius, DB version reporting | `backend/app/osint/geo_resolver.py`, `asn_lookup.py` | `backend/tests/test_geo.py::test_maxmind_real_resolution` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-GEO-02** | Eliminate hardcoded 30-prefix table & first-octet guessing; return `null` with reason | `backend/app/osint/geo_resolver.py` | `backend/tests/test_geo.py::test_unknown_ip_null_handling` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-TOR-01** | Live Tor exit list fetching from `check.torproject.org` with TTL caching & age label | `backend/app/osint/tor_detector.py` | `backend/tests/test_osint.py::test_tor_live_list_fetch` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-RDP-01** | Async RDAP client via IANA bootstrap for domain age, registrar, and NRD detection | `backend/app/osint/whois_client.py` | `backend/tests/test_osint.py::test_rdap_client_iana` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-URL-01** | URL de-obfuscation (nested percent-encoding, hex/octal/dword IP hosts, punycode) | `backend/app/ai/url_analyzer.py` | `backend/tests/test_pipeline.py::test_url_deobfuscation` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-URL-02** | Integration with open phishing feeds (PhishTank/OpenPhish) downloaded & versioned | `backend/app/osint/feed_manager.py` | `backend/tests/test_osint.py::test_feed_matching` | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-ML-01** | Trained classifier pipeline (TF-IDF + LogReg/LightGBM & fine-tuned transformer) | `backend/app/ai/nlp_engine.py`, `model_registry.py` | `backend/tests/test_ai.py::test_intent_classifier` | `evidence/phase4.md` | Phase 4 | Planned |
| **REQ-ML-02** | Token-level entity extraction (IFSC, amounts, deadlines, orgs) via spaCy NER | `backend/app/ai/nlp_engine.py` | `backend/tests/test_ai.py::test_ner_entity_extraction` | `evidence/phase4.md` | Phase 4 | Planned |
| **REQ-ML-03** | Calibrated composite threat score (0-100) with Platt/isotonic scaling & SHAP weights | `backend/app/ai/threat_scorer.py` | `backend/tests/test_ai.py::test_calibrated_scoring` | `evidence/phase4.md` | Phase 4 | Planned |
| **REQ-ML-04** | UTS#39 confusable character and IDN homograph detection | `backend/app/forensics/spoof_detector.py` | `backend/tests/test_pipeline.py::test_spoof_detection_vip_and_homograph` | `evidence/phase4.md` | Phase 4 | Planned |
| **REQ-ATT-01** | Attachment inspection: macro presence via oletools, double extensions, archive triage | `backend/app/forensics/attachment_analyzer.py` | `backend/tests/test_attachments.py::test_macro_detection` | `evidence/phase4.md` | Phase 4 | Planned |
| **REQ-CMP-01** | Dynamic campaign clustering using SimHash Hamming distance (< 10) & shared infra | `backend/app/forensics/clustering.py`, `endpoints_campaigns.py` | `backend/tests/test_campaigns.py::test_dynamic_clustering` | `evidence/phase5.md` | Phase 5 | Planned |
| **REQ-CMP-02** | Network graph relationship generation (NetworkX graph algorithms) | `backend/app/api/v1/endpoints_campaigns.py` | `backend/tests/test_campaigns.py::test_graph_generation` | `evidence/phase5.md` | Phase 5 | Planned |
| **REQ-REP-01** | Section 63 BSA 2023 certified PDF with dual SHA-256 + SHA-512 hashes & audit trail | `backend/app/reporting/pdf_generator.py` | `backend/tests/test_pipeline.py::test_forensic_pdf_generation` | `evidence/phase6.md` | Phase 6 | Planned |
| **REQ-REP-02** | Tamper detection on export: modified vault byte triggers explicit export rejection | `backend/app/reporting/pdf_generator.py` | `backend/tests/test_reports.py::test_tampered_vault_export_fails` | `evidence/phase6.md` | Phase 6 | Planned |
| **REQ-FND-01** | Purge mock fallbacks in frontend `api.ts`; render explicit error states on network drop | `frontend/src/lib/api.ts`, `app/page.tsx` | `frontend/__tests__/api_error_handling.test.tsx` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-FND-02** | Remove client-side scenario switcher; ingest real emails via dropzone/API | `frontend/src/components/TopBar.tsx`, `FileDropzone.tsx` | `frontend/__tests__/ingestion_flow.test.tsx` | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-FND-03** | Fix HTML entity leak (`&lt;` / `&gt;`) in HeaderMismatchTable | `frontend/src/components/HeaderMismatchTable.tsx` | Visual inspection & component unit test | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-FND-04** | Render all 6 subscores on ThreatScoreGauge | `frontend/src/components/ThreatScoreGauge.tsx` | Visual inspection & component unit test | `evidence/phase1.md` | Phase 1 | Planned |
| **REQ-FND-05** | Air-gapped offline map fallback (bundled GeoJSON/PMTiles) | `frontend/src/components/GeoTraceMapInner.tsx` | Network-disabled Playwright test | `evidence/phase3.md` | Phase 3 | Planned |
| **REQ-FND-06** | Force-directed or Cytoscape.js campaign graph with pan/zoom and no overlap | `frontend/src/components/CampaignGraph.tsx` | Visual inspection with 50+ nodes | `evidence/phase5.md` | Phase 5 | Planned |
| **REQ-OPS-01** | Production Docker Compose (`api`, `worker`, `redis`, `db`, `frontend`) | `docker-compose.yml`, `Dockerfile.backend`, `Dockerfile.frontend` | Clean container startup test | `evidence/benchmarks.md` | Deliverable | Planned |
| **REQ-OPS-02** | GitHub Actions CI with Ruff, Mypy, ESLint, TypeScript compiler, Pytest | `.github/workflows/ci.yml` | GitHub Actions workflow execution | `evidence/phase0.md` | Phase 0 | In Progress |
| **REQ-OPS-03** | Alembic database migration management (no `--reset` in production) | `alembic.ini`, `backend/alembic/` | `backend/tests/test_migrations.py` | `evidence/phase0.md` | Phase 0 | In Progress |

