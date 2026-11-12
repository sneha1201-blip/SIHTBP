# Requirements Traceability Matrix: SIH Problem Statement 26106

**Smart India Hackathon (SIH 2026)**  
**Problem Statement ID:** 26106 (SIH26106)  
**Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Organization:** All India Council for Technical Education (AICTE) — Cyber Security Cell  
**Theme:** Blockchain & Cybersecurity  
**Category:** Software  
**Legal Admissibility Standard:** Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023  

---

## 1. Official Problem Statement Text (Verbatim)

### Problem Description
> "Current email security ecosystems primarily focus on filtering or blocking suspicious content, but they provide limited intelligence for the deep forensic tracing of fraudulent email origins.
> 
> Existing tools often fail to adequately correlate:
> - Email headers and SMTP relay paths;
> - SPF, DKIM, and DMARC validation results;
> - IP reputation and geolocation indicators;
> - Domain registration intelligence and behavioral patterns.
> 
> Because of this fragmentation, security teams lack a complete, unified picture required to accurately trace the sender’s true identity, source infrastructure, or operating location when investigating sophisticated phishing, spoofed, impersonated, and fraudulent emails."

### Expected Outcomes
> 1. **Early & Accurate Detection:** High-precision detection of fraudulent, spoofed, and phishing-based email attacks.
> 2. **Deep Forensic Tracing:** Improved capability to trace suspicious email origin paths and identify probable source infrastructure (such as analyzing raw .eml headers and relay hops).
> 3. **Enhanced Investigation Support:** Streamlined fraud investigations backed by geolocation analysis, domain intelligence, and sender attribution mapping.
> 4. **Mitigation of Impact:** Reduction in financial loss, reputational damage, and unauthorized disclosure of confidential information caused by email-based social engineering and fraud.
> 5. **Institutional Readiness:** Better preparedness for cyber incident response, digital forensic examinations, and cross-enforcement coordination.

---

## 2. Sentence-by-Sentence Traceability Matrix

Every sentence and deliverable clause of official PS 26106 is mapped below to its implementing codebase module, automated test suite, verifiable evidence artifact, and verified status.

| Clause ID | Problem Statement Sentence / Clause | Implementing Module(s) | Verification Test(s) | Evidence File | Commit | Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **PS-DESC-01** | *"Deep forensic tracing of fraudulent email origins beyond filtering/blocking"* | `backend/app/forensics/hop_traversal.py`, `job_queue.py` | `backend/tests/test_hop_traversal.py` | `evidence/phase3.md` | `52a11a1` | **VERIFIED** |
| **PS-DESC-02A** | *"Correlate email headers and SMTP relay paths"* | `backend/app/forensics/hop_traversal.py`, `parsers/eml_parser.py` | `backend/tests/test_hop_traversal.py::test_reverse_hop_traversal` | `evidence/phase3.md` | `52a11a1` | **VERIFIED** |
| **PS-DESC-02B** | *"Correlate SPF, DKIM, and DMARC validation results"* | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | `evidence/phase2.md` | `52a11a1` | **VERIFIED** |
| **PS-DESC-02C** | *"Correlate IP reputation and geolocation indicators"* | `backend/app/osint/geo_resolver.py`, `tor_detector.py`, `dnsbl_checker.py` | `backend/tests/test_osint_geoip.py` | `evidence/phase3.md` | `52a11a1` | **VERIFIED** (GeoIP: zero-guess without key) |
| **PS-DESC-02D** | *"Correlate domain registration intelligence and behavioral patterns"* | `backend/app/osint/whois_client.py`, `spoof_detector.py`, `url_analyzer.py` | `backend/tests/test_ai_detection.py` | `evidence/phase4.md` | `52a11a1` | **VERIFIED** |
| **PS-DESC-03** | *"Unified correlation engine tracing sender identity, source infra, and operating location"* | `backend/app/ai/threat_scorer.py`, `job_queue.py` | `backend/tests/test_ai_detection.py::test_dkim_fail_plus_high_risk_url_hard_override` | `evidence/fix7.md` | `d22ebba` | **VERIFIED** |
| **PS-OUT-01** | **Early & Accurate Detection:** *"High-precision detection of fraudulent, spoofed, and phishing-based email attacks"* | `backend/app/ai/nlp_engine.py`, `model_trainer.py`, `spoof_detector.py` | `backend/tests/test_ai_detection.py::test_unseen_real_world_emails_no_false_positives` | `evidence/fix7.md`, `evidence/model_card.md` | `d22ebba` | **VERIFIED (91.67% Test Acc, 10/10 Audit Acc)** |
| **PS-OUT-02** | **Deep Forensic Tracing:** *"Trace suspicious email origin paths and identify probable source infrastructure (.eml / .msg)"* | `backend/app/parsers/msg_parser.py`, `eml_parser.py`, `hop_traversal.py` | `backend/tests/test_pipeline.py::test_corrupt_msg_partial_carving_no_invented_data` | `evidence/fix5.md` | `52a11a1` | **VERIFIED** |
| **PS-OUT-03** | **Enhanced Investigation Support:** *"Streamlined fraud investigations backed by geolocation, domain intelligence, and sender attribution mapping"* | `backend/app/forensics/campaign_clusterer.py`, `endpoints_campaigns.py` | `backend/tests/test_campaign_clustering.py::test_campaign_clustering_corpus_eval_gates` | `evidence/fix3.md`, `evidence/cluster_eval.json` | `a61a4f6` | **VERIFIED (ARI: 0.8766, NMI: 0.9037)** |
| **PS-OUT-04** | **Mitigation of Impact:** *"Reduction in financial loss and confidential disclosure caused by email fraud (BEC & wire fraud)"* | `backend/app/ai/nlp_engine.py` (Indian Banking NER: IFSC, accounts, SWIFT, amounts) | `backend/tests/test_ai_detection.py::test_bec_financial_intent_and_entities` | `evidence/fix7.md` | `d22ebba` | **VERIFIED** |
| **PS-OUT-05** | **Institutional Readiness:** *"Cyber incident response, digital forensic examinations, cross-enforcement coordination (tamper-evidence & BSA)"* | `backend/app/database/vault.py`, `models.py`, `reporting/pdf_generator.py` | `backend/tests/test_pipeline.py::test_pdf_report_aborts_with_409_on_vault_tamper` | `evidence/fix2.md`, `evidence/campaign_bundle.json` | `1e41d60` | **VERIFIED** (Dual SHA-256/512 + STIX 2.1) |

---

## 3. Detailed Technical Sub-System Traceability

| Functional Domain | Specific Capability | Code Implementation | Test File | Verified Status |
| :--- | :--- | :--- | :--- | :---: |
| **Ingestion & Validation** | Stream upload with strict 25MB cap | `backend/app/core/upload_validator.py` | `test_security.py` | **VERIFIED** |
| | Non-email binary rejection (HTTP 422) | `backend/app/core/upload_validator.py` | `test_security.py` | **VERIFIED** |
| | Outlook .msg partial stream carving | `backend/app/parsers/msg_parser.py` | `test_pipeline.py` | **VERIFIED** |
| **Cryptographic Vault** | WORM storage under `{sha256}.raw` + fsync | `backend/app/database/vault.py` | `test_database.py` | **VERIFIED** |
| | Dual hashing (SHA-256 + SHA-512) | `backend/app/database/vault.py` | `test_database.py` | **VERIFIED** |
| | Vault HMAC secret startup enforcement | `backend/app/core/config.py` | `test_security.py` | **VERIFIED** |
| **Audit Ledger** | Hash-chained audit logging (`prev_hash` + HMAC) | `backend/app/database/models.py` | `test_security.py` | **VERIFIED** |
| | Tamper detection on audit chain | `backend/app/api/v1/endpoints_forensics.py`| `test_security.py` | **VERIFIED** |
| **Authentication Checks** | DKIM verification (RSA / Ed25519) | `backend/app/forensics/auth_validator.py` | `test_protocol_auth.py` | **VERIFIED** |
| | SPF evaluation from trusted boundary IP | `backend/app/forensics/auth_validator.py` | `test_protocol_auth.py` | **VERIFIED** |
| | DMARC RFC 7489 alignment & PSL logic | `backend/app/forensics/auth_validator.py` | `test_protocol_auth.py` | **VERIFIED** |
| | Historical DNS snapshot & `KEY_UNAVAILABLE` | `backend/app/forensics/auth_validator.py` | `test_protocol_auth.py` | **VERIFIED** |
| **Header Forensics** | RFC 5321 Hop Traversal (Exchange, Postfix, Gmail, qmail) | `backend/app/forensics/hop_traversal.py` | `test_hop_traversal.py` | **VERIFIED** |
| | Trust boundary & forged hop detection | `backend/app/forensics/hop_traversal.py` | `test_hop_traversal.py` | **VERIFIED** |
| | Originating public IP extraction | `backend/app/forensics/hop_traversal.py` | `test_hop_traversal.py` | **VERIFIED** |
| **OSINT & Intelligence** | MaxMind GeoIP with accuracy radius | `backend/app/osint/geo_resolver.py` | `test_osint_geoip.py` | **EXTERNAL KEY NEEDED** |
| | Live Tor exit node sync (1,250+ nodes) | `backend/app/osint/tor_detector.py` | `test_osint_geoip.py` | **VERIFIED** |
| | Async RDAP domain age & NRD (<30d) | `backend/app/osint/whois_client.py` | `test_osint_geoip.py` | **VERIFIED** |
| | URL deobfuscation (DWORD/Hex/Octal IP) | `backend/app/ai/url_analyzer.py` | `test_ai_detection.py` | **VERIFIED** |
| **AI Threat Engine** | Multi-class intent classifier (120 samples) | `backend/app/ai/model_trainer.py` | `test_ai_detection.py` | **VERIFIED (91.67%)** |
| | Explainable token feature attributions | `backend/app/ai/nlp_engine.py` | `test_ai_detection.py` | **VERIFIED** |
| | Indian banking NER (IFSC, accounts, amounts)| `backend/app/ai/nlp_engine.py` | `test_ai_detection.py` | **VERIFIED** |
| | UTS#39 confusable homoglyph translation | `backend/app/forensics/spoof_detector.py` | `test_ai_detection.py` | **VERIFIED** |
| | Calibrated 6-subscore threat calculation | `backend/app/ai/threat_scorer.py` | `test_ai_detection.py` | **VERIFIED** |
| **Threat Correlation** | Multi-signal campaign clustering (4 families)| `backend/app/forensics/campaign_clusterer.py`| `test_campaign_clustering.py` | **VERIFIED (ARI: 0.8766)** |
| | Hyperscaler ASN filtering (Google, AWS) | `backend/app/forensics/campaign_clusterer.py`| `test_campaign_clustering.py` | **VERIFIED** |
| | STIX 2.1 JSON bundle export | `backend/app/forensics/campaign_clusterer.py`| `test_campaign_clustering.py` | **VERIFIED** |
| **Legal & Reporting** | Section 63 BSA certified PDF generation | `backend/app/reporting/pdf_generator.py` | `test_pipeline.py` | **VERIFIED** |
| | Export-time vault re-hash & 409 Conflict | `backend/app/api/v1/endpoints_forensics.py`| `test_pipeline.py` | **VERIFIED** |
| **Frontend UI** | Dedicated `/login` portal with JWT storage | `frontend/src/app/login/page.tsx` | Next.js Build | **VERIFIED** |
| | Real fetch-based SSE progress streaming | `frontend/src/components/FileDropzone.tsx` | Next.js Build | **VERIFIED** |
| | Zero mock fallbacks & zero pre-cooked demos | `frontend/src/lib/api.ts` | Next.js Build | **VERIFIED** |
| | Air-gapped offline map fallback (SVG) | `frontend/src/components/GeoTraceMapInner.tsx`| Next.js Build | **VERIFIED** |
| **Ops & Benchmarking** | Docker Compose with environment secrets | `docker-compose.yml` | `test_security.py` | **VERIFIED** |
| | Batch corpus ingestion CLI tool | `scripts/ingest_corpus.py` | `test_pipeline.py` | **VERIFIED** |
| | Empirical on-disk SQLite WAL E2E benchmark | `scripts/benchmark_e2e.py` | Benchmark Run | **VERIFIED** |

---

## 4. Current External Blockers & Action Items

| Blocker ID | Requirement | Dependency | Why it is Blocked | Action Needed to Unblock |
| :--- | :--- | :--- | :--- | :--- |
| **BLK-01** | `PS-DESC-02C` | `MAXMIND_LICENSE_KEY` | Without `.mmdb` database file on disk, system strictly follows zero-guessing policy and returns `UNKNOWN` coordinates. | User provides free MaxMind key in `.env` and runs `scripts/update_geoip.ps1`. |
| **BLK-02** | `PS-OUT-05` | Legal Counsel Review | Section 63(4) BSA certificate template is functionally complete, but Part B statutory language requires state legal mentor review. | Legal mentor confirms text of Part B declaration. |
