# Requirements Traceability Matrix: SIH Problem Statement 26106

**Smart India Hackathon (SIH 2026)**  
**Problem Statement ID:** 26106 (SIH26106)  
**Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Target Organization:** All India Council for Technical Education (AICTE) — Cyber Security Cell  
**Theme:** Blockchain & Cybersecurity  
**Category:** Software  
**Legal Admissibility Standard:** Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023  
**Status:** **AUTHORITATIVE** (Derived verbatim from official SIH portal json via `docs/PS_26106_OFFICIAL.json`, SHA-256: `6ad5eb7495824359871cddc038c01a80bd49a670e6a1a39891bc12e4f42e212f`)  
**Generation Mode:** Dynamically generated from verified gate execution artifacts (`evidence/gates/g*.json`).  

---

## 1. Official Problem Statement Text (Verbatim from SIH Portal)

### Background
> "Email continues to be one of the most widely used communication channels in government, education, banking, and enterprise ecosystems. However, it also remains one of the most exploited attack vectors for phishing, impersonation, business email compromise, financial fraud, credential theft, and malware delivery. Threat actors increasingly use spoofed domains, deceptive sender identities, social engineering techniques, and compromised infrastructure to send highly convincing fraudulent emails that appear legitimate to end users. Traditional email security controls such as spam filters, static blacklists, and rule-based signature mechanisms are often insufficient to detect sophisticated fraudulent emails. Attackers now use AI-generated language, domain lookalikes, display-name spoofing, hidden redirection links, and relay chains to evade standard detection systems. In many cases, even when a suspicious email is identified, organizations lack the technical capability to effectively trace the source path, identify probable sender infrastructure, correlate geolocation clues, and support investigation into the origin of the email. This gap creates major challenges for cybersecurity teams, law enforcement support, fraud response units, and institutional administrators who need not only to detect malicious emails but also to investigate their source and reveal indicators that may help identify the actor or infrastructure behind the attack."

### Problem Statement
> "Current email security ecosystems primarily focus on filtering or blocking suspicious content but provide limited intelligence for deep forensic tracing of fraudulent email origins. Existing tools often do not adequately correlate email headers, SMTP relay paths, SPF/DKIM/DMARC validation results, IP reputation, geolocation indicators, domain registration intelligence, and behavioral patterns to build a complete picture of the sender’s identity or operating location. There is a need for an AI-powered platform capable of detecting phishing, spoofed, impersonated, and fraudulent emails in real time or near real time, analyzing the complete technical structure of an email, tracing its transmission path across mail servers, estimating its origin with location, and generating forensic intelligence and investigative insights that assist in identifying malicious infrastructure, compromised systems, or threat actors behind the attack. The solution should support forensic analysis, fraud prevention, institutional email security, and investigation workflows while maintaining legal, privacy, and evidentiary standards."

### Proposed Solution
> "Develop an AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform that combines Natural Language Processing (NLP), Machine Learning (ML), email header forensics, IP intelligence, domain analysis, and graph-based correlation to identify suspicious emails, detect advanced email threats, and investigate their probable origin. The system should ingest raw email content, metadata, and headers; validate sender authentication mechanisms; extract indicators of compromise; reconstruct relay paths; analyze originating IP addresses and associated geolocation data; and generate a confidence-based assessment of fraud risk and probable sender origin. The platform should provide actionable alerts, visual trace maps, and forensic reports for security analysts, administrators, and investigators."

### Expected Outcomes
> 1. Early and accurate detection of fraudulent, spoofed, and phishing-based email attacks.
> 2. Improved ability to trace suspicious email origin paths and identify probable source infrastructure.
> 3. Enhanced fraud investigation capability through geolocation analysis, domain intelligence, and sender attribution support.
> 4. Reduced financial loss, reputational damage, and unauthorized disclosure of confidential information caused by email-based fraud.
> 5. Better institutional readiness for cyber incident response, forensic investigation, and enforcement coordination.

---

## 2. Sentence-by-Sentence Traceability Matrix

| Clause ID | Problem Statement Requirement / Sentence | Implementing Module | Verification Test | Gate | Generated Evidence File | Status |
|:---|:---|:---|:---|:---:|:---|:---:|
| **PS-BG-01** | *Detection of phishing, impersonation, BEC, financial fraud, credential theft, and malware delivery* | `backend/app/ai/nlp_engine.py`, `threat_scorer.py` | `backend/tests/test_ai_detection.py` | G07 | `evidence/model_card.md`, `evidence/evaluation.json` | **DONE** |
| **PS-BG-02** | *Defense against spoofed domains, deceptive sender identities, and display-name spoofing* | `backend/app/forensics/spoof_detector.py` | `backend/tests/test_ai_detection.py` | G07 | `evidence/model_card.md` | **DONE** |
| **PS-BG-03** | *Defense against hidden redirection links, obfuscated URLs, and evasion chains* | `backend/app/ai/url_analyzer.py` | `backend/tests/test_ai_detection.py` | G07 | `evidence/model_card.md` | **DONE** |
| **PS-BG-04** | *Tracing source path, sender infrastructure, and origin clues for law enforcement/cyber teams* | `backend/app/forensics/hop_traversal.py`, `campaign_clusterer.py` | `backend/tests/test_hop_traversal.py` | G06 | `evidence/real_headers_eval.json` | **DONE** |
| **PS-CORE-01** | *Correlate email headers, SMTP relay paths, SPF/DKIM/DMARC results, IP reputation, and domain intelligence* | `backend/app/forensics/auth_validator.py`, `hop_traversal.py`, `geo_resolver.py` | `backend/tests/test_protocol_auth.py`, `test_hop_traversal.py` | G06, G07 | `evidence/real_headers_eval.json`, `evidence/benchmark_results.json` | **DONE** |
| **PS-CORE-02** | *Detect phishing, spoofed, impersonated, and fraudulent emails in real time or near real time* | `backend/app/ai/threat_scorer.py`, `job_queue.py` | `backend/tests/test_pipeline.py`, `scripts/benchmark_e2e.py` | G13 | `evidence/benchmark_results.json` | **DONE** |
| **PS-CORE-03** | *Maintain legal, privacy, and evidentiary standards (Section 63 BSA 2023)* | `backend/app/reporting/pdf_generator.py`, `vault.py`, `models.py` | `backend/tests/test_pipeline.py`, `test_database.py` | G09 | `evidence/gates/g09.json` | **BLOCKED: awaiting Section 63 BSA Gazette statute text & human signatory attestation** |
| **PS-SOL-01** | *Ingest raw email content, metadata, headers, attachments, and carve .msg/.eml streams* | `backend/app/parsers/eml_parser.py`, `msg_parser.py`, `upload_validator.py` | `backend/tests/test_parsers_and_scoring_coverage.py` | G12 | `evidence/coverage.json` | **DONE** |
| **PS-SOL-02** | *Validate sender authentication mechanisms (SPF, DKIM, DMARC, ARC)* | `backend/app/forensics/auth_validator.py` | `backend/tests/test_protocol_auth.py` | G04 | `evidence/gates/g04.json` | **BLOCKED: awaiting >=20 real signed .eml in tests/fixtures/real/** |
| **PS-SOL-03** | *Reconstruct relay paths and extract originating IP from earliest reliable sending node* | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | G06 | `evidence/real_headers_eval.json` | **DONE** |
| **PS-SOL-04** | *Analyze originating IP addresses and associated geolocation data* | `backend/app/osint/geo_resolver.py` | `backend/tests/test_osint_geoip.py` | G05 | `evidence/gates/g05.json` | **BLOCKED: awaiting MaxMind License Key & ground_truth.csv** |
| **PS-SOL-05** | *Actionable alerts, visual trace maps, and forensic dashboard* | `frontend/src/app/page.tsx`, `components/` | `frontend/e2e/soc_journey.spec.ts` | G11 | `evidence/gates/g11.json`, `evidence/e2e/` | **DONE** |
| **PS-COMP-1A** | *NLP-based analysis of subject lines, body text, urgency cues, social engineering* | `backend/app/ai/nlp_engine.py` | `backend/tests/test_ai_detection.py` | G07 | `evidence/model_card.md` | **DONE** |
| **PS-COMP-1B** | *Detection of phishing indicators: spoofed senders, deceptive domains, dangerous attachments* | `backend/app/forensics/attachment_analyzer.py`, `spoof_detector.py` | `backend/tests/test_ai_detection.py` | G07 | `evidence/model_card.md` | **DONE** |
| **PS-COMP-1C** | *5-class AI/ML verdict: legitimate, suspicious, impersonated, phishing, fraud-related* | `backend/app/ai/threat_scorer.py`, `model_trainer.py` | `backend/tests/test_parsers_and_scoring_coverage.py` | G07 | `evidence/evaluation.json` | **DONE** |
| **PS-COMP-1D** | *Business email compromise detection: payment diversion, fake invoices, credential harvesting* | `backend/app/ai/nlp_engine.py` (Banking NER: IFSC, accounts, SWIFT) | `backend/tests/test_ai_detection.py` | G07 | `evidence/model_card.md` | **DONE** |
| **PS-COMP-2A** | *Deep header analysis: Return-Path, Received, Message-ID, Reply-To, DKIM, SPF, DMARC* | `backend/app/forensics/hop_traversal.py`, `auth_validator.py` | `backend/tests/test_hop_traversal.py` | G06 | `evidence/real_headers_eval.json` | **DONE** |
| **PS-COMP-2B** | *Detection of routing anomalies, forged sender fields, relay manipulation, clock skew (>300s)* | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | G06 | `evidence/real_headers_eval.json` | **DONE** |
| **PS-COMP-2C** | *Validation of authorized infrastructure vs suspicious relay paths* | `backend/app/forensics/auth_validator.py`, `hop_traversal.py` | `backend/tests/test_protocol_auth.py` | G04 | `evidence/gates/g04.json` | **BLOCKED: awaiting >=20 real signed .eml in tests/fixtures/real/** |
| **PS-COMP-3A** | *Earliest reliable sending node extraction & trust boundary isolation* | `backend/app/forensics/hop_traversal.py` | `backend/tests/test_hop_traversal.py` | G06 | `evidence/real_headers_eval.json` | **DONE** |
| **PS-COMP-3B** | *IP geolocation mapping (country, region, city, ISP, proxy status)* | `backend/app/osint/geo_resolver.py` | `backend/tests/test_osint_geoip.py` | G05 | `evidence/gates/g05.json` | **BLOCKED: awaiting MaxMind License Key & ground_truth.csv** |
| **PS-COMP-3C** | *Correlation with VPN, Tor, open relay, botnet, or cloud infrastructure* | `backend/app/osint/tor_detector.py`, `dnsbl_checker.py` | `backend/tests/test_osint_geoip.py` | G05 | `evidence/gates/g05.json` | **BLOCKED: awaiting MaxMind License Key & ground_truth.csv** |
| **PS-COMP-3D** | *Domain intelligence: WHOIS/RDAP, DNS, MX, newly registered domains (<30d)* | `backend/app/osint/whois_client.py` | `backend/tests/test_osint_geoip.py` | G05 | `evidence/gates/g05.json` | **BLOCKED: awaiting MaxMind License Key & ground_truth.csv** |
| **PS-COMP-4A** | *Confidence-based fraud scoring (0-100) with weighted mathematical formula* | `backend/app/ai/threat_scorer.py` | `backend/tests/test_parsers_and_scoring_coverage.py` | G07 | `evidence/model_card.md` | **DONE** |
| **PS-COMP-4B** | *Graph-based correlation & campaign clustering across multiple incidents* | `backend/app/forensics/campaign_clusterer.py` | `backend/tests/test_campaign_clusterer.py` | G08 | `evidence/cluster_eval.json` | **DONE** |
| **PS-COMP-4C** | *Interactive visual trace maps and SOC forensic dashboard with Cytoscape graph* | `frontend/src/app/page.tsx`, `components/` | `frontend/e2e/soc_journey.spec.ts` | G11 | `evidence/gates/g11.json`, `evidence/e2e/` | **DONE** |
| **PS-COMP-4D** | *Export court-admissible forensic report compliant with Section 63 BSA 2023* | `backend/app/reporting/pdf_generator.py` | `backend/tests/test_pipeline.py` | G09 | `evidence/gates/g09.json` | **BLOCKED: awaiting Section 63 BSA Gazette statute text & human signatory attestation** |

---

## 3. Statutory Attestation & Custody Field Traceability

| Field Category | Schedule Section | Extraction Mode | Admissibility Handling | Audit Verification Status |
|---|---|---|---|---|
| Technical Device Identifiers | Part A (1, 2) | Automated | Extracted from OS environment (Node, CPU, OS, MAC, UTC/IST timestamp) | **VERIFIED (Draft Mode)** |
| Cryptographic Dual Digest | Part A (6) | Automated | Simultaneous calculation of SHA-256 and SHA-512 hashes from raw MIME byte payload | **VERIFIED (HMAC & Hash-Chain Protected)** |
| Lawful Control Affirmation | Part A (3, 4, 5) | Manual | Checkbox selection & affirmative declaration by lawful custodian | **REQUIRES HUMAN ATTESTATION** |
| Expert Qualifications & Signature | Part B (1-4) | Manual | Certified Examiner / Digital Forensics Expert credentials and handwritten/digital signature | **REQUIRES HUMAN ATTESTATION** |
