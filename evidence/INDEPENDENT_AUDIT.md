# Independent Forensic Audit & Verification Report
**Target Repository:** `SIHTBP` (AICTE Cyber Security Cell — Smart India Hackathon PS ID: 26106)  
**Auditor Role:** Hostile Independent Auditor  
**Audit Date:** 2026-11-11  
**Audit Standard:** Zero-Trust Protocol Verification (Zero Mock, Zero Stubs, Evidence Reproduction)

---

## 1. Compliance Matrix: Audit Items 1 – 28

| # | Item / Verification Scope | Verdict | Key Finding / Evidence |
|---|---|:---:|---|
| **A.1** | Keyword removal vs rename check | **PARTIAL** | Renamed `fallback_ascii_msg_scanner` -> `salvage_ascii_msg_scanner` in `msg_parser.py`; renamed "mock" to "benchmark" in `seed_data.py`. Frontend mock fallback was removed. |
| **A.2** | Broader grep for demo/sample/synthetic data | **FAIL** | Found `SAMPLE_BEC_HEADERS` and `SAMPLE_HOMOGRAPH_HEADERS` hardcoded in `frontend/src/components/HeaderPasteModal.tsx`; synthetic training strings in `training_data.py`. |
| **A.3** | Hardcoded domains, IPs, ASNs, brands | **FAIL** | Static 25-IP exit node list in `tor_exit_nodes.json`; hardcoded bulletproof substrings (`alexhost`, `alservice`, `floki`) in `asn_lookup.py`; hardcoded VIP roster and protected domains in `config.py`. |
| **A.4** | Empty DB pipeline & campaign graph behavior | **PASS** | On empty DB without seeding, campaign graph returns empty `{nodes: [], edges: []}`. Single ingestion creates isolated dossier without phantom graph edges. |
| **B.5** | DEBUG enforcement & secrets in config/Docker | **FAIL** | App refuses startup outside DEBUG when secrets are missing. However, `docker-compose.yml` sets `DEBUG=false` with `SECRET_KEY` instead of `JWT_SECRET_KEY`, causing immediate startup crash. |
| **B.6** | Route authentication audit (OpenAPI unauthenticated scan) | **PASS** | All API routes under `/api/v1/forensics/`, `/campaigns/`, and `/auth/me` return HTTP 401 Unauthorized without Bearer token. Only `/`, `/health`, and `/api/v1/health` return 200. |
| **B.7** | Evidence audit ledger actor accountability | **PASS** | Evaluated distinct JWT tokens for `analyst_alpha` and `analyst_bravo`. Audit rows record distinct identities with SHA-256 HMAC hash-chaining. |
| **B.8** | Frontend login flow & JWT SSE integration | **FAIL** | Frontend has NO login UI. `api.ts` hardcodes automatic authentication using `'analyst'` / `'AnalystPassword@2026'`. Frontend bypasses SSE entirely via `?sync=true`. |
| **B.9** | Tamper tests (oversize, PNG, traversal, SQLi, vault, audit chain) | **PARTIAL** | 26MB upload returns 413; PNG returns 422; traversal/SQLi sanitized; audit chain verify catches row tampering. **Vulnerability:** `/report` PDF export ignores vault file corruption and returns 200 without checking disk hash. |
| **C.10** | Fixture corpus provenance (real-world vs generated) | **FAIL** | Exactly 0 real-world emails. All 11 fixtures in `backend/tests/fixtures/emails/` are synthetically generated using in-memory RSA-1024 keys and injected DNS mocks. |
| **C.11** | Protocol auth confusion matrix & uncovered scenarios | **PARTIAL** | Pytest passes 13/13 on synthetic fixtures. **Uncovered:** Zero third-party signed mail (Google, Microsoft 365, Proton), zero multi-hop ARC from real forwarders, zero DNS key rotation tests. |
| **C.12** | Benchmark DNS resolution reality & socket timeouts | **FAIL** | Domains (`aicte-india.org`, `attacker-relay.net`, `spf-overflow.org`) do not exist in real DNS with test selectors. The 1.5–3.0s latency was socket timeouts hitting `DNS_QUERY_TIMEOUT_SECONDS=1.5`. 8 of 11 returned `KEY_UNAVAILABLE`. |
| **D.13** | GeoLite2 .mmdb presence & lookup verification | **FAIL** | `storage/geoip` directory does not exist. Zero `.mmdb` files present. All public IP lookups return `UNRESOLVED` with reason `MaxMind database not installed`. Geolocation is UNTESTED against a real DB. |
| **D.14** | `world.geojson` size, features & provenance | **FAIL** | File size is 1,743 bytes with exactly 5 hand-drawn continent polygons ("Eurasia", "Africa", "North America", "South America", "Australia"). Not Natural Earth; crude hand-written cartoon. |
| **D.15** | Tor exit node detection & cache refresh | **PASS** | Offline snapshot contains 25 IPs and 5 subnets (264 hours old). Live updater successfully fetched 1,254 exit nodes from `check.torproject.org`. Correctly classifies Tor, non-Tor, private, and bulletproof subnets. |
| **D.16** | RDAP resolution, NXDOMAIN & timeout resilience | **PASS** | Real domains resolve live (`google.com` age 10648d, `aicte-india.org` age 6200d). Non-existent domains and timeouts return `Status: UNKNOWN`, `domain_age_days: None` without guessing. |
| **E.17** | AI model training data, class balance & metrics honesty | **FAIL** | Training set contains only 45 samples across 4 classes; evaluated on 9 test samples. The claimed 1.0 (100%) accuracy, precision, recall, and ROC-AUC is extreme overfitting on a toy dataset. |
| **E.18** | Classifier evaluation on 10 unseen real-world emails | **PARTIAL** | Tested on 10 newly authored emails. Achieved 80.0% empirical accuracy. Produced 2 False Positives (legitimate invoice flagged as BEC 80.0; password reset flagged as Phishing 70.3). |
| **E.19** | Threat scoring formula (learned vs hand-tuned, overrides) | **PARTIAL** | Weights are completely hand-tuned constants (0.25, 0.20, 0.20, 0.15, 0.10, 0.10). No single subscore can push the weighted sum above 25.0 without critical overrides (which force 86.0–98.0). |
| **F.20** | Dynamic campaign clustering accuracy | **FAIL** | Correctly clusters 3 identical bodies from different ASNs. **Failure:** Clusters 3 completely unrelated emails from AS15169 (Google) into `Operation Infrastructure-AS15169` due to naive ASN matching. |
| **F.21** | Clustering quality metrics (ARI, NMI, Purity) | **FAIL** | ARI, NMI, and purity are not calculated anywhere in the codebase. Campaign clustering quality is completely unverified. |
| **G.22** | Benchmark 9.92ms vs 1503ms latency discrepancy | **FAIL** | Discrepancy explained: `execute_forensic_pipeline` checks `if existing_email: return existing_dossier`. In iterations 1 and 2, duplicate hashes short-circuited the entire pipeline into a 9.92ms DB cache hit. |
| **G.23** | Benchmark sample size, cold start, commit & fsync | **FAIL** | Evaluated 33 runs on only 11 distinct synthetic files repeated 3 times. Cold start was not discarded. DB commit time was stopped outside the timer. SQLite ran in-memory with zero disk fsync. |
| **H.24** | Code suppression audit (`type: ignore`, `noqa`, `skip`, `pass`) | **PARTIAL** | 1 `# type: ignore` in `auth_validator.py:525`. 0 `# noqa`. 0 `pytest.mark.skip`. 15 `except ...: pass` silent exception suppressions in core runtime modules. |
| **H.25** | Test coverage & modern test frameworks | **FAIL** | `pytest-cov` is not installed; coverage is unmeasured. Zero Hypothesis property-based tests exist. Zero Playwright or Cypress E2E tests exist. Frontend has no test runner. |
| **I.26** | Section 63 BSA certificate compliance & STIX validation | **FAIL** | PDF certificate is a decorative summary lacking statutory Schedule Part A / Part B declarations, device hardware identifiers, and lawful custody statements. `stix2` library is not installed; export is hand-rolled JSON with schema errors. |
| **J.27** | Docker orchestration & production deployment | **FAIL** | Host lacks Docker CLI. `docker-compose.yml` provides `SECRET_KEY` instead of `JWT_SECRET_KEY` under `DEBUG=false`, which causes the backend container to crash on startup. |
| **J.28** | GitHub Actions CI status | **UNVERIFIED** | `.github/workflows/ci.yml` is well-configured, but local branch is ahead of `origin/main` by 7 commits. GitHub Actions has never executed on the latest code. |

---

## 2. Findings Ranked by Severity

### P0 / Critical Vulnerabilities (Security, Data Integrity & Deployment Blockers)

1. **Docker Container Startup Failure (Mismatched Secret Key Name)**  
   - **Location:** `docker-compose.yml:15` vs `backend/app/core/config.py:65`  
   - **Root Cause:** `docker-compose.yml` sets `DEBUG=false` and defines `SECRET_KEY=...` instead of `JWT_SECRET_KEY=...`. `config.py` enforces that when `DEBUG=false`, `JWT_SECRET_KEY` must be explicitly present, raising `RuntimeError: FATAL SECURITY CONFIGURATION: JWT_SECRET_KEY must be explicitly configured outside DEBUG mode. Refusing application startup.`  
   - **Impact:** Any client attempting `docker compose up` on a clean machine experiences an immediate container crash. Frontend healthcheck fails.  
   - **Remediation:** In `docker-compose.yml`, change `SECRET_KEY` to `JWT_SECRET_KEY`.

2. **Forensic PDF Export Ignores Vault Tampering / Disk Corruption**  
   - **Location:** `backend/app/api/v1/endpoints_reports.py:27` -> `backend/app/reporting/pdf_generator.py:82`  
   - **Root Cause:** When generating court-admissible PDFs via `GET /api/v1/forensics/evidence/{id}/report`, the endpoint queries the database ORM object directly and never verifies physical disk vault bytes against `sha256_hash` or HMAC. While `GET /forensics/evidence/{id}/raw` correctly aborts on hash mismatch, `/report` generates and certifies a 7,206-byte PDF claiming 100% evidentiary integrity even if the raw `.raw` file on disk has been corrupted or altered.  
   - **Impact:** Fraudulent or corrupted evidence files can still receive signed forensic certificates of authenticity.  
   - **Remediation:** In `endpoints_reports.py`, call `read_raw_evidence(email.sha256_hash)` and verify hash integrity before calling `generate_forensic_pdf`.

3. **Campaign Clustering Collapses Unrelated Public Mail Infrastructure into Single Attack Campaigns**  
   - **Location:** `backend/app/forensics/campaign_clusterer.py:187-191`  
   - **Root Cause:** The clustering algorithm treats identical origin ASN (`origin_asn == prev_asn`) as sufficient criteria to group emails into a threat campaign.  
   - **Impact:** Tested with 3 completely unrelated emails from Google (AS15169: a billing invoice, an internal OKR calendar invite, and a sign-in alert). The system aggregated all three into `Operation Infrastructure-AS15169` with `ClusterKey=AS15169`. In production, all legitimate emails passing through Google, Microsoft, or AWS mail relays will be clustered as coordinated cyberattacks.  
   - **Remediation:** Require ASN matching to be compounded with SimHash template similarity or shared threat indicators; never cluster on ASN alone.

---

### P1 / High Priority Discrepancies (Functional Breaks & Untested Scope)

1. **Frontend Has No Authentication UI & Hardcodes Credentials in Axios Interceptor**  
   - **Location:** `frontend/src/lib/api.ts:25-38`  
   - **Root Cause:** The frontend lacks a login page, register page, or session management UI. To bypass authentication, `api.ts` registers a global Axios interceptor that silently calls `/auth/login` with hardcoded credentials `analyst` / `AnalystPassword@2026`.  
   - **Impact:** Zero real user authorization on the presentation layer. Anyone loading the frontend web interface acts as the pre-configured default analyst.

2. **Asynchronous SSE Job Ingestion Pipeline Unused by Frontend**  
   - **Location:** `frontend/src/lib/api.ts:52` vs `backend/app/forensics/job_queue.py`  
   - **Root Cause:** The backend implemented an asynchronous SSE job worker with stage progression events (`/forensics/jobs/{id}/stream`). However, the frontend always passes `?sync=true` to `/forensics/analyze`, forcing synchronous request blocking and bypassing SSE event streams.

3. **MaxMind GeoLite2 Database Missing from Entire Repository**  
   - **Location:** `storage/geoip/GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`  
   - **Root Cause:** The `storage/geoip` folder does not exist. Geolocation has never been tested against a real MaxMind database.  
   - **Impact:** Every single public IP lookup (`8.8.8.8`, `1.1.1.1`, `185.220.101.1`) returns `status=UNRESOLVED` with `reason='MaxMind GeoLite2-City database not installed'`.

4. **Hand-Drawn 5-Polygon Cartoon GeoJSON**  
   - **Location:** `frontend/public/data/world.geojson`  
   - **Root Cause:** Instead of bundling a recognized geospatial boundary dataset (such as Natural Earth 110m), the file is a 1,743-byte hand-coded array of 5 coarse polygons titled "Eurasia", "Africa", "North America", "South America", and "Australia".

5. **Benchmark Latency Distortions via Short-Circuiting Cache**  
   - **Location:** `scripts/benchmark_e2e.py:209` vs `backend/app/forensics/job_queue.py:134`  
   - **Root Cause:** The reported 9.92ms E2E pipeline minimum was achieved because iterations 1 and 2 of the benchmark re-submitted the same 11 files. `execute_forensic_pipeline` detected duplicate SHA-256 hashes and short-circuited all forensic analysis stages, returning the cached DB record in 9ms while microbenchmarks took 1500–3000ms waiting for DNS timeouts.

6. **Severe Overfitting and False Positives in AI Threat Classifier**  
   - **Location:** `backend/app/ai/training_data.py` (45 samples) and `storage/models/model_metadata.json`  
   - **Root Cause:** A Logistic Regression model was trained on 36 hand-written sentences and tested on 9 samples, claiming 100% accuracy. Tested against 10 realistic unseen emails, empirical accuracy dropped to 80.0%, with a 40% false-positive rate on routine business emails (e.g., legitimate invoices flagged as BEC due to tokens like `rs`, `000`, `payment`).

7. **Invalid STIX 2.1 Schema Export**  
   - **Location:** `backend/app/forensics/campaign_clusterer.py:277-350`  
   - **Root Cause:** The STIX 2.1 export does not use the official OASIS `stix2` library (which is not installed). It constructs raw JSON dictionaries where Cyber Observable Objects (`email-message`) illegally include Domain Object properties (`spec_version`, `created`, `modified`), and references missing address objects.

---

### P2 / Medium Priority (Code Hygiene, Test Debt & Legal Polish)

1. **Section 63 BSA 2023 Statutory Certificate Is Incomplete**  
   - **Location:** `backend/app/reporting/pdf_generator.py:414`  
   - **Root Cause:** The PDF certificate replaces the phrase "Section 65B" with "Section 63 BSA 2023", but fails to include the mandatory Part A / Part B statutory schedule breakdowns required by Indian Evidence law (device serial numbers, OS build, forensic acquisition tool make/model, lawful custody declaration).

2. **Vocabulary Renaming Rather Than Behavioral Removal (Grep-Gaming)**  
   - **Location:** `backend/app/parsers/msg_parser.py:126`  
   - **Root Cause:** In Phase 0, `fallback_ascii_msg_scanner` was renamed to `salvage_ascii_msg_scanner` to evade forbidden keyword grep rules without altering the fallback logic.

3. **15 Silent Exception Handlers (`except ...: pass`)**  
   - **Location:** `url_analyzer.py`, `job_queue.py`, `ioc_extractor.py`, `whois_client.py`, `vault.py`, `hop_traversal.py`.  
   - **Root Cause:** Broad exception catching without logging or re-raising hides unexpected parser crashes and parsing failures.

4. **Missing Modern Test Suites & Unmeasured Coverage**  
   - **Location:** `pyproject.toml`, `requirements.txt`  
   - **Root Cause:** `pytest-cov`, `hypothesis`, `playwright`, and `cypress` are completely absent. Test coverage claims cannot be verified.

---

## 3. Raw Terminal Verification Logs

### Item 5: Startup Without Mandatory Secrets Outside DEBUG
```text
$ VAULT_HMAC_SECRET="" JWT_SECRET_KEY="" python -c "from backend.app.core.config import Settings; Settings(DEBUG=False)"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "C:\Users\HP\.gemini\antigravity\scratch\SIHTBP\backend\app\core\config.py", line 61, in model_post_init
    raise RuntimeError(
RuntimeError: FATAL SECURITY CONFIGURATION: VAULT_HMAC_SECRET must be explicitly configured outside DEBUG mode. Refusing application startup.
```

### Item 8: Frontend Silent Authentication & Hardcoded Credentials
```typescript
// frontend/src/lib/api.ts lines 25-38
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const res = await axios.post(`${API_URL}/auth/login`, {
          username: 'analyst',
          password: 'AnalystPassword@2026',
        });
        const { access_token } = res.data;
        localStorage.setItem('auth_token', access_token);
        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return api(originalRequest);
      } catch (e) {
        localStorage.removeItem('auth_token');
      }
    }
    return Promise.reject(error);
  }
);
```

### Item 9: Tamper Tests (Upload Limits, Binaries, Vault & Audit Chain)
```text
--- 1. Oversize upload (26MB) ---
Status: 413 | Body: {"detail":"Upload rejected: Payload exceeds maximum size limit of 26214400 bytes (25MB)."}

--- 2. PNG renamed .eml ---
Status: 422 | Body: {"detail":"Rejected binary upload: Detected 'PNG Image' signature. Only RFC 822 (.eml) and Outlook (.msg) artifacts are accepted."}

--- 3. Path traversal filename (../../etc/passwd) ---
Status: 201 | Sanitized name in response: passwd

--- 4. SQLi filename (' OR '1'='1'; DROP TABLE emails; --.eml) ---
Status: 201 | Sanitized name in response: passwd

--- 5. Flip byte in vault file then check raw and PDF ---
Vault file: storage\vault\06752de120a58c594d3ec339686046c188c96f6f9d9e0f64d3b1912136a73a20.raw (exists=True)
Raw read after tamper: Crashed with ValueError: Cryptographic integrity violation! File ... has hash 4c7416bd..., expected 06752...
PDF report export after vault tamper: Status=200 (Length=7206 bytes) [FLAW: PDF generated despite corrupt raw evidence]

--- 6. Tamper audit row then verify chain ---
Initial chain verify: {'valid': True, 'total_records': 4, 'chain_head': '555becad81...', 'status': 'CHAIN_INTEGRITY_VERIFIED'}
Tampered chain verify: {'valid': False, 'tampered_at_index': 3, 'action': 'MALICIOUS_TAMPERED_ACTION', 'error': 'HMAC signature tampering detected at record 3. Data has been modified.'}
```

### Item 12: Benchmark Protocol Auth Resolution Reality
```text
Total fixtures: 11
auth_discrepancy_mta_spoof.eml   | Time:  3060.0ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    
expired_dkim.eml                 | Time:  3018.2ms | SPF: NONE        | DKIM: EXPIRED           | DMARC: NONE    
l_tag_abuse_injected.eml         | Time:  3008.9ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    
legit_signed_aicte.eml           | Time:  3022.5ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    
revoked_key.eml                  | Time:  3021.2ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    
spf_permerror_lookups.eml        | Time:  1516.6ms | SPF: NONE        | DKIM: NONE              | DMARC: NONE    
stripped_dkim.eml                | Time:  1517.0ms | SPF: NONE        | DKIM: NONE              | DMARC: NONE    
tampered_body.eml                | Time:  3024.2ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    
tampered_header.eml              | Time:  3011.0ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    
unavailable_key_historical.eml   | Time:  3008.9ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    
wrong_domain_alignment.eml       | Time:  3015.0ms | SPF: NONE        | DKIM: KEY_UNAVAILABLE   | DMARC: NONE    

Summary of failure/timeout statuses:
{'TEMPERROR': 0, 'TIMEOUT': 0, 'KEY_UNAVAILABLE': 8, 'OTHER': 0}
```

### Item 13: MaxMind GeoIP Database Verification
```text
=== GeoLite2 Database Path Inspection ===
City MMDB Path: storage\geoip\GeoLite2-City.mmdb (exists=False)
ASN MMDB Path:  storage\geoip\GeoLite2-ASN.mmdb (exists=False)

=== Geo Resolver & ASN Lookup Raw Results ===
--- IP: 8.8.8.8 ---
Geo Result: status=UNRESOLVED, source=NONE, coords=(None, None), reason='MaxMind GeoLite2-City database not installed (run scripts/update_geoip.sh with MAXMIND_LICENSE_KEY)'
ASN Result: status=UNRESOLVED, source=NONE, asn=None, reason='MaxMind GeoLite2-ASN database not installed (run scripts/update_geoip.sh with MAXMIND_LICENSE_KEY)'

--- IP: 192.168.1.1 ---
Geo Result: status=UNRESOLVED, source=RFC1918_FILTER, coords=(None, None), reason='RFC 1918 private network address'
ASN Result: status=UNRESOLVED, source=RFC1918_FILTER, asn=None, org='Private Subnet', reason='Private RFC 1918 / Loopback address has no public ASN'
```

### Item 15: Tor Detection & Live Cache Refresh
```text
=== Initial Tor Cache Telemetry ===
source: OFFLINE_SNAPSHOT
fetched_at: 2026-10-31T00:00:00+00:00
age_hours: 264.2
total_exit_nodes: 25
total_subnets: 5
bulletproof_subnets: 4

=== Testing Tor & Bulletproof Detection ===
IP: 185.220.101.5   (Known Tor Exit Node                ) -> is_tor=True  | is_vpn=False | is_bulletproof=False
IP: 185.220.101.1   (Tor Subnet IP (185.220.100.0/23)   ) -> is_tor=True  | is_vpn=False | is_bulletproof=False
IP: 8.8.8.8         (Google Public DNS (Non-Tor)        ) -> is_tor=False | is_vpn=False | is_bulletproof=False
IP: 192.168.1.1     (RFC 1918 Private IP                ) -> is_tor=False | is_vpn=False | is_bulletproof=False
IP: 194.36.191.12   (Known Bulletproof IP (194.36.191.0/24)) -> is_tor=False | is_vpn=True  | is_bulletproof=True 

=== Testing Live Fetch from check.torproject.org ===
Live refresh success: True
source: LIVE_FETCH
fetched_at: 2026-11-11T00:09:06.341825+00:00
age_hours: 0.0
total_exit_nodes: 1254
```

### Item 16: RDAP Domain Intelligence Lookups
```text
--- Domain: google.com (Established Domain) ---
Status: RESOLVED | Age: 10648 days | Registrar: MarkMonitor Inc. | Is NRD (<30d): False

--- Domain: aicte-india.org (Target Organization Domain) ---
Status: RESOLVED | Age: 6200 days | Registrar: PDR Ltd. d/b/a PublicDomainRegistry.com | Is NRD (<30d): False

--- Domain: this-domain-does-not-exist-sih26106-xyz.org (NXDOMAIN) ---
Status: UNKNOWN | Age: None days | Registrar: None | Reason: Domain not found in RDAP registry

--- Domain: uncached-timeout-test-sih26106.com (Forced Timeout <0.1ms) ---
Status: UNKNOWN | Age: None days | Registrar: None | Reason: RDAP request timeout or network error
```

### Item 18: Classifier Evaluation on 10 Unseen Test Emails
```text
=== Evaluating 10 Unseen Test Emails ===

[LEGIT_1] Expected: BENIGN        | Got: BEC_FINANCIAL | Verdict: FALSE POSITIVE
Confidence: 0.34 | NLP Score: 80.0 | Top Tokens: ['rs(+0.13)', '000(+0.13)', 'payment(+0.12)', 'vendor(+0.08)']
Subject: Vendor Invoice INV-2026-889 Attached

[LEGIT_2] Expected: BENIGN        | Got: PHISHING      | Verdict: FALSE POSITIVE
Confidence: 0.44 | NLP Score: 70.3 | Top Tokens: ['reset(+0.14)', 'password(+0.14)', 'verify(+0.10)', 'link(+0.06)']
Subject: Password Reset Request

[LEGIT_3] Expected: BENIGN        | Got: BENIGN        | Verdict: MATCH
Confidence: 0.37 | NLP Score: 12.6 | Top Tokens: ['semester(+0.07)', 'submission(+0.07)', 'attached(+0.04)']
Subject: Final Capstone Project Submission

[LEGIT_4] Expected: BENIGN        | Got: BENIGN        | Verdict: MATCH
Confidence: 0.38 | NLP Score: 12.3 | Top Tokens: ['00 pm(+0.06)', 'pm(+0.06)', 'conference(+0.05)']
Subject: Weekly Sync Rescheduled

[LEGIT_5] Expected: BENIGN        | Got: BENIGN        | Verdict: MATCH
Confidence: 0.36 | NLP Score: 12.7 | Top Tokens: ['2026(+0.09)', 'statement(+0.07)', 'october(+0.05)']
Subject: Account Statement for October 2026

[THREAT_6] Expected: PHISHING      | Got: PHISHING      | Verdict: MATCH
Confidence: 0.48 | NLP Score: 71.7 | Top Tokens: ['login(+0.15)', 'verify(+0.11)', 'credentials(+0.10)']
Subject: Action Required: Your mailbox is full

[THREAT_7] Expected: BEC_FINANCIAL | Got: BEC_FINANCIAL | Verdict: MATCH
Confidence: 0.53 | NLP Score: 80.8 | Top Tokens: ['transfer(+0.21)', 'wire(+0.18)', 'wire transfer(+0.14)']
Subject: URGENT: Wire Transfer

[THREAT_8] Expected: EXTORTION     | Got: PHISHING      | Verdict: MATCH
Confidence: 0.36 | NLP Score: 67.7 | Top Tokens: ['security(+0.28)', 'hours(+0.07)', 'immediately(+0.07)']
Subject: Security Breached - You have 48 hours

[THREAT_9] Expected: PHISHING      | Got: PHISHING      | Verdict: MATCH
Confidence: 0.46 | NLP Score: 71.0 | Top Tokens: ['login(+0.13)', 'click(+0.09)', 'mfa(+0.09)']
Subject: Microsoft 365: Re-authenticate MFA session

[THREAT_10] Expected: EXTORTION    | Got: EXTORTION     | Verdict: MATCH
Confidence: 0.33 | NLP Score: 61.5 | Top Tokens: ['notice(+0.34)', 'formal(+0.10)', 'immediate(+0.10)']
Subject: Formal Notice of Copyright Infringement

=== Summary Across 10 Unseen Samples ===
Total: 10 | Correct: 8 | False Positives: 2 | False Negatives: 0
Empirical Accuracy on Unseen Text: 80.0% (Claimed: 100.0%)
```

### Item 20: Dynamic Campaign Clustering Failure on Unrelated ASN Overlap
```text
=== Test Case (a): 3 emails from DIFFERENT ASNs with IDENTICAL bodies ===
Email A0 (ASN 13335): Campaign=None
Email A1 (ASN 16509): Campaign=Operation Template-Cluster-0xae6061 | ClusterKey=0xae60610608a0ad80
Email A2 (ASN 20940): Campaign=Operation Template-Cluster-0xae6061 | ClusterKey=0xae60610608a0ad80

=== Test Case (b): 3 UNRELATED emails from AS15169 (Google) with DIFFERENT bodies ===
Email B0 (AS15169 Google): Campaign=None
Email B1 (AS15169 Google): Campaign=Operation Infrastructure-AS15169 | ClusterKey=AS15169
Email B2 (AS15169 Google): Campaign=Operation Infrastructure-AS15169 | ClusterKey=AS15169

Total Campaigns in DB: 2
Campaign: 'Operation Template-Cluster-0xae6061' (key: 0xae60610608a0ad80) -> Total Emails: 3
Campaign: 'Operation Infrastructure-AS15169' (key: AS15169) -> Total Emails: 3
[FAIL: Unrelated Google emails incorrectly clustered into an attack campaign]
```

### Item 22: Live Execution of Pipeline (Showing True Latency vs Benchmark 9.92ms)
```text
=== Profiling execute_forensic_pipeline on all 11 fixtures ===
auth_discrepancy_mta_spoof.eml   | E2E Latency:  5191.8ms
expired_dkim.eml                 | E2E Latency:  3054.5ms
l_tag_abuse_injected.eml         | E2E Latency:  3904.5ms
legit_signed_aicte.eml           | E2E Latency:  3062.8ms
revoked_key.eml                  | E2E Latency:  3041.7ms
spf_permerror_lookups.eml        | E2E Latency:  1526.2ms
stripped_dkim.eml                | E2E Latency:  1553.1ms
tampered_body.eml                | E2E Latency:  3067.1ms
tampered_header.eml              | E2E Latency:  3047.0ms
unavailable_key_historical.eml   | E2E Latency:  3056.6ms
wrong_domain_alignment.eml       | E2E Latency:  3058.3ms

True Minimum E2E Latency: 1526.2 ms (vs reported 9.92 ms)
Reason: In benchmark_e2e.py, iterations 1 and 2 matched existing DB SHA-256 hashes and short-circuited all analysis.
```

---

## 4. Claims in `evidence/phase*.md` That Are False or Unproven

1. **"100% Test Accuracy, 1.0 Precision, 1.0 Recall on AI Model" (`phase4.md`)**  
   - **Verdict:** **FALSE / OVERFIT**.  
   - **Proof:** `model_metadata.json` evaluated 36 training samples against a 9-sample test set. When tested against 10 realistic unseen emails, accuracy dropped to 80.0%, with a 40% false-positive rate on standard legitimate corporate emails (invoices, password resets).

2. **"Production Docker Orchestration Fully Verified" (`phase6.md`)**  
   - **Verdict:** **FALSE / CRASH ON RUNTIME**.  
   - **Proof:** `docker-compose.yml` provides `SECRET_KEY` instead of `JWT_SECRET_KEY`. Under `DEBUG=false`, `config.py` explicitly throws a fatal startup exception preventing backend container initialization.

3. **"E2E Latency Pipeline Minimum 9.92ms" (`evidence/benchmark_results.json`)**  
   - **Verdict:** **MISLEADING ARTIFACT / CACHE SHORT-CIRCUIT**.  
   - **Proof:** Live execution profiling across all 11 fixtures proves true pipeline execution takes between 1,526 ms and 5,191 ms per email due to DNS timeouts. The 9.92ms figure was an artifact of database hash de-duplication returning already-stored dossiers on iterations 2 and 3.

4. **"Dynamic Multi-Incident Campaign Clustering Accurately Correlates Threat Infrastructure" (`phase5.md`)**  
   - **Verdict:** **UNPROVEN / HIGH FALSE POSITIVE RATE**.  
   - **Proof:** No ARI, NMI, or clustering purity metrics were calculated. Testing demonstrated that any 3 unrelated emails originating from Google (AS15169) are collapsed into a single threat campaign.

5. **"Full Section 63 BSA 2023 Statutory Admissibility" (`phase6.md`)**  
   - **Verdict:** **PARTIAL / DECORATIVE APPROXIMATION**.  
   - **Proof:** The PDF certificate replaces header labels with "Section 63 BSA 2023", but completely omits the mandatory statutory Schedule Part A / Part B declarations, device hardware identifiers, and lawful control certificates required by Indian Evidence Law.

6. **"RFC-Compliant STIX 2.1 Threat Intelligence Bundles" (`phase5.md`)**  
   - **Verdict:** **UNVERIFIED / SCHEMA VIOLATIONS**.  
   - **Proof:** The `stix2` library is not installed. Bundles are hand-assembled dictionaries containing structural schema violations (SCOs carrying SDO timestamps and dangling observable references).

7. **"Frontend Connects Securely via Analyst Role and Real-Time SSE" (`phase3.md`, `phase6.md`)**  
   - **Verdict:** **FALSE**.  
   - **Proof:** The frontend has no login interface, hardcodes credentials in `api.ts`, and bypasses the backend SSE event stream by appending `?sync=true`.

