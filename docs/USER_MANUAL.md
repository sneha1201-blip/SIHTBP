# SOC Analyst & Forensic Investigator User Manual

**Platform:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Authority:** AICTE Cyber Security Cell | Smart India Hackathon (Problem Statement ID: 26106)

---

## 1. Accessing the Platform

1. Navigate to the secure web interface (e.g., `https://soc.aicte-india.org` or `http://localhost:3000`).
2. Enter your assigned SOC Analyst credentials:
   - Default Bootstrap Admin: `admin@aicte-india.org`
   - *Note: Accounts are temporarily locked after 5 failed login attempts for 15 minutes.*
3. Upon authentication, you will be redirected to the **AICTE Cyber Defense Operations Center** dashboard.

---

## 2. Ingesting & Analyzing an Email

### Step 1: Uploading the Evidence Payload
1. Navigate to the **Evidence Ingestion** tab.
2. Either drag-and-drop a raw `.eml` / `.msg` file into the cryptographic dropzone or paste raw RFC 5322 email headers directly into the text area.
3. Click **Initiate Forensic Ingestion**.

### Step 2: Real-Time Pipeline Streaming
- The system automatically uploads the payload via a chunked streaming pipe to ensure strict 25 MB file bounds.
- The UI connects to the Server-Sent Events (SSE) feed (`/api/v1/forensics/jobs/{id}/stream`), visualizing progress through distinct forensic stages:
  1. Cryptographic Vault Hashing (SHA-256 + SHA-512)
  2. RFC 5321 Hop Traversal & MTA Classification
  3. Protocol Authentication (SPF, DKIM, DMARC, ARC)
  4. Attachment Deep Scan & OLE Macro Extraction
  5. URL Deobfuscation & SSRF Validation
  6. Machine Learning Threat Intent Classification
  7. Cross-Incident Campaign Correlation

---

## 3. Interpreting the Forensic Dossier

Once processing completes, the platform presents the **Comprehensive Threat Dossier**:

### A. Threat Verdict & Composite Score
- **Composite Score (0–100):** Weighted combination of protocol spoofing, NLP threat intent, malicious attachments, and phishing links.
- **Threat Verdicts:**
  - `BENIGN` (0–34): Normal institutional communication.
  - `SUSPICIOUS` (35–69): Anomalies detected (e.g., failed SPF or cousin domain).
  - `MALICIOUS` (70–100): Confirmed spear phishing, BEC wire fraud, or ransomware payload.
  - `UNCERTAIN`: Boundary case with low model confidence; routed to manual analyst review.

### B. Protocol Authentication Breakdown
- **DKIM:** Indicates whether cryptographic digital signatures match the sending domain's public key.
- **SPF:** Evaluates whether the connecting MTA IP is authorized in the sender's DNS SPF record.
- **DMARC:** Confirms alignment between the visible `From:` header and SPF/DKIM authenticated domains.
- **ARC:** Displays the chain-of-trust for emails forwarded across intermediate mailing lists.

### C. Reverse Hop Map & MTA Trace
- Displays the physical route traveled by the email from origin to destination.
- Each hop details:
  - **MTA Type:** Identified mail server software (Postfix, Exchange, Sendmail, Google, Exim).
  - **IP Geolocation:** Country, city, ASN, and confidence radius in kilometers.
  - **Clock Skew Anomaly:** Highlights discrepancies exceeding +/- 300 seconds (indicative of forged timestamps).
  - **Hop Confidence:** Confidence score (`0.0` to `1.0`) indicating evidence trustworthiness.

---

## 4. Threat Campaign Graph Investigation

1. Open the **Threat Campaigns** tab to view the interactive infrastructure graph.
2. **Nodes** represent individual emails, threat actors, IP subnets, and domains.
3. **Edges** represent correlation signals:
   - *SimHash 0-bit:* Identical message templates.
   - *Subnet /24:* Shared hosting infrastructure.
   - *Domain:* Common threat actor envelope sender.
4. **Analyst Actions:**
   - **Merge Campaigns:** Select two correlated clusters and click *Merge* to unify them.
   - **Split Campaign:** Select outlier nodes and click *Split* to isolate a distinct operation.
   - **Export STIX 2.1:** Click *Export STIX 2.1 Bundle* to download machine-readable threat intelligence.

---

## 5. Generating Court-Admissible Section 63 BSA Certificates

1. From any analyzed evidence dossier, click **Export Section 63 BSA Certificate (PDF)**.
2. The platform performs an export-time vault integrity check, re-reading the physical file from disk to guarantee zero post-ingestion tampering.
3. The generated certificate contains:
   - **Part A:** Machine specifications, software version, dual SHA-256 and SHA-512 digests, byte size, and NTP-synchronized UTC timestamps.
   - **Part B:** Statutory legal attestation block for the human officer in lawful custody of the computer device.

---

## 6. Offline Independent Verification

Law enforcement, judicial magistrates, or defense attorneys can verify the evidence without connecting to the server:

```bash
# Verify raw evidence against expected SHA-256
python scripts/verify_report.py --raw evidence.raw --sha256 <SHA256_HASH>

# Verify raw evidence against an exported Section 63 BSA PDF certificate
python scripts/verify_report.py --raw evidence.raw --pdf Section63_Certificate.pdf
```
If the certificate and physical evidence match, the script outputs `INTEGRITY VERIFIED: Evidence matches Section 63 BSA Certificate`.
