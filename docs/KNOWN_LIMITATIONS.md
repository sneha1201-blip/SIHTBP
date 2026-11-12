# Known Technical Limitations & Legal Boundaries

**Platform:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Authority:** AICTE Cyber Security Cell | Smart India Hackathon (Problem Statement ID: 26106)

---

## 1. Geolocation is IP Infrastructure, Not Physical Device GPS

- **Technical Ground Truth:** IP geolocation via MaxMind GeoLite2 maps the physical location of the **mail server (MTA), VPN gateway, or webmail relay** that transmitted the message across the network boundary.
- **Forensic Scope:** It does **not** pinpoint the physical GPS coordinates, laptop, or smartphone of the individual author.
- **Operational Policy:** If an email is transmitted via a webmail interface (e.g., Gmail or Outlook 365), the origin IP in headers represents Google or Microsoft datacenter infrastructure, unless an optional `X-Originating-IP` header was stamped. The platform displays this with an explicit accuracy radius in kilometers and tags null coordinates as `"Unresolved / Private Network"`.

---

## 2. Historical DKIM Verification & Key Rotation

- **Technical Ground Truth:** DKIM verification relies on active DNS TXT queries against the sender's public selector key (e.g., `selector1._domainkey.example.com`).
- **Limitation:** If a sending organization rotates or deprecates an old selector key years after an email is archived, historical DKIM verification will report `FAIL` or `TEMPFAIL`.
- **Forensic Scope:** The platform preserves the original raw cryptographic signature header verbatim. Forensic examiners should reference DNS historical archives (e.g., SecurityTrails or DNSDB) for cold-case validation.

---

## 3. Machine Learning NLP Failure Modes & Boundaries

- **Trained Architecture:** Linear pipeline combining `TfidfVectorizer(ngram=(1,2))` with L2-regularized `LogisticRegression`.
- **Known Edge Cases:**
  1. *Subtle Conversational BEC:* Spear phishing attacks that begin with benign conversational grooming (e.g., "Are you at your desk?") without immediate financial keywords or links may initially register as `BENIGN` or `UNCERTAIN`.
  2. *Legitimate High-Urgency Notices:* Legitimate administrative communications from institutional registrars or court summons containing strict compliance deadlines may trigger elevated NLP threat scores.
- **Mitigation:** The system uses a composite scoring formula that requires multiple corroborating signals (failed SPF/DKIM, cousin domains, malicious URLs) before issuing a high-confidence `MALICIOUS` verdict.

---

## 4. Adversarial Evasion Boundaries

- **Optical Steganography & Audio Lures:** While the platform inspects QR codes embedded in images (`pyzbar`) and OLE macros in office documents (`oletools`), highly sophisticated steganographic data concealed in arbitrary image pixels or deepfake audio attachments is outside the scope of RFC 5322 parsing.
- **Polymorphic Fast-Flux Infrastructure:** Threat actors utilizing fast-flux DNS with TTLs below 60 seconds may resolve to distinct IP addresses during live analysis compared to transit time.

---

## 5. Statutory Limits under Section 63 BSA 2023

- **Statutory Mandate:** Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 requires electronic evidence to be certified by a person occupying an official position in lawful custody or management of the relevant computer device.
- **Legal Partition:**
  - **Part A (Automated Parameters):** The platform legitimately self-certifies physical hash digests, byte lengths, operating system specs, NTP timestamps, and extraction audit logs.
  - **Part B (Lawful Custody Attestation):** The platform **strictly refuses** to fabricate or auto-generate human signatures, designation stamps, or device custody claims. Any unpopulated officer fields are stamped `[NEEDS LEGAL REVIEW]` and must be physically attested and signed by the investigating officer.
