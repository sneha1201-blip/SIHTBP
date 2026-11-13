# Public Mailing List Real Signed Mail Retrieval Audit
**Execution Timestamp:** 2026-11-13T06:07:04Z  
**Objective:** Attempt automated retrieval of authentic third-party DKIM-signed `.eml` fixtures from public mailing list archives (LKML, Apache, Debian).  
**Outcome:** `UNABLE TO RETRIEVE UNMODIFIED SIGNED MAIL` — Legitimate Technical and Anti-Bot Constraints. Gate G04 remains honestly `BLOCKED` awaiting user-supplied signed `.eml` fixtures.

---

## 1. Retrieval Attempts & Technical Findings

### 1.1 Source 1: Linux Kernel Mailing List (`lore.kernel.org`)
- **Target URL:** `https://lore.kernel.org/git/?q=dkim` / `https://lore.kernel.org/all/`
- **Result:** **BLOCKED (Anti-Bot Challenge)**
- **Raw Diagnostic Output:**
  ```html
  HTTP 200 OK
  <!doctype html><html lang="en"><head>
  <title>Making sure you're not a bot!</title>
  <link rel="stylesheet" href="/.within.website/x/xess/xess.min.css?cachebuster=v1.26.2">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex,nofollow">
  <meta property="og:description" content="Browse git repositories hosted by the Linux Foundation.">
  ```
- **Constraint:** `lore.kernel.org` enforces a Cloudflare / Linux Foundation proof-of-work challenge ("Making sure you're not a bot!"). Per system safety guidelines, automated agents must never bypass anti-bot challenges or proof-of-work gates.

---

### 1.2 Source 2: Apache Mailing List Archives (`mail-archives.apache.org`)
- **Target URL:** `https://mail-archives.apache.org/mod_mbox/spamassassin-users/202401.mbox`
- **Download Status:** **SUCCESS** (678,343 bytes downloaded, 104 RFC 822 messages parsed).
- **DKIM Presence:** Multiple messages contain validly formed `DKIM-Signature` headers (e.g. from `bway.net`, `microsoft.com`, `ena.com`, `fantomas.sk`).
- **Cryptographic Verification Result:** **ALL FAILED (`dkim.verify(raw) == False`)**
- **Technical Root Cause (Mailing List Modification in Transit):**
  1. **Body Hash Mismatch (`bh=`):** The Apache mailing list software appends standard unsubscription instructions to the body of every relayed message (e.g. `To unsubscribe, e-mail: users-unsubscribe@spamassassin.apache.org`). Because RFC 6376 computes `bh=` as `SHA256(canonicalized_body)`, any appended text causes an immediate, non-recoverable body hash divergence.
  2. **Header Invalidation (`b=`):** The mailing list manager injects or rewrites header fields (e.g., `Subject: [users] ...`, `List-Id`, `List-Unsubscribe`, `X-Spam-Status`). When these fields are included in the signed header list (`h=`), the RSA-SHA256 signature (`b=`) fails cryptographic verification.
  3. **Key Lifecycle Expiration:** Several public keys published in 2024 have been rotated or withdrawn from DNS TXT records (`selector._domainkey.domain`), resulting in `dns.resolver.NXDOMAIN` or `NoAnswer`.

---

### 1.3 Source 3: Debian Mailing List Archives (`lists.debian.org`)
- **Target URL:** `https://lists.debian.org/debian-security/`
- **Result:** **UNSUITABLE (HTML-Only Web Rendering)**
- **Technical Root Cause:** Debian public archives provide web-rendered HTML archives (`.html`) with hyperlinked threads rather than raw, downloadable RFC 822 MIME streams preserving original binary headers and uncanonicalized bodies.

---

## 2. Conclusion & Adherence to Rule R3

Mailing list archivers by design alter message bodies and headers, inherently breaking sender-origin DKIM signatures unless ARC (`Authenticated Received Chain`) is fully established and supported by a trust chain.

Consequently:
1. Genuine, pass-verifying DKIM fixtures cannot be scraped from modified mailing list relays without violating the laws of cryptographic hashes.
2. Direct `.eml` files exported from primary user mailboxes (Gmail, Microsoft 365, Zoho) that have not undergone list mediation are strictly required for authentic DKIM/SPF/ARC validation.
3. In strict compliance with **Rule R3**, Gate G04 accurately and honestly records status **`BLOCKED`** pending the provision of $\ge 20$ authentic user `.eml` files in `tests/fixtures/real/`.

