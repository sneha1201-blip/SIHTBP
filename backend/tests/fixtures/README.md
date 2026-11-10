# Cryptographic Forensic Email Test Corpus & Provenance Record
**Smart India Hackathon 2026 | Problem Statement 26106**  
**AICTE Cyber Security Cell: AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence**  

---

## 1. Corpus Metadata & Provenance
- **Dataset Name:** `SIH-Forensic-Protocol-Auth-Corpus`
- **Version:** `2.0.0`
- **Total Samples:** 11 RFC 822 `.eml` test files
- **Generation Timestamp:** `2026-11-10T18:25:00Z`
- **Generation Seed:** `26106` (PRNG seeded with SIH PS ID 26106)
- **Primary Domain Authority:** `aicte-india.org`
- **Adversary Relay Domain:** `attacker-relay.net`
- **Cryptographic Algorithms:** RSA-SHA256 (1024-bit keypairs generated via `cryptography.hazmat`)
- **DKIM Canonicalization:** `relaxed/simple` and `relaxed/relaxed` per RFC 6376
- **Compliance Standard:** Section 63 Bharatiya Sakshya Adhiniyam (BSA), 2023 / Section 65B IEA

---

## 2. Sample Manifest & Expected Ground Truth

| File Name | Protocol Focus | Attack / Variant Mechanism | Expected SPF | Expected DKIM | Expected DMARC | Expected Discrepancy |
|---|---|---|---|---|---|---|
| `legit_signed_aicte.eml` | Baseline Authentic | Valid RSA-SHA256 signature, authorized IP, DMARC aligned | `PASS` | `PASS` | `PASS` | `False` |
| `tampered_body.eml` | Integrity Attack | Body altered post-signing (wire fraud text injected) | `PASS` | `BODY_HASH_MISMATCH` | `PASS` (via SPF) | `False` |
| `tampered_header.eml` | Integrity Attack | `Subject:` header altered post-signing | `PASS` | `FAIL` | `PASS` (via SPF) | `False` |
| `stripped_dkim.eml` | Stripping Attack | `DKIM-Signature` header stripped entirely | `PASS` | `NONE` | `PASS` (via SPF) | `False` |
| `wrong_domain_alignment.eml` | Alignment Spoof | Valid DKIM from `attacker-relay.net`, From is `aicte-india.org` | `FAIL` | `PASS` (Unaligned) | `FAIL` | `False` |
| `expired_dkim.eml` | Replay Defense | Signature with `x=` expiration timestamp in the past | `PASS` | `EXPIRED` | `PASS` (via SPF) | `False` |
| `revoked_key.eml` | Key Revocation | DNS TXT record for selector publishes empty `p=` | `PASS` | `KEY_REVOKED` | `PASS` (via SPF) | `False` |
| `unavailable_key_historical.eml` | Historical Email | DNS key selector no longer resolvable in DNS | `PASS` | `KEY_UNAVAILABLE` | `PASS` (via SPF) | `False` |
| `l_tag_abuse_injected.eml` | Length Injection | `l=50` length limit with malicious content appended post-length | `PASS` | `PASS` (Partial) | `PASS` | `True` (Advisory) |
| `spf_permerror_lookups.eml` | DNS DoS Attack | 12 nested SPF `include:` directives exceeding RFC 7208 10-lookup limit | `PERMERROR` | `NONE` | `FAIL` | `False` |
| `auth_discrepancy_mta_spoof.eml` | Header Forgery | Forged upstream `Authentication-Results: spf=pass; dkim=pass` | `FAIL` | `KEY_UNAVAILABLE` | `FAIL` | `True` (Critical) |

---

## 3. Reproduction & Execution
To regenerate this corpus deterministically and run the Phase 2 cryptographic confusion matrix:
```bash
python -c "from backend.tests.fixtures.email_corpus import save_corpus_to_disk; save_corpus_to_disk('backend/tests/fixtures/emails')"
pytest -v backend/tests/test_protocol_auth.py
```

