# Evidence Log: STEP 5 - Geolocation & OSINT Intelligence

**Problem Statement:** AICTE Cyber Security Cell — SIH PS 26106  
**Timestamp:** 2026-11-12T20:59:30+05:30  
**Phase:** STEP 5 (GeoIP Zero-Guessing, Tor Telemetry, RDAP, DNSBL, Threat Feeds & Failure Injection)

---

## 1. Zero-Guessing Geolocation Architecture

The platform enforces a strict zero-guessing policy for all IP-based geolocation:
- **Null Coordinates for Unresolvable IPs:** RFC 1918 private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`, `::1`), link-local, and reserved ranges return `latitude=None`, `longitude=None`, `resolution_status="UNRESOLVED"`, and `source="RFC1918_FILTER"`.
- **No Geographical Fallback Clichés:** The platform never defaults to Nagpur, geographical centroids, or static prefix tables.
- **Precision Metadata:** Includes MaxMind database build date (`db_build_date`) and accuracy radius in kilometers (`accuracy_radius_km`).

### External Dependency Status: MaxMind MMDB & Ground-Truth CSV
- **`MAXMIND_LICENSE_KEY`:** `BLOCKED: awaiting user input`.
  - The script [`scripts/update_geoip.ps1`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/scripts/update_geoip.ps1) is ready. When the user sets `MAXMIND_LICENSE_KEY` in `.env` or passes it via `-LicenseKey <key>`, it automatically downloads `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
  - In the absence of an external `.mmdb` file, the platform does not fabricate locations, but returns `UNRESOLVED` with explicit diagnostic explanations.
- **Geo Ground-Truth CSV:** `BLOCKED: awaiting user input`.
  - Without user-provided ground-truth CSV containing known VPS/VPN locations, empirical city/country accuracy and median km error are marked blocked to prevent fabricated accuracy metrics.

---

## 2. OSINT Intelligence Services

1. **Tor Exit Node & Anonymizer Detection:**
   - Detects Tor exit nodes and bulletproof hosting subnets.
   - Uses local age-labeled snapshot (`tor_exit_nodes.json`) with exact age in hours (`age_hours`) and live update capabilities.
2. **RFC 7483 RDAP / WHOIS Intelligence:**
   - Extracts domain registration date and computes exact domain age in days.
   - Newly Registered Domain (NRD) classifier flags domains `< 30 days` old as elevated risk (`reputation_score=85.0`).
3. **DNSBL Reverse-IP Reputation:**
   - Formats reverse IPv4 octets (`<d>.<c>.<b>.<a>.<provider>`) and executes low-latency A-record queries across configured blocklists (Spamhaus ZEN, SpamCop).
   - Skips private RFC 1918 addresses automatically.
4. **Downloadable & Versioned Threat Feeds:**
   - Implemented in [`backend/app/osint/threat_feeds.py`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/backend/app/osint/threat_feeds.py).
   - Supports PhishTank, OpenPhish, and custom threat lists.
   - Computes SHA-256 cryptographic digest of downloaded feeds, writes versioned manifests (`{feed}_{timestamp}.manifest.json`), and tracks record counts.

---

## 3. Failure Injection Test Results

| Source | Failure Mode Tested | Behavior & Recovery | Status |
|---|---|---|---|
| **MaxMind GeoIP** | Corrupted MMDB / null input | Returns `UNRESOLVED`, `latitude=None`, `longitude=None`; zero system crash | **VERIFIED** |
| **Tor Detector** | Network unreachable during live refresh | Falls back to bundled age-labeled offline snapshot (`OFFLINE_SNAPSHOT`) | **VERIFIED** |
| **RDAP / WHOIS** | Domain unresolvable / timeout | Returns `UNKNOWN` with `domain_age_days=None`, avoiding false benign verdicts | **VERIFIED** |
| **DNSBL Checker** | DNS resolver timeout / connection refused | Safely marks query status as `CLEAN` / `TIMEOUT` without blocking pipeline | **VERIFIED** |
| **Threat Feeds** | Network failure / 404 / 500 error | Returns `status="UNAVAILABLE"` or falls back to last known good manifest (`DEGRADED_CACHED`) | **VERIFIED** |

---

## 4. Test Verification Output

Command:
```powershell
python -m pytest backend/tests/test_osint_geoip.py
```

Output:
```
============================= test session starts =============================
platform win32 -- Python 3.12.14, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\.gemini\antigravity\scratch\SIHTBP
configfile: pyproject.toml
plugins: anyio-4.16.0, asyncio-1.4.1.post1
collected 16 items

backend\tests\test_osint_geoip.py ................                       [100%]

============================= 16 passed in 1.01s ==============================
```
