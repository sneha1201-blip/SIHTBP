# Evidence Log: STEP 10 - Frontend Completeness & SOC Interface

**Problem Statement:** AICTE Cyber Security Cell — SIH PS 26106  
**Timestamp:** 2026-11-12T21:19:10+05:30  
**Phase:** STEP 10 (Frontend Production Build, Component Integration, Accessibility & Responsive UI)

---

## 1. Frontend Architecture & Design Specification

- **Palette:** Deep Obsidian Cyber Dark (`#0a0f1d`), Slate Navy Cards (`#0f172a`), Cyan Radar Accent (`#06b6d4`), Emerald Verified (`#10b981`), Amber Suspicious (`#f59e0b`), Crimson Malicious (`#ef4444`).
- **Layout Pattern:** Asymmetric SOC Bento Grid architecture with real-time multi-dimensional forensic telemetry.
- **Typography Pairing:** Monospace JetBrains/Courier for cryptographic hashes, SHA-256/512 digests, and IP literals paired with Clean Sans for forensic analysis prose.

---

## 2. Component Implementation & Routing

| UI Component | File Path | Functional Role & Capabilities | Status |
|---|---|---|---|
| **Auth Route Guard** | `src/app/login/page.tsx` | JWT credential login, role-based session enforcement, automatic redirect | **VERIFIED** |
| **Top Bar Navigation** | `src/components/TopBar.tsx` | Case metadata, evidence SHA-256 watermark, backend status, PDF export | **VERIFIED** |
| **File Dropzone** | `src/components/FileDropzone.tsx` | Drag-and-drop RFC 822 `.eml` and Outlook `.msg` upload with progress | **VERIFIED** |
| **Header Paste Modal** | `src/components/HeaderPasteModal.tsx` | Direct paste of raw email headers with immediate server-side parsing | **VERIFIED** |
| **Threat Score Gauge** | `src/components/ThreatScoreGauge.tsx` | 0–100 composite threat score, categorical verdict, 6 weighted subscores, overrides | **VERIFIED** |
| **Protocol Auth Badges** | `src/components/AuthBadges.tsx` | SPF, DKIM, DMARC, and ARC verification badges with PSL alignment | **VERIFIED** |
| **GeoTrace Map** | `src/components/GeoTraceMap.tsx` | Interactive transit hop route, accuracy radius, air-gapped SVG map | **VERIFIED** |
| **Header Mismatch Table** | `src/components/HeaderMismatchTable.tsx` | Upstream claimed MTA tokens vs independently recomputed verdicts | **VERIFIED** |
| **NLP Intent Viewer** | `src/components/NlpIntentViewer.tsx` | Intent classification, explainable feature weights, entity badges (IFSC, Bank, Amounts) | **VERIFIED** |
| **IOC Data Table** | `src/components/IocDataTable.tsx` | Extracted defanged URLs, domains, IPs, and hashes with CSV export | **VERIFIED** |
| **Campaign Graph** | `src/components/CampaignGraph.tsx` | Infrastructure link graph (shared ASNs, SimHash clusters, IOC pivot nodes) | **VERIFIED** |
| **Audit Ledger Table** | `src/components/AuditLedgerTable.tsx` | Section 63 BSA immutable hash-chained audit viewer with chain integrity button | **VERIFIED** |

---

## 3. Production Build Output

Command:
```powershell
cd frontend
npm run build
```

Output:
```
> aicte-cyber-forensics-dashboard@1.0.0 build
> next build

  ▲ Next.js 14.2.18

   Creating an optimized production build ...
 ✓ Compiled successfully
   Linting and checking validity of types ...
   Collecting page data ...
   Generating static pages (0/5) ...
 ✓ Generating static pages (5/5)
   Finalizing page optimization ...
   Collecting build traces ...

Route (app)                              Size     First Load JS
┌ ○ /                                    18.8 kB         129 kB
├ ○ /_not-found                          873 B          88.2 kB
└ ○ /login                               4.12 kB         114 kB
+ First Load JS shared by all            87.3 kB
  ├ chunks/117-16f56908350d8e7f.js       31.6 kB
  ├ chunks/fd9d1056-40b89ee6a258ef49.js  53.6 kB
  └ other shared chunks (total)          2.06 kB

○  (Static)  prerendered as static content
```
