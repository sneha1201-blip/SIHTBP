# Frontend Dependency Security Audit & Triage
**Audit Timestamp:** 2026-11-13T01:14:00+00:00  
**Evidence Artifact:** `evidence/security/npm_audit.json`  
**Tool:** `npm audit --json` on Next.js 14 Frontend

---

## 1. Vulnerability Summary

| Severity | Count | Primary Affected Packages |
|:---|:---:|:---|
| **Critical** | 1 | `next` (Transitive advisories related to server actions & SSRF rewrites) |
| **High** | 4 | `next`, `postcss`, `glob`, `@next/eslint-plugin-next` |
| **Moderate** | 6 | `micromatch`, `brace-expansion`, `cross-spawn` (Transitive devDependencies) |
| **Total** | 11 | All in frontend build/runtime dependencies |

---

## 2. Detailed Triage & Risk Mitigation

### Package: `next` (14.2.18)
- **Reported Advisories:**
  - *Next.js: Denial of Service with Server Actions / Server Components* (GHSA-m84x-895p-h234, GHSA-36ch-w5cp-4w37)
  - *Next.js: SSRF in rewrites via attacker-controlled destination hostname* (GHSA-2g9h-5x79-jrcg)
  - *Next.js: Unauthenticated RCE in Image Optimization API* (GHSA-9g5h-m6x6-q4p6)
- **Forensic Context & Exploitability Analysis:**
  1. The platform's frontend acts strictly as a presentation layer consuming FastAPI endpoints (`http://localhost:8000/api/v1/`).
  2. Next.js Server Actions are **disabled / unused** in this application. All API calls use standard client-side `fetch()` with explicit Bearer tokens.
  3. Image Optimization API (`next/image`) is not exposed to untrusted external URLs (`remotePatterns` is empty).
  4. Next.js build is pre-rendered as static HTML/JS pages (5/5 static pages).
- **Resolution Plan:**
  - Upgrading to Next.js 15+ is a breaking change requiring React 19 migration. Retained on stable 14.2.18 LTS with all risky features disabled. Risk is mitigated and accepted for this release candidate.

---

### Package: `postcss` (8.4.38)
- **Reported Advisories:**
  - *PostCSS: Arbitrary file read / source map auto-loading* (GHSA-7fh5-64p2-3v2j, GHSA-6g55-p6wh-862q)
- **Forensic Context & Exploitability Analysis:**
  - PostCSS is executed strictly at build-time (`next build` / Tailwind compilation) within the isolated developer environment. It is never invoked on user-supplied CSS or runtime data.
- **Resolution Plan:**
  - No runtime exploit vector. Mitigated by restricting CSS inputs to repo source files.

---

### Package: `glob` (10.3.10)
- **Reported Advisories:**
  - *Glob CLI: Command injection via -c/--cmd* (GHSA-556v-m22f-q5vq)
- **Forensic Context & Exploitability Analysis:**
  - Transitive devDependency of build utilities. The CLI interface (`glob -c`) is never executed.
- **Resolution Plan:**
  - Zero runtime impact. Mitigated.

---

### Packages: `@next/eslint-plugin-next`, `eslint-config-next`
- **Reported Advisories:** Transitive high severity via next dependency.
- **Forensic Context:** Development-time linting only (`npm run lint`).
- **Resolution Plan:** No runtime impact. Mitigated.
