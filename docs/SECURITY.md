# Security Architecture, Hardening & CSRF Stance

**Project:** AICTE Cyber Security Cell — Email Threat Detection & Forensic Intelligence  
**Problem Statement ID:** 26106 (SIH 2026)  

---

## 1. Authentication & Session Management
- **Cryptographic Token Issuance**: Authentication relies on signed JSON Web Tokens (JWT) using HS256 with strong secrets (`JWT_SECRET_KEY`) enforced on startup.
- **Argon2 Password Hashing**: Passwords are hashed using the Argon2id algorithm (`time_cost=3`, `memory_cost=65536`, `parallelism=4`).
- **Institutional Password Policy**: Enforces a minimum 10-character length, requiring at least one uppercase letter, one lowercase letter, one digit, and one special character.
- **Account Lockout & Brute-Force Protection**: 5 consecutive failed login attempts trigger an automatic 15-minute account lockout (`HTTP 429 Too Many Requests`).

---

## 2. CSRF Stance & Token Storage
- **RESTful Architecture**: The API is entirely stateless and does not use ambient session cookies for authentication.
- **Authorization Header**: All state-changing requests (`POST`, `PUT`, `DELETE`, `PATCH`) require the `Authorization: Bearer <JWT>` header.
- **CSRF Immunity**: Because browsers do not automatically attach Bearer headers on cross-site requests, the application is inherently immune to standard Cross-Site Request Forgery (CSRF) attacks.

---

## 3. Defense-in-Depth HTTP Security Headers
Every HTTP response carries strict security headers configured via middleware:
- `Content-Security-Policy`: Restricts resource execution to trusted origins (`default-src 'self'`).
- `X-Content-Type-Options: nosniff`: Prevents MIME-confusion attacks.
- `X-Frame-Options: DENY`: Blocks clickjacking by preventing iframe embedding.
- `Strict-Transport-Security`: Enforces TLS encryption for 1 year (`max-age=31536000; includeSubDomains`).
- `Referrer-Policy: strict-origin-when-cross-origin`: Minimizes referrer leakage.
- `X-Request-ID`: Distributed tracing header for request auditing.

---

## 4. Input Limits & Defensive Validation
- **Streaming Upload Cap**: Hard 25MB streaming limit enforced at chunk level before disk writes (`HTTP 413 Content Too Large`).
- **Binary Rejection**: Magic-byte inspection rejects executables, ELF binaries, and non-email files disguised with `.eml` extensions (`HTTP 422 Unprocessable Content`).
- **Sanitization**: File names are sanitized against path traversal (`../`) and null-byte injection.
