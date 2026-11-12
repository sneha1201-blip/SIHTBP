# Design Note 02: Legal Admissibility under Section 63 Bharatiya Sakshya Adhiniyam, 2023

**Statutory Authority:** Bharatiya Sakshya Adhiniyam, 2023 (Act No. 47 of 2023), Section 63  
**Predecessor Law:** Section 65B of the Indian Evidence Act, 1872  
**Applicability:** Admissibility of Electronic Records in Criminal and Civil Judicial Proceedings in India  

---

## 1. Statutory Mandate

Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023 governs the conditions under which electronic records (including emails, server logs, cryptographic hashes, and digital artifacts) are deemed admissible as documentary evidence without direct production of the original physical storage medium.

Under Section 63(4), a certificate must be produced identifying the electronic record and describing the manner in which it was produced, accompanied by particulars of the device and signed by a person in lawful management of the relevant device or system.

---

## 2. Certificate Architecture: Part A vs. Part B

Pursuant to the Schedule Certificate format of the BSA 2023:

```
+-----------------------------------------------------------------------------------------------+
| PART A: TECHNICAL PARTICULARS OF THE ELECTRONIC RECORD                                        |
| (Legitimately and deterministically produced by the automated forensic platform)              |
|                                                                                               |
| 1. Record Description: RFC 822 MIME stream, original filename, byte count, parsing status     |
| 2. Cryptographic Hashes: SHA-256 and SHA-512 calculated at ingestion, re-hashed at export       |
| 3. Storage Proof: WORM physical path ({sha256}.raw), POSIX permissions, fsync confirmation    |
| 4. System Parameters: Operating system, Python interpreter, database engine, server hostname   |
| 5. Operating Integrity: Operating condition during period of production, absence of tampering  |
+-----------------------------------------------------------------------------------------------+
| PART B: CERTIFICATE OF LAWFUL CONTROL & AFFIRMATION                                           |
| (MANDATORY HUMAN ATTESTATION - NEVER GENERATED AUTOMATICALLY BY SCRIPT)                       |
|                                                                                               |
| 1. Lawful Charge Declaration: Officer in lawful management of the forensic server / custody    |
| 2. Truth Statement: Declaration to the best of the officer's knowledge and personal belief     |
| 3. Officer Identification: Full name, official designation, badge/employee ID, agency          |
| 4. Execution: Date, place of execution, handwritten or PAdES/e-Sign digital token signature  |
| 5. Official Seal: Seal of the Cyber Security Cell / Law Enforcement Agency                    |
+-----------------------------------------------------------------------------------------------+
```

---

## 3. Anti-Tamper & Verification Architecture

1. **Dual Hashing at Ingestion**: When an email is ingested, the raw bytes are hashed simultaneously with SHA-256 and SHA-512 before any processing.
2. **HMAC Signature**: The SHA-256 digest is signed using HMAC-SHA256 with the server's private `VAULT_HMAC_SECRET`.
3. **Chain of Custody Ledger**: An immutable, hash-chained audit log (`EvidenceAuditLog`) records the analyst identity, ingestion timestamp, client IP, and previous record hash.
4. **Re-Hashing on Export**: When `GET /api/v1/forensics/evidence/{id}/report` is called to generate a court PDF, the physical file on disk is read anew and re-hashed. If the disk hash mismatches the database hash or HMAC signature, the endpoint aborts with `HTTP 409 Conflict`, logs an `INTEGRITY_FAILURE` event, and refuses to issue a certificate.
5. **Offline Third-Party Verification (`scripts/verify_report.py`)**: A defense attorney, forensic examiner, or judicial officer can verify the physical raw file against the stamped certificate hashes offline without requiring database access or server connectivity.
