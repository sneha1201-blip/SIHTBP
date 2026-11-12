# Evidence Log: STEP 11 - Performance, Reliability & Test Coverage

**Problem Statement:** AICTE Cyber Security Cell — SIH PS 26106  
**Timestamp:** 2026-11-12T21:21:40+05:30  
**Phase:** STEP 11 (Full Test Suite 109/109, Coverage Gate, Physical NVMe E2E Benchmark, Reliability Audits)

---

## 1. Test Suite & Coverage Verification

All 109 unit and integration tests passed cleanly across the entire platform:

```powershell
python -m pytest --cov=backend/app --cov-report=term-missing
====================== 109 passed, 5 warnings in 44.31s =======================
```

### Module Coverage Breakdown for Critical Forensic Components:

| Module Path | Functional Scope | Statements | Coverage |
|---|---|---|---|
| `backend/app/reporting/pdf_generator.py` | Court-Admissible Section 63 BSA PDF Dossier | 146 | **95%** |
| `backend/app/database/models.py` | Relational ORM Schemas & Indexes | 177 | **95%** |
| `backend/app/database/audit_service.py` | Hash-Chained Immutable Audit Ledger | 47 | **96%** |
| `backend/app/database/seed_data.py` | Standard Forensic Scenario Seeder | 256 | **96%** |
| `backend/app/ai/nlp_engine.py` | TF-IDF Intent Classifier & Offsets | 140 | **91%** |
| `backend/app/forensics/spoof_detector.py` | Confusable Homoglyphs & VIP Spoofing | 125 | **90%** |
| `backend/app/main.py` | Application Routing, Security & Probes | 105 | **90%** |
| `backend/app/forensics/campaign_clusterer.py` | Multi-Signal Dynamic Campaign Correlation | 243 | **87%** |
| `backend/app/forensics/hop_traversal.py` | RFC 5321 Hop Forensics & Clock Skew | 178 | **86%** |
| `backend/app/forensics/auth_validator.py` | Cryptographic SPF, DKIM, DMARC, ARC | 535 | **81%** |
| `backend/app/core/upload_validator.py` | Magic Byte Validation & Size Limits | 62 | **79%** |
| `backend/app/forensics/attachment_analyzer.py` | OLE Macros, Double Exts, Zip Bombs | 167 | **70%** |

---

## 2. Empirical End-to-End Performance Benchmark

Executed via [`scripts/benchmark_e2e.py`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/scripts/benchmark_e2e.py) under zero cache pollution (100% unique cryptographic nonces on physical NVMe SSD with SQLite WAL + `fsync`):

```
==============================================================================================================
   AICTE CYBER SECURITY CELL - HONEST E2E FORENSIC PIPELINE PERFORMANCE AUDIT
   Problem Statement: 26106 | Legal Admissibility: Section 63 BSA 2023
==============================================================================================================
Platform:       Windows 11 (10.0.26200) | Python 3.12.14 | SQLite 3.53.1
Storage Engine: Physical On-Disk NVMe/SSD (SQLite WAL Mode + O_SYNC fsync)
Git Commit:     f11349f1f57196f7144b6e8e8b777dc442239c24
Cold Start:     2557.10 ms (Model Loading & Regex Compilation)
Throughput:     0.82 emails/second (steady-state across live network DNS queries)
Evaluated:      14 unique nonced samples (0% cache hits)
Wall Time:      17.087 seconds
--------------------------------------------------------------------------------------------------------------
  Forensic Stage                       | Mean     | P50      | P95      | P99      | Min      | Max      | StdDev  
--------------------------------------------------------------------------------------------------------------
  dual_hashing_vault_store             |   5.14ms |   5.18ms |   6.99ms |   6.99ms |   3.75ms |   6.99ms |   0.88ms
  mime_rfc822_parsing                  |   3.88ms |   3.57ms |   6.77ms |   6.77ms |   1.39ms |   6.77ms |   1.36ms
  hop_traversal_geoip_asn              |   0.07ms |   0.00ms |   0.68ms |   0.68ms |   0.00ms |   0.68ms |   0.17ms
  protocol_auth_dkim_spf_dmarc         | 539.27ms |   0.26ms | 3026.54ms | 3026.54ms |   0.13ms | 3026.54ms | 921.68ms
  spoof_homoglyph_detection            |   0.60ms |   0.50ms |   1.27ms |   1.27ms |   0.38ms |   1.27ms |   0.26ms
  ioc_extraction_url_deobfuscation     |   0.15ms |   0.07ms |   1.30ms |   1.30ms |   0.03ms |   1.30ms |   0.32ms
  nlp_intent_and_entity_extraction     |   5.48ms |   5.04ms |  10.67ms |  10.67ms |   4.07ms |  10.67ms |   1.76ms
  threat_scoring_formula               |   0.02ms |   0.02ms |   0.04ms |   0.04ms |   0.02ms |   0.04ms |   0.01ms
  database_orm_persistence             |   0.07ms |   0.07ms |   0.08ms |   0.08ms |   0.07ms |   0.08ms |   0.01ms
  pdf_generation_section63_bsa         |  37.68ms |  35.09ms |  63.92ms |  63.92ms |  32.91ms |  63.92ms |   7.75ms
  full_pipeline_ingest_e2e             | 628.10ms |  53.97ms | 2051.58ms | 2051.58ms |  42.07ms | 2051.58ms | 778.64ms
  concurrent_dns_resolution_latency    | 4018.07ms | 4017.58ms | 4025.29ms | 4025.29ms | 4014.44ms | 4025.29ms |   3.14ms
==============================================================================================================
```

Raw JSON artifacts persisted at [`evidence/benchmark_results.json`](file:///C:/Users/HP/.gemini/antigravity/scratch/SIHTBP/evidence/benchmark_results.json) and timestamped in `evidence/benchmarks/`.

---

## 3. Reliability & Failure Injection Audits

1. **Hypothesis Property Fuzzing:** Tested on 100 arbitrary and malformed input strings; verified 0 crashes and 0 unhandled exceptions.
2. **Missing GeoIP Database:** Returns explicit `UNRESOLVED` status with `latitude=None`, `longitude=None`; zero fallback guessing.
3. **Corrupt OLE Stream Carving:** Partial ASCII carving extracts authentic subject/body chunks without inventing synthetic sender/recipient data.
4. **Threat Feed Downloader:** Gracefully handles network outages, returning `status="UNAVAILABLE"` and falling back to cached snapshots.
