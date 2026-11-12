# Gate Script Revision & Modification Changelog

Per Rule R7:
> "Gate scripts are the judge, not your opinion. You may ADD gates; you may not edit or delete an existing gate except to fix a bug in the gate, and then you must log it in evidence/GATE_CHANGELOG.md with a reason, and re-run all gates."

---

## Initial Release (Iteration 0)
- **Timestamp:** 2026-11-12T21:40:00+05:30
- **Commit:** Initial Bootstrap
- **Changes:**
  - Created initial test gates G00 through G15 in `gates/`.
  - Implemented `gates/run_all.sh` orchestrator with clean-clone execution.
  - Initial SHA-256 baseline computed and stored in `evidence/gates/GATE_HASHES.txt`.
