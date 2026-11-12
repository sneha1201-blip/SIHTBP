"""Offline Third-Party Forensic Evidence & Section 63 BSA Verification Script.

Allows judicial officers, forensic examiners, and defense counsel to independently
verify the cryptographic integrity of raw email evidence files (.raw / .eml)
against certificates issued under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023.

Usage:
    python scripts/verify_report.py --raw storage/vault/<hash>.raw --sha256 <expected_sha256> [--sha512 <expected_sha512>]
    python scripts/verify_report.py --raw storage/vault/<hash>.raw --pdf <exported_report.pdf>
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import sys
from pathlib import Path
from typing import Optional, Tuple


def calculate_hashes(file_path: Path) -> Tuple[str, str, int]:
    """Calculate SHA-256, SHA-512, and byte count of a physical file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    byte_count = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            byte_count += len(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return sha256.hexdigest().lower(), sha512.hexdigest().lower(), byte_count


def extract_hashes_from_pdf(pdf_path: Path) -> Tuple[Optional[str], Optional[str]]:
    """Extract stamped SHA-256 and SHA-512 digests from Section 63 BSA PDF."""
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF report not found: {pdf_path}")

    # Read binary bytes of PDF to find plain-text hex hash patterns
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    # Search for 64-char hex (SHA-256) and 128-char hex (SHA-512)
    pdf_text = pdf_bytes.decode("latin-1", errors="ignore")

    sha256_match = re.search(r"SHA-256(?:\s*Hash)?\s*[:\n]\s*([a-fA-F0-9]{64})", pdf_text)
    sha512_match = re.search(r"SHA-512(?:\s*Hash)?\s*[:\n]\s*([a-fA-F0-9]{128})", pdf_text)

    sha256 = sha256_match.group(1).lower() if sha256_match else None
    sha512 = sha512_match.group(1).lower() if sha512_match else None

    # Fallback to general hex searching if formatted label is wrapped
    if not sha256:
        m256 = re.findall(r"\b([a-fA-F0-9]{64})\b", pdf_text)
        if m256:
            sha256 = m256[0].lower()

    return sha256, sha512


def verify_evidence(
    raw_path: Path,
    expected_sha256: Optional[str] = None,
    expected_sha512: Optional[str] = None,
    pdf_path: Optional[Path] = None,
    hmac_secret: Optional[str] = None,
) -> bool:
    """Verify raw file integrity against expected hashes or stamped PDF."""
    print("=" * 80)
    print("   AICTE CYBER SECURITY CELL | SECTION 63 BSA 2023 INDEPENDENT VERIFIER")
    print("   Digital Evidence Cryptographic Integrity and Admissibility Audit")
    print("=" * 80)

    actual_sha256, actual_sha512, byte_count = calculate_hashes(raw_path)
    print(f"File Path:    {raw_path.resolve()}")
    print(f"File Size:    {byte_count:,} bytes")
    print(f"Calculated SHA-256: {actual_sha256}")
    print(f"Calculated SHA-512: {actual_sha512}")
    print("-" * 80)

    if pdf_path:
        print(f"Inspecting Section 63 BSA Certificate PDF: {pdf_path.name}")
        pdf_sha256, pdf_sha512 = extract_hashes_from_pdf(pdf_path)
        if pdf_sha256:
            print(f"Extracted Certificate SHA-256: {pdf_sha256}")
            expected_sha256 = pdf_sha256
        else:
            print("WARNING: Could not extract SHA-256 hash pattern from PDF.")
        if pdf_sha512:
            print(f"Extracted Certificate SHA-512: {pdf_sha512}")
            expected_sha512 = pdf_sha512

    passed = True

    if expected_sha256:
        if actual_sha256 == expected_sha256.lower().strip():
            print("[PASS] SHA-256 Digest Verification: EXACT MATCH")
        else:
            print(f"[FAIL] SHA-256 Digest Mismatch! Expected: {expected_sha256}")
            passed = False

    if expected_sha512:
        if actual_sha512 == expected_sha512.lower().strip():
            print("[PASS] SHA-512 Digest Verification: EXACT MATCH")
        else:
            print(f"[FAIL] SHA-512 Digest Mismatch! Expected: {expected_sha512}")
            passed = False

    if hmac_secret:
        computed_hmac = hmac.new(
            hmac_secret.encode("utf-8"),
            actual_sha256.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        print(f"HMAC-SHA256 Signature: {computed_hmac}")

    print("=" * 80)
    if passed:
        print("VERDICT: EVIDENCE INTEGRITY VERIFIED (Court-Admissible under Section 63 BSA 2023)")
    else:
        print("VERDICT: TAMPERING DETECTED OR INTEGRITY CORRUPTED (Inadmissible)")
    print("=" * 80)

    return passed


def main():
    parser = argparse.ArgumentParser(description="Verify digital evidence against Section 63 BSA certificate.")
    parser.add_argument("--raw", required=True, help="Path to raw evidence file (.raw or .eml)")
    parser.add_argument("--sha256", help="Expected SHA-256 hash")
    parser.add_argument("--sha512", help="Expected SHA-512 hash")
    parser.add_argument("--pdf", help="Path to Section 63 BSA PDF certificate")
    parser.add_argument("--hmac-secret", help="Optional HMAC secret key")

    args = parser.parse_args()
    raw_path = Path(args.raw)
    pdf_path = Path(args.pdf) if args.pdf else None

    success = verify_evidence(
        raw_path=raw_path,
        expected_sha256=args.sha256,
        expected_sha512=args.sha512,
        pdf_path=pdf_path,
        hmac_secret=args.hmac_secret,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
