"""Cryptographic Evidence Vault for Raw Email Evidence.

Provides tamper-evident, immutable storage for raw RFC 822 (.eml) and .msg artifacts.
Implements dual SHA-256 and MD5 cryptographic hashing, WORM (Write-Once-Read-Many)
storage mechanics, and HMAC-SHA256 audit ledger signatures to satisfy chain-of-custody
integrity requirements for the AICTE Cyber Security Cell.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO, Optional, Tuple, Union

# Environment-configurable vault directory and HMAC secret key
DEFAULT_VAULT_DIR = Path(__file__).resolve().parent.parent.parent.parent / "storage" / "vault"
DEFAULT_HMAC_SECRET = "aicte-sih-26106-forensic-vault-secret-key-2026"


def get_vault_dir() -> Path:
    """Return the absolute path to the immutable storage vault directory."""
    raw_path = os.getenv("VAULT_STORAGE_DIR")
    if raw_path:
        vault_path = Path(raw_path).resolve()
    else:
        vault_path = DEFAULT_VAULT_DIR.resolve()
    vault_path.mkdir(parents=True, exist_ok=True)
    return vault_path


def get_hmac_secret() -> bytes:
    """Return the HMAC secret key as bytes."""
    secret = os.getenv("VAULT_HMAC_SECRET", DEFAULT_HMAC_SECRET)
    return secret.encode("utf-8")


def calculate_hashes(data: Union[bytes, bytearray, memoryview]) -> Tuple[str, str]:
    """Calculate SHA-256 and MD5 hashes in a single pass over raw byte data.

    Returns:
        Tuple[str, str]: (sha256_hex, md5_hex)
    """
    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    
    view = memoryview(data)
    chunk_size = 65536
    for i in range(0, len(view), chunk_size):
        chunk = view[i:i + chunk_size]
        sha256_hasher.update(chunk)
        md5_hasher.update(chunk)
        
    return sha256_hasher.hexdigest(), md5_hasher.hexdigest()


def calculate_stream_hashes(stream: BinaryIO, chunk_size: int = 65536) -> Tuple[str, str, int]:
    """Calculate SHA-256 and MD5 hashes and total byte length over a binary stream.

    Returns:
        Tuple[str, str, int]: (sha256_hex, md5_hex, total_bytes)
    """
    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    total_bytes = 0

    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        total_bytes += len(chunk)
        sha256_hasher.update(chunk)
        md5_hasher.update(chunk)

    return sha256_hasher.hexdigest(), md5_hasher.hexdigest(), total_bytes


def generate_hmac_signature(
    message: Union[str, bytes],
    key: Optional[Union[str, bytes]] = None,
) -> str:
    """Generate an HMAC-SHA256 signature for audit ledger entries and evidence sealing.

    Args:
        message: The canonicalized string or bytes to sign.
        key: Optional HMAC key. Defaults to environment/configured secret.

    Returns:
        str: Hexadecimal HMAC-SHA256 digest.
    """
    if key is None:
        key_bytes = get_hmac_secret()
    elif isinstance(key, str):
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = key

    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    else:
        message_bytes = message

    return hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()


def verify_hmac_signature(
    message: Union[str, bytes],
    expected_hmac: str,
    key: Optional[Union[str, bytes]] = None,
) -> bool:
    """Verify an HMAC-SHA256 signature using constant-time comparison.

    Returns:
        bool: True if signature is valid and untampered, False otherwise.
    """
    computed = generate_hmac_signature(message, key=key)
    return hmac.compare_digest(computed.lower(), expected_hmac.lower())


def canonicalize_audit_payload(
    actor: str,
    action: str,
    evidence_sha256: str,
    recorded_at: Union[datetime, str],
    details: Optional[dict] = None,
) -> str:
    """Build a deterministic, sorted canonical string representation of an audit event.

    Ensures consistent cryptographic HMAC generation across all nodes and storage engines.
    """
    if hasattr(recorded_at, "strftime"):
        time_str = recorded_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        time_clean = str(recorded_at).split(".")[0].replace("Z", "").replace("+00:00", "")
        time_str = f"{time_clean}Z"

    details_str = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    return f"ACTOR:{actor}|ACTION:{action}|SHA256:{evidence_sha256}|TIME:{time_str}|DETAILS:{details_str}"


def store_raw_evidence(
    raw_bytes: bytes,
    file_name_hint: Optional[str] = None,
    vault_dir: Optional[Union[Path, str]] = None,
) -> Tuple[str, str, str, int]:
    """Store raw email evidence in the cryptographic vault under {sha256}.raw.

    Implements atomic write operations and write-once read-only permission flags
    to protect evidence integrity against accidental or malicious tampering.

    Args:
        raw_bytes: Complete raw RFC 822 (.eml) or .msg content bytes.
        file_name_hint: Original filename provided during ingestion.
        vault_dir: Optional override for vault directory path.

    Returns:
        Tuple[str, str, str, int]: (sha256, md5, stored_absolute_path, file_size_bytes)
    """
    target_dir = Path(vault_dir).resolve() if vault_dir else get_vault_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    sha256_hash, md5_hash = calculate_hashes(raw_bytes)
    evidence_path = target_dir / f"{sha256_hash}.raw"

    # If the file already exists, verify its integrity rather than re-writing
    if evidence_path.exists():
        with open(evidence_path, "rb") as f:
            existing_bytes = f.read()
        existing_sha256, _ = calculate_hashes(existing_bytes)
        if existing_sha256 != sha256_hash:
            raise ValueError(
                f"Vault collision/tampering detected: Existing file {evidence_path} "
                f"hash {existing_sha256} does not match incoming {sha256_hash}"
            )
        return sha256_hash, md5_hash, str(evidence_path), len(raw_bytes)

    # Atomic write pattern: write to temporary file in the same directory, then rename
    temp_fd, temp_file_path = tempfile.mkstemp(dir=target_dir, prefix="evidence_", suffix=".tmp")
    try:
        with os.fdopen(temp_fd, "wb") as f:
            f.write(raw_bytes)
            f.flush()
            os.fsync(f.fileno())

        # Set read-only permission (Write-Once-Read-Many forensic principle)
        try:
            os.chmod(temp_file_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except Exception:
            pass  # Non-fatal on platforms that don't support full POSIX modes

        os.replace(temp_file_path, evidence_path)
    except Exception:
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass
        raise

    return sha256_hash, md5_hash, str(evidence_path), len(raw_bytes)


def read_raw_evidence(
    sha256_hash: str,
    vault_dir: Optional[Union[Path, str]] = None,
) -> bytes:
    """Read raw email bytes from the vault and verify SHA-256 before returning.

    Raises:
        FileNotFoundError: If no vault artifact matches sha256_hash.
        ValueError: If stored file fails cryptographic integrity verification.
    """
    target_dir = Path(vault_dir).resolve() if vault_dir else get_vault_dir()
    evidence_path = target_dir / f"{sha256_hash}.raw"

    if not evidence_path.exists():
        raise FileNotFoundError(f"Vault artifact not found for hash: {sha256_hash}")

    with open(evidence_path, "rb") as f:
        data = f.read()

    computed_sha256, _ = calculate_hashes(data)
    if computed_sha256.lower() != sha256_hash.lower():
        raise ValueError(
            f"Cryptographic integrity violation! File {evidence_path} has hash {computed_sha256}, "
            f"expected {sha256_hash}"
        )

    return data


def verify_evidence_integrity(
    sha256_hash: str,
    vault_dir: Optional[Union[Path, str]] = None,
) -> dict:
    """Perform a thorough health and cryptographic integrity audit on a vault file.

    Returns:
        dict: Inspection report containing status, actual hashes, size, and integrity flag.
    """
    target_dir = Path(vault_dir).resolve() if vault_dir else get_vault_dir()
    evidence_path = target_dir / f"{sha256_hash}.raw"

    if not evidence_path.exists():
        return {
            "exists": False,
            "intact": False,
            "sha256": sha256_hash,
            "error": "File does not exist in vault",
        }

    try:
        with open(evidence_path, "rb") as f:
            data = f.read()
        computed_sha256, computed_md5 = calculate_hashes(data)
        is_intact = computed_sha256.lower() == sha256_hash.lower()

        return {
            "exists": True,
            "intact": is_intact,
            "file_path": str(evidence_path),
            "expected_sha256": sha256_hash,
            "computed_sha256": computed_sha256,
            "computed_md5": computed_md5,
            "size_bytes": len(data),
            "error": None if is_intact else "SHA-256 hash mismatch - possible tampering",
        }
    except Exception as exc:
        return {
            "exists": True,
            "intact": False,
            "file_path": str(evidence_path),
            "sha256": sha256_hash,
            "error": str(exc),
        }
