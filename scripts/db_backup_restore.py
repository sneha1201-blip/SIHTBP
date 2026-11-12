"""Database Backup & Disaster Recovery Utility.

Supports snapshotting and restoring forensic database state with cryptographic
SHA-256 manifest verification, ensuring tamper-evident operational recovery.

Usage:
    python scripts/db_backup_restore.py backup [--dest storage/backups]
    python scripts/db_backup_restore.py restore --manifest storage/backups/backup_<timestamp>.manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("db_backup_restore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = PROJECT_ROOT / "storage"
DEFAULT_DB_FILE = STORAGE_DIR / "forensic_platform.db"
BACKUP_DIR = STORAGE_DIR / "backups"


def calculate_file_sha256(path: Path) -> str:
    """Calculate SHA-256 checksum of a physical file."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest().lower()


def backup_database(
    source_db: Path = DEFAULT_DB_FILE,
    dest_dir: Path = BACKUP_DIR,
) -> Dict[str, Any]:
    """Execute online physical snapshot of database with cryptographic manifest."""
    if not source_db.exists():
        raise FileNotFoundError(f"Source database file not found: {source_db}")

    dest_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = dest_dir / f"forensic_platform_backup_{timestamp}.db"
    manifest_file = dest_dir / f"forensic_platform_backup_{timestamp}.manifest.json"

    logger.info("Initiating online backup from %s -> %s", source_db, backup_file)

    # Use SQLite online backup API for ACID safety during active WAL writes
    src_conn = sqlite3.connect(str(source_db))
    dst_conn = sqlite3.connect(str(backup_file))
    with dst_conn:
        src_conn.backup(dst_conn, pages=100)
    dst_conn.close()
    src_conn.close()

    source_hash = calculate_file_sha256(source_db)
    backup_hash = calculate_file_sha256(backup_file)
    size_bytes = backup_file.stat().st_size

    manifest = {
        "backup_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_db_path": str(source_db.resolve()),
        "source_sha256": source_hash,
        "backup_db_path": str(backup_file.resolve()),
        "backup_sha256": backup_hash,
        "backup_size_bytes": size_bytes,
        "sih_problem_statement_id": "26106",
        "statutory_mandate": "Section 63 Bharatiya Sakshya Adhiniyam, 2023",
    }

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info("Backup successfully completed (Size: %d bytes, SHA256: %s)", size_bytes, backup_hash)
    logger.info("Manifest saved to: %s", manifest_file)

    return manifest


def restore_database(
    manifest_file: Path,
    target_db: Path = DEFAULT_DB_FILE,
) -> bool:
    """Verify cryptographic manifest and restore database safely."""
    if manifest_file.suffix == ".db":
        manifest_file = manifest_file.with_suffix(".manifest.json")

    if not manifest_file.exists():
        raise FileNotFoundError(f"Manifest file not found: {manifest_file}")

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    backup_path = Path(manifest["backup_db_path"])
    expected_sha256 = manifest["backup_sha256"].lower()

    if not backup_path.exists():
        raise FileNotFoundError(f"Backup image referenced in manifest not found: {backup_path}")

    logger.info("Verifying cryptographic integrity of backup image: %s", backup_path)
    actual_sha256 = calculate_file_sha256(backup_path)

    if actual_sha256 != expected_sha256:
        logger.error(
            "RESTORE REJECTED: Cryptographic checksum mismatch! Expected %s, got %s",
            expected_sha256,
            actual_sha256,
        )
        return False

    logger.info("Checksum verified. Restoring database to: %s", target_db)
    target_db.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup_path, target_db)

    # Clean up any stale WAL or SHM companion files
    wal_file = target_db.with_name(f"{target_db.name}-wal")
    shm_file = target_db.with_name(f"{target_db.name}-shm")
    if wal_file.exists():
        wal_file.unlink()
    if shm_file.exists():
        shm_file.unlink()

    logger.info("Database restoration successfully completed.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Forensic database backup and disaster recovery utility.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_parser = subparsers.add_parser("backup", help="Create a verified database backup snapshot.")
    backup_parser.add_argument("--source", "--db", dest="source", default=str(DEFAULT_DB_FILE), help="Source database file path.")
    backup_parser.add_argument("--dest", "--out", dest="dest", default=str(BACKUP_DIR), help="Destination backup directory.")

    restore_parser = subparsers.add_parser("restore", help="Restore database from a verified manifest.")
    restore_parser.add_argument("--manifest", "--backup", dest="manifest", required=True, help="Path to backup manifest JSON or DB.")
    restore_parser.add_argument("--target", default=str(DEFAULT_DB_FILE), help="Target database file path.")

    args = parser.parse_args()

    if args.command == "backup":
        backup_database(Path(args.source), Path(args.dest))
    elif args.command == "restore":
        success = restore_database(Path(args.manifest), Path(args.target))
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
