"""Threat Intelligence Feed Manager (PhishTank, OpenPhish, Tor).

Handles downloading, versioning, SHA-256 cryptographic hashing, and local caching
of threat feeds for offline and air-gapped forensic threat analysis.
Includes full failure-injection safety (graceful degradation on timeout/error).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from backend.app.core.config import STORAGE_DIR

logger = logging.getLogger("threat_feeds")

FEEDS_STORAGE_DIR = STORAGE_DIR / "threat_feeds"


def get_feeds_dir() -> Path:
    """Return and ensure presence of threat feeds storage directory."""
    FEEDS_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return FEEDS_STORAGE_DIR


async def download_and_version_feed(
    feed_name: str,
    feed_url: str,
    timeout_seconds: float = 3.0,
    storage_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Download external threat feed, record SHA-256 hash, and version timestamp."""
    target_dir = storage_dir or get_feeds_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    manifest_file = target_dir / f"{feed_name}_{timestamp}.manifest.json"
    data_file = target_dir / f"{feed_name}_{timestamp}.dat"
    latest_manifest_file = target_dir / f"{feed_name}_latest.manifest.json"

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
            resp = await client.get(feed_url)
            resp.raise_for_status()
            content = resp.content

        sha256_hash = hashlib.sha256(content).hexdigest()
        data_file.write_bytes(content)

        # Parse count if JSON or lines if text
        record_count = 0
        try:
            parsed = json.loads(content.decode("utf-8", errors="ignore"))
            if isinstance(parsed, list):
                record_count = len(parsed)
            elif isinstance(parsed, dict):
                record_count = len(parsed.keys())
        except Exception:
            record_count = len([line for line in content.splitlines() if line.strip()])

        manifest = {
            "feed_name": feed_name,
            "feed_url": feed_url,
            "version": timestamp,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "sha256": sha256_hash,
            "size_bytes": len(content),
            "record_count": record_count,
            "status": "ACTIVE",
            "file_path": str(data_file.resolve()),
        }

        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        with open(latest_manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        logger.info(
            "Threat feed '%s' successfully updated (Records: %d, SHA256: %s)",
            feed_name,
            record_count,
            sha256_hash,
        )
        return manifest

    except Exception as exc:
        logger.warning("Failure downloading threat feed '%s' from %s: %s", feed_name, feed_url, exc)
        # Failure injection resilience: check if a previous local version exists
        if latest_manifest_file.exists():
            try:
                with open(latest_manifest_file, "r", encoding="utf-8") as f:
                    cached_manifest = json.load(f)
                cached_manifest["status"] = "DEGRADED_CACHED"
                cached_manifest["fallback_reason"] = f"Live fetch failed: {exc}"
                return cached_manifest
            except Exception:
                pass

        return {
            "feed_name": feed_name,
            "feed_url": feed_url,
            "version": None,
            "sha256": None,
            "status": "UNAVAILABLE",
            "record_count": 0,
            "reason": f"Feed fetch failed: {exc}",
        }


def check_url_in_threat_feed(
    url: str,
    feed_name: str,
    storage_dir: Optional[Path] = None,
    mock_feed_urls: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Check whether a target URL is present in the specified threat feed."""
    if mock_feed_urls is not None:
        is_hit = any(bad_url.lower() in url.lower() for bad_url in mock_feed_urls)
        return {
            "feed_name": feed_name,
            "is_matched": is_hit,
            "feed_source": "FIXTURE",
            "feed_version": "20261112_TEST",
            "feed_sha256": hashlib.sha256(b"fixture").hexdigest(),
        }

    target_dir = storage_dir or get_feeds_dir()
    latest_manifest_file = target_dir / f"{feed_name}_latest.manifest.json"

    if not latest_manifest_file.exists():
        return {
            "feed_name": feed_name,
            "is_matched": False,
            "feed_source": "NONE",
            "reason": f"Threat feed '{feed_name}' not downloaded or uninitialized",
        }

    try:
        with open(latest_manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        data_path = Path(manifest.get("file_path", ""))
        if not data_path.exists():
            return {
                "feed_name": feed_name,
                "is_matched": False,
                "feed_source": "MISSING_DATA",
                "reason": "Manifest exists but feed data file was deleted",
            }

        content_str = data_path.read_text(encoding="utf-8", errors="ignore")
        is_hit = url.lower() in content_str.lower()
        return {
            "feed_name": feed_name,
            "is_matched": is_hit,
            "feed_source": manifest.get("status", "ACTIVE"),
            "feed_version": manifest.get("version"),
            "feed_sha256": manifest.get("sha256"),
        }
    except Exception as exc:
        return {
            "feed_name": feed_name,
            "is_matched": False,
            "feed_source": "ERROR",
            "reason": f"Lookup error: {exc}",
        }
