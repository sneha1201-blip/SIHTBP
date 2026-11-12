#!/usr/bin/env python3
"""Corpus Ingestion CLI Tool for AICTE Cyber Security Forensic Platform.

Batch ingests real-world RFC 822 (.eml) and Outlook (.msg) files into the
forensic analysis pipeline via the authenticated REST API endpoint
`/api/v1/forensics/analyze`.

Displays case IDs, SHA-256 digests, threat scores, forensic verdicts,
and saves optional JSON telemetry for audit trail verification.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for corpus ingestion."""
    parser = argparse.ArgumentParser(
        description="Ingest a directory of RFC 822 (.eml) or Outlook (.msg) files into the AICTE Forensic Platform."
    )
    parser.add_argument(
        "corpus_dir",
        nargs="?",
        default=None,
        help="Path to directory containing .eml or .msg files to ingest.",
    )
    parser.add_argument(
        "--dir",
        dest="dir_flag",
        default=None,
        help="Alternative flag to specify corpus directory path.",
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api/v1"),
        help="API base URL (default: http://127.0.0.1:8000/api/v1).",
    )
    parser.add_argument(
        "--username",
        default=os.getenv("INGEST_USERNAME", "analyst"),
        help="Analyst or admin username for Bearer authentication.",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("INGEST_PASSWORD", "AnalystPassword@2026"),
        help="Password for Bearer authentication.",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("INGEST_TOKEN", None),
        help="Pre-issued JWT Bearer token (bypasses login request if provided).",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        default=True,
        help="Ingest synchronously via ?sync=true (default: True).",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        default=False,
        help="Recursively scan subdirectories for email files.",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write full ingestion telemetry JSON artifact.",
    )
    return parser.parse_args()


def acquire_bearer_token(client: httpx.Client, api_url: str, username: str, password: str) -> str:
    """Authenticate with OAuth2 password grant to acquire a JWT Bearer token."""
    token_url = f"{api_url.rstrip('/')}/auth/token"
    resp = client.post(
        token_url,
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Authentication failed ({resp.status_code}): {resp.text}"
        )
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError("No access_token returned by auth endpoint.")
    return str(token)


def discover_email_files(target_dir: Path, recursive: bool = False) -> List[Path]:
    """Find all .eml and .msg files in the target directory."""
    patterns = ("*.eml", "*.msg")
    files: List[Path] = []
    for pattern in patterns:
        if recursive:
            files.extend(target_dir.rglob(pattern))
        else:
            files.extend(target_dir.glob(pattern))
    return sorted(files)


def ingest_single_file(
    client: httpx.Client,
    api_url: str,
    file_path: Path,
    auth_token: str,
    sync_mode: bool = True,
) -> Dict[str, Any]:
    """Upload and analyze a single email artifact via the REST API."""
    analyze_url = f"{api_url.rstrip('/')}/forensics/analyze"
    if sync_mode:
        analyze_url += "?sync=true"

    headers = {"Authorization": f"Bearer {auth_token}"}
    content_type = "application/vnd.ms-outlook" if file_path.suffix.lower() == ".msg" else "message/rfc822"

    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f, content_type)}
        resp = client.post(analyze_url, files=files, headers=headers, timeout=60.0)

    if resp.status_code not in (200, 201):
        return {
            "file_name": file_path.name,
            "path": str(file_path),
            "status": "FAILED",
            "http_status": resp.status_code,
            "error": resp.text,
        }

    data = resp.json()
    # Check if synchronous dossier returned
    if "email" in data and "forensic_analysis" in data:
        email_meta = data.get("email", {})
        analysis_meta = data.get("forensic_analysis", {})
        return {
            "file_name": file_path.name,
            "path": str(file_path),
            "status": "SUCCESS",
            "case_id": email_meta.get("id"),
            "sha256": email_meta.get("sha256_hash"),
            "subject": email_meta.get("subject"),
            "sender": email_meta.get("sender_email"),
            "threat_score": analysis_meta.get("threat_score"),
            "verdict": analysis_meta.get("verdict"),
            "spf": analysis_meta.get("spf_status"),
            "dkim": analysis_meta.get("dkim_status"),
            "dmarc": analysis_meta.get("dmarc_status"),
        }
    elif "job_id" in data:
        # Asynchronous job queued: poll job status endpoint until completion
        job_id = data["job_id"]
        job_url = f"{api_url.rstrip('/')}/forensics/jobs/{job_id}"
        poll_start = time.time()
        while time.time() - poll_start < 45.0:
            time.sleep(1.0)
            j_resp = client.get(job_url, headers=headers, timeout=10.0)
            if j_resp.status_code == 200:
                j_data = j_resp.json()
                if j_data.get("status") == "COMPLETED":
                    res = j_data.get("result", {})
                    email_meta = res.get("email", {})
                    analysis_meta = res.get("forensic_analysis", {})
                    return {
                        "file_name": file_path.name,
                        "path": str(file_path),
                        "status": "SUCCESS",
                        "case_id": email_meta.get("id"),
                        "sha256": email_meta.get("sha256_hash"),
                        "subject": email_meta.get("subject"),
                        "sender": email_meta.get("sender_email"),
                        "threat_score": analysis_meta.get("threat_score"),
                        "verdict": analysis_meta.get("verdict"),
                        "spf": analysis_meta.get("spf_status"),
                        "dkim": analysis_meta.get("dkim_status"),
                        "dmarc": analysis_meta.get("dmarc_status"),
                    }
                elif j_data.get("status") == "FAILED":
                    return {
                        "file_name": file_path.name,
                        "path": str(file_path),
                        "status": "FAILED",
                        "error": j_data.get("error_message", "Background analysis job failed"),
                    }

        return {
            "file_name": file_path.name,
            "path": str(file_path),
            "status": "TIMEOUT",
            "error": "Job timed out after 45s",
        }

    return {
        "file_name": file_path.name,
        "path": str(file_path),
        "status": "UNEXPECTED_RESPONSE",
        "data": data,
    }


def render_ingestion_table(results: List[Dict[str, Any]]) -> None:
    """Print formatted ASCII summary table of ingestion results."""
    print("+" + "-" * 5 + "+" + "-" * 26 + "+" + "-" * 38 + "+" + "-" * 16 + "+" + "-" * 8 + "+" + "-" * 12 + "+")
    print(f"| {'#':<3} | {'File Name':<24} | {'Case ID / UUID':<36} | {'SHA-256 (Prefix)':<14} | {'Score':<6} | {'Verdict':<10} |")
    print("+" + "=" * 5 + "+" + "=" * 26 + "+" + "=" * 38 + "+" + "=" * 16 + "+" + "=" * 8 + "+" + "=" * 12 + "+")

    for idx, item in enumerate(results, start=1):
        if item.get("status") == "SUCCESS":
            fname = item["file_name"][:24]
            cid = str(item.get("case_id", ""))[:36]
            sha = str(item.get("sha256", ""))[:14]
            score = f"{float(item.get('threat_score', 0.0)):>5.1f}"
            verdict = str(item.get("verdict", "UNKNOWN"))[:10]
            print(f"| {idx:<3} | {fname:<24} | {cid:<36} | {sha:<14} | {score:<6} | {verdict:<10} |")
        else:
            fname = item["file_name"][:24]
            err = str(item.get("error") or item.get("status"))[:54]
            print(f"| {idx:<3} | {fname:<24} | [ERROR] {err:<52} |")

    print("+" + "-" * 5 + "+" + "-" * 26 + "+" + "-" * 38 + "+" + "-" * 16 + "+" + "-" * 8 + "+" + "-" * 12 + "+")
    print()


def ingest_corpus(
    corpus_dir: Path,
    api_url: str = "http://127.0.0.1:8000/api/v1",
    username: str = "analyst",
    password: str = "AnalystPassword@2026",
    token: Optional[str] = None,
    sync_mode: bool = True,
    recursive: bool = False,
    custom_client: Optional[Any] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Programmatic entry point to ingest an entire corpus directory."""
    files = discover_email_files(corpus_dir, recursive=recursive)
    if not files:
        return [], {"total": 0, "success": 0, "failed": 0}

    client = custom_client or httpx.Client(timeout=60.0)
    should_close_client = custom_client is None

    try:
        active_token = token
        if not active_token:
            active_token = acquire_bearer_token(client, api_url, username, password)

        results: List[Dict[str, Any]] = []
        for f in files:
            res = ingest_single_file(client, api_url, f, active_token, sync_mode=sync_mode)
            results.append(res)

        success_count = sum(1 for r in results if r.get("status") == "SUCCESS")
        stats = {
            "total": len(files),
            "success": success_count,
            "failed": len(files) - success_count,
        }
        return results, stats
    finally:
        if should_close_client:
            client.close()


def main() -> None:
    """CLI execution entry point."""
    args = parse_arguments()
    target_str = args.dir_flag or args.corpus_dir
    if not target_str:
        print("[!] Error: You must specify a target corpus directory containing .eml or .msg files.")
        print("    Usage: python scripts/ingest_corpus.py /path/to/emails/ [--api-url http://...]")
        sys.exit(1)

    target_dir = Path(target_str)
    if not target_dir.exists() or not target_dir.is_dir():
        print(f"[!] Error: Target corpus path does not exist or is not a directory: {target_dir}")
        sys.exit(1)

    print(f"[*] Target Corpus Directory: {target_dir.resolve()}")
    print(f"[*] Target API Endpoint:     {args.api_url}")
    print(f"[*] Recursive Discovery:     {args.recursive}")
    print()

    with httpx.Client(timeout=60.0) as client:
        try:
            token = args.token
            if not token:
                print(f"[*] Authenticating as '{args.username}'...")
                token = acquire_bearer_token(client, args.api_url, args.username, args.password)
                print("[+] Authentication successful (Bearer JWT acquired).")

            print("[*] Scanning directory for .eml and .msg files...")
            files = discover_email_files(target_dir, recursive=args.recursive)
            print(f"[+] Discovered {len(files)} email artifacts.")
            if not files:
                print("[!] No .eml or .msg files found in target directory. Exiting.")
                sys.exit(0)

            print(f"[*] Ingesting {len(files)} files via POST /forensics/analyze ...\n")
            results = []
            for idx, f in enumerate(files, start=1):
                print(f"[{idx}/{len(files)}] Ingesting {f.name} ... ", end="", flush=True)
                res = ingest_single_file(client, args.api_url, f, token, sync_mode=args.sync)
                results.append(res)
                if res.get("status") == "SUCCESS":
                    print(f"DONE (Score: {res.get('threat_score'):.1f}, Verdict: {res.get('verdict')})")
                else:
                    print(f"FAILED ({res.get('error', 'Unknown error')})")

            print("\n" + "=" * 80)
            print("                 CORPUS INGESTION EXECUTIVE SUMMARY")
            print("=" * 80 + "\n")
            render_ingestion_table(results)

            success_cnt = sum(1 for r in results if r.get("status") == "SUCCESS")
            failed_cnt = len(results) - success_cnt
            print(f"[+] Total Files Ingested: {success_cnt}/{len(results)} (Failed: {failed_cnt})")

            if args.json_out:
                out_path = Path(args.json_out)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as out_fp:
                    json.dump({"ingested_at": time.time(), "results": results}, out_fp, indent=2)
                print(f"[+] Telemetry artifact saved to: {out_path.resolve()}")

            sys.exit(0 if failed_cnt == 0 else 1)

        except Exception as exc:
            print(f"[!] Ingestion aborted due to fatal error: {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()
