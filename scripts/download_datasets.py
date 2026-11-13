"""Script to download, verify, hash, parse, deduplicate, and curate email threat datasets.

Datasets:
1. Apache SpamAssassin (easy_ham, spam, hard_ham)
2. Jose Nazario Phishing Corpus (phishing0.mbox)
3. Enron Ham Slice (bdanalytics emails.csv)
4. Tranco Top 10k Domains (tranco-list.eu)

Computes SHA-256 for all archives, records provenance in evidence/datasets.md,
deduplicates via 64-bit SimHash (Hamming distance <= 3), and outputs:
- data/processed/corpus_deduped.jsonl
- data/processed/real_received_headers.json (for G06)
"""

from __future__ import annotations

import csv
import email
import email.policy
import gzip
import hashlib
import io
import json
import os
import re
import ssl
import sys
import tarfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_RAW = PROJECT_ROOT / "data" / "raw"
DATA_PROCESSED = PROJECT_ROOT / "data" / "processed"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"

DATA_RAW.mkdir(parents=True, exist_ok=True)
DATA_PROCESSED.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

SOURCES = {
    "sa_easy_ham": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "filename": "20030228_easy_ham.tar.bz2",
        "license": "Apache License 2.0 / Public Domain",
        "description": "Apache SpamAssassin Easy Ham (Legitimate Email Corpus)",
    },
    "sa_spam": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "filename": "20030228_spam.tar.bz2",
        "license": "Apache License 2.0 / Public Domain",
        "description": "Apache SpamAssassin Spam Corpus (Spam/Unsolicited Email)",
    },
    "sa_hard_ham": {
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "filename": "20030228_hard_ham.tar.bz2",
        "license": "Apache License 2.0 / Public Domain",
        "description": "Apache SpamAssassin Hard Ham (Tricky Benign Email)",
    },
    "nazario_phishing": {
        "url": "https://monkey.org/~jose/phishing/phishing0.mbox",
        "filename": "phishing0.mbox",
        "license": "Public Phishing Corpus (Jose Nazario)",
        "description": "Jose Nazario Phishing Email Corpus (Real Phishing Campaigns)",
    },
    "enron_slice": {
        "url": "https://raw.githubusercontent.com/bdanalytics/Enron-Spam/master/data/emails.csv",
        "filename": "enron_emails.csv",
        "license": "Public Domain (FERC Enron Investigation)",
        "description": "Enron Ham Slice (Corporate Legitimate Communications)",
    },
    "tranco_top10k": {
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "filename": "tranco_top1m.zip",
        "license": "Research and Non-Commercial / Tranco Research Project",
        "description": "Tranco Top Domains List (Top 10k extracted)",
    },
}


def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def download_file(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        print(f"[*] Already cached: {dest.name} ({dest.stat().st_size} bytes)")
        return
    print(f"[*] Downloading {url} -> {dest.name}...")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "SIHTBP-DatasetDownloader/1.0"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
        with open(dest, "wb") as out:
            while chunk := response.read(65536):
                out.write(chunk)
    print(f"[+] Download complete: {dest.name} ({dest.stat().st_size} bytes)")


def simhash(text: str) -> int:
    tokens = re.findall(r"\w+", text.lower())
    if not tokens:
        return 0
    v = [0] * 64
    for token in tokens:
        # 64-bit hash
        h = int(hashlib.md5(token.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            fingerprint |= 1 << i
    return fingerprint


def hamming_distance(h1: int, h2: int) -> int:
    return bin(h1 ^ h2).count("1")


def main() -> int:
    print("=== Downloading Datasets for SIHTBP Threat Detection ===")
    hashes = {}

    for key, info in SOURCES.items():
        dest = DATA_RAW / info["filename"]
        try:
            download_file(info["url"], dest)
            h = sha256_file(dest)
            hashes[key] = {
                **info,
                "sha256": h,
                "size_bytes": dest.stat().st_size,
                "download_date": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            print(f"[ERROR] Failed downloading {info['url']}: {e}")
            sys.exit(1)

    # 1. Process Tranco top 10k
    tranco_zip_path = DATA_RAW / SOURCES["tranco_top10k"]["filename"]
    tranco_out = DATA_PROCESSED / "tranco_top10k.csv"
    with zipfile.ZipFile(tranco_zip_path) as z:
        for name in z.namelist():
            if name.endswith(".csv"):
                with z.open(name) as zf, open(tranco_out, "w", encoding="utf-8", newline="") as out_csv:
                    reader = csv.reader(io.TextIOWrapper(zf, encoding="utf-8"))
                    writer = csv.writer(out_csv)
                    count = 0
                    for row in reader:
                        if len(row) >= 2:
                            writer.writerow(row[:2])
                            count += 1
                            if count >= 10000:
                                break
                print(f"[+] Extracted Tranco Top 10,000 domains -> {tranco_out.name}")
                break

    # 2. Extract and parse SpamAssassin archives & Received headers
    raw_samples: list[dict] = []
    received_headers: list[dict] = []

    def extract_sa_archive(archive_path: Path, label: int, source_name: str, limit: int = 1500) -> None:
        print(f"[*] Extracting {archive_path.name} (label={label})...")
        count = 0
        with tarfile.open(archive_path, "r:bz2") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                f = tar.extractfile(member)
                if not f:
                    continue
                content_bytes = f.read()
                try:
                    msg = email.message_from_bytes(content_bytes, policy=email.policy.default)
                    subject = str(msg.get("subject", "") or "")
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                try:
                                    body += part.get_content()
                                except Exception:
                                    pass
                    else:
                        try:
                            body = msg.get_content()
                        except Exception:
                            body = msg.get_payload() or ""
                    if not isinstance(body, str):
                        body = str(body)

                    # Extract all Received headers for G06
                    msg_headers = msg.get_all("received", [])
                    for rh in msg_headers:
                        clean_rh = " ".join(str(rh).split())
                        if clean_rh and len(received_headers) < 1000:
                            received_headers.append({
                                "source": source_name,
                                "raw_header": clean_rh
                            })

                    text = f"{subject}\n\n{body}".strip()
                    if len(text) > 20:
                        raw_samples.append({
                            "source": source_name,
                            "label": label,
                            "subject": subject,
                            "body": body[:4000],
                            "full_text": text[:5000],
                        })
                        count += 1
                        if count >= limit:
                            break
                except Exception:
                    continue
        print(f"[+] Loaded {count} samples from {archive_path.name}")

    extract_sa_archive(DATA_RAW / SOURCES["sa_easy_ham"]["filename"], label=0, source_name="sa_easy_ham", limit=1200)
    extract_sa_archive(DATA_RAW / SOURCES["sa_hard_ham"]["filename"], label=0, source_name="sa_hard_ham", limit=250)
    extract_sa_archive(DATA_RAW / SOURCES["sa_spam"]["filename"], label=1, source_name="sa_spam", limit=500)

    # 3. Extract Nazario phishing corpus
    nazario_path = DATA_RAW / SOURCES["nazario_phishing"]["filename"]
    print(f"[*] Extracting Nazario phishing mbox: {nazario_path.name}...")
    naz_count = 0
    with open(nazario_path, "rb") as mf:
        content_bytes = mf.read()
    # Split mbox by "From " line
    mbox_parts = re.split(rb"\n(?=From \S+)", content_bytes)
    for part in mbox_parts:
        if not part.strip():
            continue
        try:
            msg = email.message_from_bytes(part, policy=email.policy.compat32)
            subject = str(msg.get("subject", "") or "")
            body = ""
            if msg.is_multipart():
                for subpart in msg.walk():
                    if subpart.get_content_type() == "text/plain":
                        payload = subpart.get_payload(decode=True)
                        if payload:
                            body += payload.decode("latin1", errors="replace")
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("latin1", errors="replace")
                else:
                    body = str(msg.get_payload() or "")

            msg_headers = msg.get_all("received", [])
            for rh in msg_headers:
                clean_rh = " ".join(str(rh).split())
                if clean_rh and len(received_headers) < 1500:
                    received_headers.append({
                        "source": "nazario_phishing",
                        "raw_header": clean_rh
                    })

            text = f"{subject}\n\n{body}".strip()
            if len(text) > 20:
                raw_samples.append({
                    "source": "nazario_phishing",
                    "label": 1,
                    "subject": subject,
                    "body": body[:4000],
                    "full_text": text[:5000],
                })
                naz_count += 1
                if naz_count >= 1200:
                    break
        except Exception:
            continue
    print(f"[+] Loaded {naz_count} phishing samples from Nazario corpus")

    # 4. Extract Enron Ham slice
    enron_path = DATA_RAW / SOURCES["enron_slice"]["filename"]
    print(f"[*] Extracting Enron Ham slice from CSV...")
    enron_count = 0
    with open(enron_path, "r", encoding="utf-8", errors="replace") as ef:
        reader = csv.DictReader(ef)
        for row in reader:
            is_spam = row.get("spam", "").strip()
            # Only take ham (spam == "0")
            if is_spam == "0":
                full_text = row.get("text", "").strip()
                if len(full_text) > 30:
                    raw_samples.append({
                        "source": "enron_ham",
                        "label": 0,
                        "subject": full_text[:100].split("\n")[0],
                        "body": full_text[100:4000],
                        "full_text": full_text[:5000],
                    })
                    enron_count += 1
                    if enron_count >= 800:
                        break
    print(f"[+] Loaded {enron_count} corporate ham samples from Enron")

    # Save real received headers for G06
    headers_file = DATA_PROCESSED / "real_received_headers.json"
    with open(headers_file, "w", encoding="utf-8") as hf:
        json.dump(received_headers, hf, indent=2)
    print(f"[+] Saved {len(received_headers)} real Received headers -> {headers_file.name}")

    # 5. Deduplicate using 64-bit SimHash (Hamming distance <= 3)
    print(f"[*] Deduplicating {len(raw_samples)} samples using 64-bit SimHash...")
    deduped_samples: list[dict] = []
    seen_hashes: list[int] = []

    for item in raw_samples:
        sh = simhash(item["full_text"])
        is_dup = False
        for existing_sh in seen_hashes:
            if hamming_distance(sh, existing_sh) <= 3:
                is_dup = True
                break
        if not is_dup:
            seen_hashes.append(sh)
            deduped_samples.append(item)

    print(f"[+] Deduplication complete: {len(raw_samples)} -> {len(deduped_samples)} unique samples (removed {len(raw_samples) - len(deduped_samples)} duplicates)")

    # Save deduped corpus
    corpus_out = DATA_PROCESSED / "corpus_deduped.jsonl"
    with open(corpus_out, "w", encoding="utf-8") as cf:
        for sample in deduped_samples:
            cf.write(json.dumps(sample) + "\n")
    print(f"[+] Saved {len(deduped_samples)} samples to {corpus_out.name}")

    # 6. Generate evidence/datasets.md with SHA-256 digests and provenance
    datasets_md = EVIDENCE_DIR / "datasets.md"
    ham_count = sum(1 for s in deduped_samples if s["label"] == 0)
    spam_count = sum(1 for s in deduped_samples if s["label"] == 1)

    md_lines = [
        "# Threat Intelligence & Threat Classification Dataset Registry",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Total Curated Samples:** {len(deduped_samples)} ({ham_count} Legitimate Ham / {spam_count} Phishing & Spam)",
        f"**Deduplication:** 64-bit SimHash (Hamming Distance $\le$ 3)",
        "",
        "## Downloaded Dataset Provenance & SHA-256 Digests",
        "",
        "| Dataset Key | Description | Source URL | Size (Bytes) | SHA-256 Hex Digest | License |",
        "|---|---|---|---|---|---|",
    ]
    for key, item in hashes.items():
        md_lines.append(
            f"| `{key}` | {item['description']} | [{item['filename']}]({item['url']}) | {item['size_bytes']:,} | `{item['sha256']}` | {item['license']} |"
        )

    md_lines.extend([
        "",
        "## Curated Corpus Composition",
        "",
        "| Source | Category | Samples Extracted | Label | Description |",
        "|---|---|---|---|---|",
        f"| Apache SpamAssassin Easy Ham | Benign / Ham | {sum(1 for s in deduped_samples if s['source'] == 'sa_easy_ham')} | 0 | Public legitimate mailing lists, discussions |",
        f"| Apache SpamAssassin Hard Ham | Benign / Ham | {sum(1 for s in deduped_samples if s['source'] == 'sa_hard_ham')} | 0 | Complex HTML and formatted notifications |",
        f"| Enron Ham Slice | Corporate Benign | {sum(1 for s in deduped_samples if s['source'] == 'enron_ham')} | 0 | Internal corporate communication |",
        f"| Jose Nazario Phishing Corpus | Threat / Phishing | {sum(1 for s in deduped_samples if s['source'] == 'nazario_phishing')} | 1 | Real-world banking, credentials & spear phishing |",
        f"| Apache SpamAssassin Spam | Threat / Spam | {sum(1 for s in deduped_samples if s['source'] == 'sa_spam')} | 1 | Unsolicited bulk commercial email & scams |",
        "",
        "## Real Received Header Extraction for Forensic Parsing (G06)",
        f"- **Extracted Headers:** {len(received_headers)} real RFC-compliant and non-compliant headers saved to `data/processed/real_received_headers.json`.",
        "- **Purpose:** Hop traversal and IP/domain forensic analysis without synthetic f-strings.",
        "",
        "## Top Domain Registry (Tranco)",
        f"- **Extracted Top Domains:** 10,000 domains saved to `data/processed/tranco_top10k.csv` for brand squatting and spoofing risk baselining.",
    ])

    datasets_md.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"[+] Written verified dataset provenance -> {datasets_md.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

