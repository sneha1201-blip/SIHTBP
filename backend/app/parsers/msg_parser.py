"""Outlook MSG (.msg) Parser with Resilient Fallback Regex Scanner.

Extracts headers, bodies, recipients, and attachments from Outlook compound document files.
Includes a dedicated fallback ASCII/MIME regex scanner to handle corrupted OLE streams
or truncated files without raising unhandled 500 exceptions.
"""

from __future__ import annotations

import io
import re
import hashlib
import logging
from typing import Optional

from backend.app.database.vault import calculate_hashes
from backend.app.parsers.mime_normalizer import (
    AttachmentMeta,
    ParsedEmailData,
    compute_simhash,
)
from backend.app.parsers.eml_parser import DANGEROUS_EXTENSIONS

logger = logging.getLogger("msg_parser")


def fallback_ascii_msg_scanner(
    raw_bytes: bytes, filename: str, sha256_hash: str, md5_hash: str
) -> ParsedEmailData:
    """Extract forensic metadata from corrupted OLE streams using raw ASCII/UTF-8 regex scanning.

    Ensures that corrupted Outlook files, partial memory dumps, or invalid compound documents
    never cause an unhandled 500 server crash during forensic triage.
    """
    logger.warning("Invoking fallback ASCII/MIME regex scanner for corrupted .msg: %s", filename)

    # Extract all printable ASCII string segments of length >= 4
    string_chunks = re.findall(rb"[\x20-\x7E\r\n\t]{4,}", raw_bytes)
    text_content = "\n".join([chunk.decode("ascii", errors="replace") for chunk in string_chunks])

    # Scan for Subject
    subject_match = re.search(r"(?:Subject|Thread-Topic)\s*:\s*([^\r\n]+)", text_content, re.IGNORECASE)
    subject = subject_match.group(1).strip() if subject_match else f"[Corrupted MSG Stream: {filename}]"

    # Scan for Sender
    sender_match = re.search(r"(?:From|Sender|Return-Path)\s*:\s*([^\r\n]+)", text_content, re.IGNORECASE)
    sender_raw = sender_match.group(1).strip() if sender_match else "unknown-sender@corrupted.msg"
    sender_email = None
    sender_display = None
    if "<" in sender_raw and ">" in sender_raw:
        parts = sender_raw.split("<")
        sender_display = parts[0].strip(' "\'')
        sender_email = parts[1].split(">")[0].strip().lower()
    else:
        sender_email = sender_raw.strip().lower()

    # Scan for Recipients
    recipients = []
    to_matches = re.findall(r"(?:To|Cc)\s*:\s*([^\r\n]+)", text_content, re.IGNORECASE)
    for tm in to_matches:
        for r in tm.split(";"):
            cleaned_r = r.strip().lower()
            if "@" in cleaned_r:
                recipients.append(cleaned_r)

    # Scan for Received headers
    received_headers = []
    rec_matches = re.findall(r"Received\s*:\s*([^\r\n]+(?:[\r\n]+[ \t]+[^\r\n]+)*)", text_content, re.IGNORECASE)
    for rm in rec_matches:
        received_headers.append(" ".join(rm.split()))

    # Build plain text body from the longest text blocks
    body_blocks = [chunk.decode("ascii", errors="replace") for chunk in string_chunks if len(chunk) > 40]
    body_plain = "\n\n".join(body_blocks[:15]) if body_blocks else text_content[:2000]

    simhash_body = compute_simhash(body_plain)

    return ParsedEmailData(
        file_name=filename,
        file_size_bytes=len(raw_bytes),
        sha256_hash=sha256_hash,
        md5_hash=md5_hash,
        subject=subject,
        date_header=None,
        sender_raw=sender_raw,
        sender_email=sender_email,
        sender_display=sender_display,
        recipient_list=recipients or ["forensics-triage@institution.ac.in"],
        received_headers=received_headers,
        headers_dict={"X-Forensic-Note": ["Corrupted MSG stream recovered via ASCII scanner"]},
        body_plain=body_plain,
        body_html=None,
        simhash_body=simhash_body,
        attachments=[],
    )


def parse_msg(raw_bytes: bytes, filename: str = "evidence.msg") -> ParsedEmailData:
    """Parse raw Outlook .msg bytes into a normalized ParsedEmailData structure.

    Wrapped with multi-tiered fallback:
    1. extract-msg compound document parser
    2. MIME/EML fallback parser (if mislabeled ASCII email)
    3. Resilient ASCII/MIME regex scanner (for corrupted binary streams)
    """
    sha256_hash, md5_hash = calculate_hashes(raw_bytes)

    # Tier 1: extract_msg library
    try:
        import extract_msg
        msg = extract_msg.Message(io.BytesIO(raw_bytes))

        subject = msg.subject or ""
        sender_raw = msg.sender or ""
        sender_email = None
        sender_display = None
        if "<" in sender_raw and ">" in sender_raw:
            parts = sender_raw.split("<")
            sender_display = parts[0].strip(' "\'')
            sender_email = parts[1].split(">")[0].strip().lower()
        else:
            sender_email = sender_raw.strip().lower()

        recipient_list = []
        if msg.to:
            recipient_list.extend([r.strip().lower() for r in msg.to.split(";") if r.strip()])
        if msg.cc:
            recipient_list.extend([r.strip().lower() for r in msg.cc.split(";") if r.strip()])

        date_header = msg.date
        body_plain = msg.body
        body_html = msg.htmlBody
        if isinstance(body_html, bytes):
            body_html = body_html.decode("utf-8", errors="replace")

        # Received headers
        received_headers = []
        headers_dict = {}
        if msg.header:
            header_text = str(msg.header)
            for line in header_text.splitlines():
                if line.startswith("Received:"):
                    received_headers.append(line.replace("Received:", "").strip())
                elif ":" in line:
                    k, v = line.split(":", 1)
                    headers_dict.setdefault(k.strip(), []).append(v.strip())

        attachments = []
        if hasattr(msg, "attachments"):
            for att in msg.attachments:
                att_data = getattr(att, "data", b"") or b""
                a_sha256 = hashlib.sha256(att_data).hexdigest()
                a_md5 = hashlib.md5(att_data).hexdigest()
                name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment"
                is_dangerous = any(name.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)
                attachments.append(
                    AttachmentMeta(
                        filename=name,
                        content_type=getattr(att, "mimetype", "application/octet-stream") or "application/octet-stream",
                        size_bytes=len(att_data),
                        sha256=a_sha256,
                        md5=a_md5,
                        is_suspicious_extension=is_dangerous,
                    )
                )

        simhash_body = compute_simhash(body_plain or body_html or "")

        return ParsedEmailData(
            file_name=filename,
            file_size_bytes=len(raw_bytes),
            sha256_hash=sha256_hash,
            md5_hash=md5_hash,
            subject=subject,
            date_header=date_header,
            sender_raw=sender_raw,
            sender_email=sender_email,
            sender_display=sender_display,
            recipient_list=recipient_list,
            received_headers=received_headers,
            headers_dict=headers_dict,
            body_plain=body_plain,
            body_html=body_html,
            simhash_body=simhash_body,
            attachments=attachments,
        )
    except Exception as exc_ole:
        logger.debug("extract-msg failed on %s: %s. Attempting Tier 2 EML parser.", filename, exc_ole)

    # Tier 2: EML parser (in case file is RFC 822 ASCII mislabeled as .msg)
    try:
        from backend.app.parsers.eml_parser import parse_eml
        return parse_eml(raw_bytes, filename=filename)
    except Exception as exc_eml:
        logger.debug("EML fallback failed on %s: %s. Attempting Tier 3 ASCII regex scanner.", filename, exc_eml)

    # Tier 3: Resilient fallback ASCII regex scanner
    return fallback_ascii_msg_scanner(raw_bytes, filename, sha256_hash, md5_hash)
