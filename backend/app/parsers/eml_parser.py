"""RFC 822 / MIME (.eml) Email Parser.

Extracts structured headers, received chains, plain and HTML bodies,
and attachments with full cryptographic checksumming.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
from email.utils import parseaddr, parsedate_to_datetime
from typing import Optional

from backend.app.database.vault import calculate_hashes
from backend.app.parsers.mime_normalizer import (
    AttachmentMeta,
    ParsedEmailData,
    compute_simhash,
)

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".xlsm", ".docm",
    ".pptm", ".iso", ".img", ".hta", ".js", ".jar", ".cpl", ".dll"
}


def parse_eml(raw_bytes: bytes, filename: str = "evidence.eml") -> ParsedEmailData:
    """Parse raw RFC 822 email bytes into a normalized ParsedEmailData structure."""
    sha256_hash, md5_hash = calculate_hashes(raw_bytes)
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    # Headers extraction
    subject = msg.get("Subject", "")
    rfc822_msg_id = msg.get("Message-ID", None)
    if rfc822_msg_id:
        rfc822_msg_id = rfc822_msg_id.strip("<> \t\r\n")

    # Date header
    date_header = None
    raw_date = msg.get("Date")
    if raw_date:
        try:
            date_header = parsedate_to_datetime(raw_date)
        except Exception:
            date_header = None

    # Sender parsing
    sender_raw = msg.get("From", "")
    sender_display, sender_email = parseaddr(sender_raw)
    sender_email = sender_email.strip().lower() if sender_email else None
    sender_display = sender_display.strip() if sender_display else None

    # Return-Path & Reply-To
    raw_return_path = msg.get("Return-Path", "")
    _, return_path = parseaddr(raw_return_path)
    return_path = return_path.strip().lower() if return_path else None

    raw_reply_to = msg.get("Reply-To", "")
    _, reply_to = parseaddr(raw_reply_to)
    reply_to = reply_to.strip().lower() if reply_to else None

    # Recipients (To, Cc, Bcc)
    recipient_list = []
    for header in ["To", "Cc", "Bcc", "Delivered-To"]:
        val = msg.get(header)
        if val:
            for part in str(val).split(","):
                _, addr = parseaddr(part)
                if addr and addr.strip().lower() not in recipient_list:
                    recipient_list.append(addr.strip().lower())

    # Received headers (MTA transport route)
    received_headers = msg.get_all("Received", [])
    authentication_results = msg.get("Authentication-Results", None)

    # General headers dictionary
    headers_dict = {}
    for k, v in msg.items():
        headers_dict.setdefault(k, []).append(str(v))

    # Bodies and Attachments extraction
    body_plain_parts = []
    body_html_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            part_filename = part.get_filename()
            if part_filename or "attachment" in content_disposition:
                payload = part.get_payload(decode=True) or b""
                p_sha256 = hashlib.sha256(payload).hexdigest()
                p_md5 = hashlib.md5(payload).hexdigest()
                safe_name = part_filename or f"attachment_{len(attachments) + 1}"
                is_dangerous = any(safe_name.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)

                attachments.append(
                    AttachmentMeta(
                        filename=safe_name,
                        content_type=content_type,
                        size_bytes=len(payload),
                        sha256=p_sha256,
                        md5=p_md5,
                        is_suspicious_extension=is_dangerous,
                    )
                )
            elif content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    text = part.get_content()
                    if isinstance(text, str):
                        body_plain_parts.append(text)
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_plain_parts.append(payload.decode("utf-8", errors="replace"))
            elif content_type == "text/html" and "attachment" not in content_disposition:
                try:
                    html = part.get_content()
                    if isinstance(html, str):
                        body_html_parts.append(html)
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")

        if content_type == "text/html":
            body_html_parts.append(content)
        else:
            body_plain_parts.append(content)

    body_plain = "\n".join(body_plain_parts).strip() if body_plain_parts else None
    body_html = "\n".join(body_html_parts).strip() if body_html_parts else None
    simhash_body = compute_simhash(body_plain or body_html or "")

    return ParsedEmailData(
        file_name=filename,
        file_size_bytes=len(raw_bytes),
        sha256_hash=sha256_hash,
        md5_hash=md5_hash,
        rfc822_msg_id=rfc822_msg_id,
        subject=str(subject),
        date_header=date_header,
        sender_raw=str(sender_raw) if sender_raw else None,
        sender_email=sender_email,
        sender_display=sender_display,
        return_path=return_path,
        reply_to=reply_to,
        recipient_list=recipient_list,
        received_headers=[str(h) for h in received_headers],
        headers_dict=headers_dict,
        authentication_results=str(authentication_results) if authentication_results else None,
        body_plain=body_plain,
        body_html=body_html,
        simhash_body=simhash_body,
        attachments=attachments,
    )

