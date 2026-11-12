"""RFC 822 / MIME (.eml) Email Parser.

Extracts structured headers, received chains, plain and HTML bodies,
and attachments with full cryptographic checksumming.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import logging
from email.utils import parseaddr, parsedate_to_datetime

from backend.app.database.vault import calculate_hashes
from backend.app.parsers.mime_normalizer import (
    AttachmentMeta,
    ParsedEmailData,
    compute_simhash,
)

logger = logging.getLogger("eml_parser")

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
        except (ValueError, TypeError) as exc:
            logger.debug("Failed parsing Date header '%s': %s", raw_date, exc)
            date_header = None

    # Sender parsing
    sender_raw = msg.get("From", "")
    raw_display, raw_email = parseaddr(sender_raw)
    sender_email: str | None = raw_email.strip().lower() if raw_email else None
    sender_display: str | None = raw_display.strip() if raw_display else None

    # Return-Path & Reply-To
    raw_return_path = msg.get("Return-Path", "")
    _, raw_rp = parseaddr(raw_return_path)
    return_path: str | None = raw_rp.strip().lower() if raw_rp else None

    raw_reply_to = msg.get("Reply-To", "")
    _, raw_rt = parseaddr(raw_reply_to)
    reply_to: str | None = raw_rt.strip().lower() if raw_rt else None

    # Recipients (To, Cc, Bcc)
    recipient_list: list[str] = []
    for header in ["To", "Cc", "Bcc", "Delivered-To"]:
        val = msg.get(header)
        if val:
            for item in str(val).split(","):
                _, addr = parseaddr(item)
                if addr and addr.strip().lower() not in recipient_list:
                    recipient_list.append(addr.strip().lower())

    # Received headers (MTA transport route)
    received_headers = msg.get_all("Received", [])
    authentication_results = msg.get("Authentication-Results", None)

    # General headers dictionary
    headers_dict: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers_dict.setdefault(k, []).append(str(v))

    # Bodies and Attachments extraction
    body_plain_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[AttachmentMeta] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            part_filename = part.get_filename()
            if part_filename or "attachment" in content_disposition:
                payload_raw = part.get_payload(decode=True)
                payload = payload_raw if isinstance(payload_raw, bytes) else b""
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
                    payload_raw = part.get_payload(decode=True)
                    payload = payload_raw if isinstance(payload_raw, bytes) else b""
                    body_plain_parts.append(payload.decode("utf-8", errors="replace"))
            elif content_type == "text/html" and "attachment" not in content_disposition:
                try:
                    html = part.get_content()
                    if isinstance(html, str):
                        body_html_parts.append(html)
                except Exception:
                    payload_raw = part.get_payload(decode=True)
                    payload = payload_raw if isinstance(payload_raw, bytes) else b""
                    body_html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        content_type = msg.get_content_type()
        try:
            content_obj = msg.get_content()
            if isinstance(content_obj, bytes):
                content = content_obj.decode("utf-8", errors="replace")
            else:
                content = str(content_obj)
        except Exception:
            payload_raw = msg.get_payload(decode=True)
            payload = payload_raw if isinstance(payload_raw, bytes) else b""
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

