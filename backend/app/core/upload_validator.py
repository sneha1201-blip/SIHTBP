"""Forensic Upload Validator and Streaming Ingestion Guard.

Enforces stream-level hard byte caps, RFC 822 / MSG magic-byte validation,
binary rejection (HTTP 422), and strict filename sanitization against path traversal and SQLi.
"""

from __future__ import annotations

import os
import re
from typing import Tuple

from fastapi import HTTPException, UploadFile, status

from backend.app.core.config import settings

# Recognized Binary Signatures that MUST be rejected as non-email artifacts
FORBIDDEN_BINARY_MAGIC = {
    b"MZ": "Windows PE Executable / DLL",
    b"\x7fELF": "Linux ELF Executable / Library",
    b"\xca\xfe\xba\xbe": "Java Class / Mach-O Fat Binary",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit Binary",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit Binary",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit Binary (Reverse)",
    b"PK\x03\x04": "ZIP / Jar Archive",
    b"PK\x05\x06": "ZIP Archive (Empty)",
    b"PK\x07\x08": "ZIP Archive (Spanned)",
    b"%PDF": "Adobe Portable Document Format (PDF)",
    b"\x1f\x8b": "GZIP Compressed File",
    b"7z\xbc\xaf\x27\x1c": "7-Zip Compressed Archive",
    b"Rar!\x1a\x07": "RAR Compressed Archive",
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"GIF8": "GIF Image",
}

# Standard OLE Compound Document signature for Outlook (.msg) emails
OLE_MSG_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Standard RFC 822 Header field prefixes (case-insensitive)
COMMON_RFC822_HEADER_PATTERNS = [
    re.compile(rb"^(?:from|to|cc|bcc|date|subject|received|message-id|return-path|delivered-to|mime-version|content-type|x-[\w-]+):", re.IGNORECASE | re.MULTILINE),
]


def sanitize_filename(filename: str) -> str:
    """Sanitize filename against path traversal, null-byte injection, and shell escaping."""
    if not filename:
        return "evidence.eml"

    # Normalize path separators and extract base filename
    cleaned = filename.replace("\\", "/").strip()
    base_name = os.path.basename(cleaned)

    # Strip null bytes and non-printable characters
    base_name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", base_name)

    # Replace forbidden path characters with underscores
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", base_name)

    # Ensure valid extension and prevent leading dot hiding
    safe_name = safe_name.lstrip(".")
    if not safe_name:
        safe_name = "evidence.eml"

    return safe_name


def validate_email_bytes(raw_bytes: bytes, filename: str) -> None:
    """Validate that raw uploaded bytes represent an authentic RFC 822 (.eml) or Outlook (.msg) email.

    Raises:
        HTTPException(422): If content is binary, forbidden executable/archive, or lacks RFC 822 headers.
    """
    if len(raw_bytes) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File content too short to constitute a valid RFC 822 or MSG email artifact.",
        )

    # 1. Check for forbidden binary file signatures (Executables, Archives, Images, PDFs)
    for magic, desc in FORBIDDEN_BINARY_MAGIC.items():
        if raw_bytes.startswith(magic):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Rejected binary upload: Detected '{desc}' signature. Only RFC 822 (.eml) and Outlook (.msg) artifacts are accepted.",
            )

    # 2. Check Outlook (.msg) OLE signature
    if filename.lower().endswith(".msg"):
        if not raw_bytes.startswith(OLE_MSG_MAGIC):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid .msg artifact: Missing required OLE Compound Document signature.",
            )
        return

    # 3. Check RFC 822 (.eml / raw text) headers
    # Inspect the first 8KB for standard RFC 822 header syntax
    header_sample = raw_bytes[:8192]

    # Reject null bytes in plaintext EML header sections (indicative of binary/corrupt data)
    if b"\x00" in header_sample:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Corrupt or non-RFC822 artifact: Found null byte in email header stream.",
        )

    has_rfc822_header = any(pattern.search(header_sample) is not None for pattern in COMMON_RFC822_HEADER_PATTERNS)

    if not has_rfc822_header:
        # Fallback check: look for generic 'Name: Value' header format on initial lines
        try:
            text_sample = header_sample.decode("utf-8", errors="replace")
            lines = [line.strip() for line in text_sample.splitlines() if line.strip()]
            valid_headers = sum(1 for line in lines[:10] if ":" in line and not line.startswith(":"))
            if valid_headers < 1:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Malformed email artifact: No valid RFC 822 header fields (From, Subject, Received, Date) detected.",
                )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Unparseable email artifact: Failed to parse RFC 822 header structure.",
            )


async def stream_and_validate_upload(
    file: UploadFile,
    max_bytes: int | None = None,
) -> Tuple[bytes, str]:
    """Stream file upload chunk-by-chunk enforcing hard size cap before writing to disk/vault.

    Returns:
        Tuple[bytes, str]: (raw_bytes, sanitized_filename)

    Raises:
        HTTPException(413): If accumulated bytes exceed max_bytes.
        HTTPException(422): If content fails email format verification.
    """
    limit = max_bytes if max_bytes is not None else settings.MAX_UPLOAD_SIZE_BYTES
    sanitized_name = sanitize_filename(file.filename or "evidence.eml")

    chunks: list[bytes] = []
    total_read = 0
    chunk_size = 65536  # 64 KB chunks

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > limit:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Upload rejected: Payload exceeds maximum size limit of {limit} bytes ({limit // (1024 * 1024)}MB).",
            )
        chunks.append(chunk)

    raw_bytes = b"".join(chunks)

    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded evidence file is empty (0 bytes).",
        )

    # Validate email authenticity before any vault storage or downstream parsing
    validate_email_bytes(raw_bytes, sanitized_name)

    return raw_bytes, sanitized_name

