"""MIME Normalizer and Common Representation for Ingested Emails.

Defines the normalized ParsedEmailData model and locality-sensitive SimHash
fingerprinting algorithm for fuzzy body similarity clustering.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def compute_simhash(text: str) -> str:
    """Compute a 64-bit Locality-Sensitive SimHash fingerprint of text content.

    Allows fuzzy clustering of near-duplicate email templates across phishing campaigns.
    """
    if not text:
        return "0x0000000000000000"

    # Normalize and extract tokens
    tokens = re.findall(r"\b[a-zA-Z0-9]{3,}\b", text.lower())
    if not tokens:
        return "0x0000000000000000"

    v = [0] * 64
    for token in tokens:
        token_hash = int.from_bytes(hashlib.md5(token.encode("utf-8")).digest()[:8], byteorder="big")
        for i in range(64):
            bit = (token_hash >> i) & 1
            v[i] += 1 if bit else -1

    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            fingerprint |= (1 << i)

    return f"0x{fingerprint:016x}"


def compute_hamming_distance(simhash1: str, simhash2: str) -> int:
    """Compute the Hamming distance between two 64-bit SimHash hex strings."""
    try:
        val1 = int(simhash1, 16)
        val2 = int(simhash2, 16)
        xor_val = val1 ^ val2
        return bin(xor_val).count("1")
    except Exception:
        return 64


class AttachmentMeta(BaseModel):
    """Metadata for extracted email attachments."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    md5: str
    is_suspicious_extension: bool = False


class ParsedEmailData(BaseModel):
    """Unified normalized structure representing parsed email contents."""

    file_name: str
    file_size_bytes: int
    sha256_hash: str
    md5_hash: str
    raw_storage_path: str = ""

    # RFC Headers
    rfc822_msg_id: Optional[str] = None
    subject: Optional[str] = None
    date_header: Optional[datetime] = None
    sender_raw: Optional[str] = None
    sender_email: Optional[str] = None
    sender_display: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    recipient_list: List[str] = Field(default_factory=list)

    # Received Header Chain
    received_headers: List[str] = Field(default_factory=list)
    headers_dict: Dict[str, List[str]] = Field(default_factory=dict)
    authentication_results: Optional[str] = None

    # Bodies
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    simhash_body: Optional[str] = None

    # Attachments
    attachments: List[AttachmentMeta] = Field(default_factory=list)

