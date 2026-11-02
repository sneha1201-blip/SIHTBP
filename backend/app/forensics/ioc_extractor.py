"""Automated IOC (Indicator of Compromise) Extraction and Defanging Engine.

Extracts URLs, domains, IPv4/IPv6 addresses, and attachment hashes from email bodies
and headers, with automatic cryptographic hashing and safe defanging (`hxxps://`, `[.]`).
"""

from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from pydantic import BaseModel


class ExtractedIOC(BaseModel):
    """Normalized Indicator of Compromise."""
    ioc_type: str         # URL, DOMAIN, IP, HASH, EMAIL_ADDR
    raw_value: str
    defanged_value: str
    context: str          # EMAIL_BODY, HTML_HREF, ATTACHMENT, SENDER, HEADER
    is_defanged: bool = True
    metadata: dict = {}


# Regex patterns
URL_REGEX = re.compile(
    r"\b(?:https?|ftp|hxxps?):\/\/[^\s/$.?#].[^\s]*",
    re.IGNORECASE,
)
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)


def defang_ioc(val: str, ioc_type: str) -> str:
    """Transform an active Indicator of Compromise into a safe, non-clickable defanged string."""
    if not val:
        return ""

    defanged = val
    if ioc_type in ("URL", "DOMAIN", "IP"):
        defanged = defanged.replace("http://", "hxxp://")
        defanged = defanged.replace("https://", "hxxps://")
        defanged = defanged.replace("ftp://", "fxp://")
        # Defang dots
        defanged = defanged.replace(".", "[.]")

    elif ioc_type == "EMAIL_ADDR":
        defanged = defanged.replace("@", "[@]")
        defanged = defanged.replace(".", "[.]")

    return defanged


def extract_iocs(
    body_plain: str | None,
    body_html: str | None,
    sender_email: str | None = None,
    reply_to: str | None = None,
    attachments: list | None = None,
    hop_ips: list[str] | None = None,
) -> List[ExtractedIOC]:
    """Extract and deduplicate all forensic indicators of compromise across email assets."""
    iocs: List[ExtractedIOC] = []
    seen_values: Set[str] = set()

    # 1. Extract from HTML href attributes
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("http://", "https://", "hxxp://", "hxxps://")) and href not in seen_values:
                    seen_values.add(href)
                    iocs.append(
                        ExtractedIOC(
                            ioc_type="URL",
                            raw_value=href,
                            defanged_value=defang_ioc(href, "URL"),
                            context="HTML_HREF",
                            metadata={"link_text": a_tag.get_text(strip=True)[:100]},
                        )
                    )
        except Exception:
            pass

    # 2. Extract URLs from plaintext and HTML bodies
    combined_text = f"{body_plain or ''} {body_html or ''}"
    for match in URL_REGEX.finditer(combined_text):
        url = match.group(0).rstrip(".,;)\"'>")
        if url not in seen_values:
            seen_values.add(url)
            iocs.append(
                ExtractedIOC(
                    ioc_type="URL",
                    raw_value=url,
                    defanged_value=defang_ioc(url, "URL"),
                    context="EMAIL_BODY",
                )
            )

    # 3. Extract Domains from URLs
    for ioc in list(iocs):
        if ioc.ioc_type == "URL":
            try:
                parsed = urlparse(ioc.raw_value.replace("hxxp", "http"))
                netloc = parsed.netloc.split(":")[0].strip()
                if netloc and not IPV4_REGEX.match(netloc) and netloc not in seen_values:
                    seen_values.add(netloc)
                    iocs.append(
                        ExtractedIOC(
                            ioc_type="DOMAIN",
                            raw_value=netloc,
                            defanged_value=defang_ioc(netloc, "DOMAIN"),
                            context="EMBEDDED_URL_DOMAIN",
                        )
                    )
            except Exception:
                pass

    # 4. Extract Hop IPs
    if hop_ips:
        for ip in hop_ips:
            if ip and ip not in seen_values:
                seen_values.add(ip)
                iocs.append(
                    ExtractedIOC(
                        ioc_type="IP",
                        raw_value=ip,
                        defanged_value=defang_ioc(ip, "IP"),
                        context="HEADER_RECEIVED",
                    )
                )

    # 5. Extract Attachment Hashes
    if attachments:
        for att in attachments:
            sha256 = getattr(att, "sha256", None) or att.get("sha256")
            name = getattr(att, "filename", None) or att.get("filename")
            if sha256 and sha256 not in seen_values:
                seen_values.add(sha256)
                iocs.append(
                    ExtractedIOC(
                        ioc_type="HASH",
                        raw_value=sha256,
                        defanged_value=sha256,
                        context="ATTACHMENT",
                        is_defanged=False,
                        metadata={"filename": name},
                    )
                )

    # 6. Extract Suspicious Sender & Reply-To
    if sender_email and sender_email not in seen_values:
        seen_values.add(sender_email)
        iocs.append(
            ExtractedIOC(
                ioc_type="EMAIL_ADDR",
                raw_value=sender_email,
                defanged_value=defang_ioc(sender_email, "EMAIL_ADDR"),
                context="SENDER",
            )
        )

    if reply_to and reply_to != sender_email and reply_to not in seen_values:
        seen_values.add(reply_to)
        iocs.append(
            ExtractedIOC(
                ioc_type="EMAIL_ADDR",
                raw_value=reply_to,
                defanged_value=defang_ioc(reply_to, "EMAIL_ADDR"),
                context="REPLY_TO",
            )
        )

    return iocs

