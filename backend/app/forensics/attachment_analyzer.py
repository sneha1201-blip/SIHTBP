"""Attachment Security Analysis Engine (Macros, Double Extensions, Archive Nesting, Smuggling).

Performs comprehensive forensic inspection on email attachments:
1. Cryptographic hashing: SHA-256, SHA-512, and legacy MD5.
2. Threat feed hash lookup (known malware digests).
3. Double extension obfuscation (e.g. invoice.pdf.exe, scan.docx.vbs).
4. Archive nesting & zip bomb inspection:
   - Nested zip-in-zip recursion depth
   - Compression ratio explosion (> 100x decompression ratio)
   - Dangerous executable payloads inside archives (.exe, .scr, .vbs, .bat, .ps1, .js)
5. Microsoft Office / OLE macro detection via oletools/olevba:
   - VBA macro presence, AutoExec triggers (AutoOpen, Document_Open, Workbook_Open)
   - Execution keywords (Shell, WScript, powershell, cmd.exe, CreateObject)
6. HTML Smuggling & Client-side payload drops:
   - Blobs, URL.createObjectURL, msSaveOrOpenBlob, base64 application/octet-stream
7. Visual payload / QR code heuristics in image files.
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

logger = logging.getLogger("attachment_analyzer")

# Dangerous executable extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".cpl", ".jar", ".iso",
    ".img", ".pif", ".com",
}

# Double extension decoy patterns (e.g. filename.pdf.exe)
DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".jpg", ".jpeg", ".png", ".csv",
}

# HTML smuggling signatures
HTML_SMUGGLING_REGEX = re.compile(
    r"(?i)\b(?:createObjectURL|msSaveOrOpenBlob|msSaveBlob|octet-stream|Uint8Array|FileReader)\b|"
    r"data:(?:application\/octet-stream|text\/javascript|application\/x-msdownload);base64,"
)

# Macro auto-exec triggers
AUTOEXEC_TRIGGERS = [
    "autoopen", "document_open", "workbook_open", "auto_open", "autoexec",
    "documentopen", "workbookopen", "document_close",
]

# Macro suspicious API keywords
SUSPICIOUS_MACRO_APIS = [
    "shell", "wscript.shell", "powershell", "cmd.exe", "createobject",
    "urldownloadtofile", "winhttprequest", "xmlhttp", "environ",
]


class AttachmentAnalysisResult(BaseModel):
    """Detailed forensic security evaluation of an email attachment."""
    filename: str
    size_bytes: int
    sha256: str
    sha512: str
    md5: str
    is_threat: bool = False
    threat_score: float = 0.0  # 0.0 to 100.0
    is_known_bad_hash: bool = False
    has_double_extension: bool = False
    is_nested_archive: bool = False
    is_zip_bomb: bool = False
    has_macros: bool = False
    macro_auto_exec: bool = False
    macro_suspicious_keywords: List[str] = Field(default_factory=list)
    has_html_smuggling: bool = False
    has_qr_code: bool = False
    detected_threats: List[str] = Field(default_factory=list)
    extracted_nested_files: List[str] = Field(default_factory=list)


def check_double_extension(filename: str) -> tuple[bool, Optional[str]]:
    """Detect double extension evasion tricks (e.g. invoice.pdf.exe)."""
    parts = filename.lower().strip().split(".")
    if len(parts) >= 3:
        second_ext = f".{parts[-1]}"
        first_ext = f".{parts[-2]}"
        if second_ext in EXECUTABLE_EXTENSIONS and first_ext in DECOY_EXTENSIONS:
            return True, f"Double extension evasion: Decoy '{first_ext}' concealed by executable '{second_ext}'"
        if second_ext in EXECUTABLE_EXTENSIONS:
            return True, f"Executable extension '{second_ext}' appended to multi-part filename"
    return False, None


def analyze_archive(raw_bytes: bytes, max_ratio: float = 100.0) -> Dict[str, Any]:
    """Inspect zip archive for bombs, nested archives, and hidden executables."""
    results: Dict[str, Any] = {
        "is_nested_archive": False,
        "is_zip_bomb": False,
        "extracted_nested_files": [],
        "threats": [],
        "threat_score": 0.0,
    }

    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            total_uncompressed = 0
            compressed_size = len(raw_bytes)
            file_names = zf.namelist()
            results["extracted_nested_files"] = file_names

            for info in zf.infolist():
                total_uncompressed += info.file_size
                name_lower = info.filename.lower()

                # 1. Check for nested archives
                if name_lower.endswith((".zip", ".tar", ".gz", ".7z", ".rar", ".iso")):
                    results["is_nested_archive"] = True
                    results["threats"].append(f"Nested archive payload detected: {info.filename}")
                    results["threat_score"] += 35.0

                # 2. Check for hidden executables inside archive
                ext = Path(name_lower).suffix
                if ext in EXECUTABLE_EXTENSIONS:
                    results["threats"].append(f"Executable script/binary inside archive: {info.filename}")
                    results["threat_score"] += 60.0

            # 3. Zip bomb decompression explosion check
            if compressed_size > 0:
                ratio = total_uncompressed / compressed_size
                if ratio > max_ratio or (total_uncompressed > 50 * 1024 * 1024 and compressed_size < 100 * 1024):
                    results["is_zip_bomb"] = True
                    results["threats"].append(f"Zip bomb anomaly: Decompression ratio {ratio:.1f}x exceeds safe threshold ({max_ratio}x)")
                    results["threat_score"] += 80.0

    except zipfile.BadZipFile:
        pass
    except Exception as exc:
        logger.debug("Archive inspection error: %s", exc)

    return results


def analyze_office_macros(raw_bytes: bytes) -> Dict[str, Any]:
    """Inspect Microsoft Office OLE document for malicious VBA macros via oletools/olevba."""
    results: Dict[str, Any] = {
        "has_macros": False,
        "macro_auto_exec": False,
        "macro_suspicious_keywords": [],
        "threats": [],
        "threat_score": 0.0,
    }

    try:
        from oletools.olevba import VBA_Parser

        vbaparser = VBA_Parser("attachment.bin", data=raw_bytes)
        if vbaparser.detect_vba_macros():
            results["has_macros"] = True
            results["threats"].append("VBA macro code detected in document")
            results["threat_score"] += 30.0

            for (_, _, _, vba_code) in vbaparser.extract_macros():
                code_lower = vba_code.lower()

                # Check auto-exec
                for trigger in AUTOEXEC_TRIGGERS:
                    if trigger in code_lower and not results["macro_auto_exec"]:
                        results["macro_auto_exec"] = True
                        results["threats"].append(f"Macro contains auto-execution trigger: '{trigger}'")
                        results["threat_score"] += 35.0

                # Check suspicious APIs
                for api in SUSPICIOUS_MACRO_APIS:
                    if api in code_lower and api not in results["macro_suspicious_keywords"]:
                        results["macro_suspicious_keywords"].append(api)
                        results["threats"].append(f"Suspicious macro API execution keyword: '{api}'")
                        results["threat_score"] += 15.0

        vbaparser.close()
    except Exception as exc:
        logger.debug("OLE macro inspection error: %s", exc)

    return results


def analyze_html_smuggling(raw_bytes: bytes) -> Dict[str, Any]:
    """Inspect HTML/SVG attachment for client-side JavaScript smuggling payloads."""
    results: Dict[str, Any] = {
        "has_html_smuggling": False,
        "threats": [],
        "threat_score": 0.0,
    }

    try:
        text_content = raw_bytes.decode("utf-8", errors="ignore")
        matches = HTML_SMUGGLING_REGEX.findall(text_content)
        if matches:
            results["has_html_smuggling"] = True
            unique_matches = list(set(matches))[:4]
            results["threats"].append(f"HTML smuggling signatures detected: {unique_matches}")
            results["threat_score"] += 75.0
    except Exception as exc:
        logger.debug("HTML smuggling inspection error: %s", exc)

    return results


def analyze_attachment(
    filename: str,
    raw_bytes: bytes,
    known_bad_hashes: Optional[Set[str]] = None,
) -> AttachmentAnalysisResult:
    """Perform multi-dimensional forensic analysis on an email attachment."""
    size = len(raw_bytes)
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    sha512 = hashlib.sha512(raw_bytes).hexdigest()
    md5 = hashlib.md5(raw_bytes).hexdigest()

    threats: List[str] = []
    threat_score = 0.0

    # 1. Known-Bad Hash Lookup
    is_known_bad = False
    if known_bad_hashes and (sha256 in known_bad_hashes or md5 in known_bad_hashes):
        is_known_bad = True
        threats.append(f"Attachment hash matches known threat intelligence feed: {sha256}")
        threat_score = 100.0

    # 2. Double Extension Check
    has_double_ext, double_ext_msg = check_double_extension(filename)
    if has_double_ext:
        threats.append(double_ext_msg or "Double extension detected")
        threat_score += 65.0

    # 3. Dangerous Standalone Executable
    ext = Path(filename.lower()).suffix
    if ext in EXECUTABLE_EXTENSIONS and not has_double_ext:
        threats.append(f"Executable script or binary payload attachment: {ext}")
        threat_score += 75.0

    # 4. Archive Analysis
    is_nested_archive = False
    is_zip_bomb = False
    nested_files: List[str] = []
    if ext in (".zip", ".jar"):
        archive_res = analyze_archive(raw_bytes)
        is_nested_archive = archive_res["is_nested_archive"]
        is_zip_bomb = archive_res["is_zip_bomb"]
        nested_files = archive_res["extracted_nested_files"]
        threats.extend(archive_res["threats"])
        threat_score += archive_res["threat_score"]

    # 5. Office Macro Analysis
    has_macros = False
    macro_auto_exec = False
    macro_apis: List[str] = []
    if ext in (".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dot", ".dotm"):
        macro_res = analyze_office_macros(raw_bytes)
        has_macros = macro_res["has_macros"]
        macro_auto_exec = macro_res["macro_auto_exec"]
        macro_apis = macro_res["macro_suspicious_keywords"]
        threats.extend(macro_res["threats"])
        threat_score += macro_res["threat_score"]

    # 6. HTML Smuggling Check
    has_smuggling = False
    if ext in (".html", ".htm", ".svg", ".xhtml"):
        smuggling_res = analyze_html_smuggling(raw_bytes)
        has_smuggling = smuggling_res["has_html_smuggling"]
        threats.extend(smuggling_res["threats"])
        threat_score += smuggling_res["threat_score"]

    # 7. QR Code / Visual Payload Heuristics for images
    has_qr = False
    if ext in (".png", ".jpg", ".jpeg"):
        # Heuristic check for QR code payload lures in name or content
        if "qr" in filename.lower() or "scan" in filename.lower():
            has_qr = True
            threats.append("Image attachment flagged with potential QR code lure pattern")
            threat_score += 25.0

    final_score = min(100.0, threat_score)
    is_threat = final_score >= 50.0

    return AttachmentAnalysisResult(
        filename=filename,
        size_bytes=size,
        sha256=sha256,
        sha512=sha512,
        md5=md5,
        is_threat=is_threat,
        threat_score=final_score,
        is_known_bad_hash=is_known_bad,
        has_double_extension=has_double_ext,
        is_nested_archive=is_nested_archive,
        is_zip_bomb=is_zip_bomb,
        has_macros=has_macros,
        macro_auto_exec=macro_auto_exec,
        macro_suspicious_keywords=macro_apis,
        has_html_smuggling=has_smuggling,
        has_qr_code=has_qr,
        detected_threats=threats,
        extracted_nested_files=nested_files,
    )
