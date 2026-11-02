"""Court-Admissible Forensic PDF Dossier Generator.

Complies with Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (formerly Section 65B
of the Indian Evidence Act, 1872) for the admissibility of electronic evidence.
Generates cryptographic hash verification ledgers, MTA routing traces, protocol proofs,
and examiner certification blocks using ReportLab.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """Custom canvas providing running headers, SHA-256 watermarks, and page numbers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []
        self.evidence_sha256 = kwargs.get("evidence_sha256", "UNKNOWN")

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(colors.HexColor("#334155"))

        # Running Header
        header_text = "AICTE CYBER SECURITY CELL | FORENSIC INTELLIGENCE PLATFORM (SIH ID: 26106)"
        self.drawString(54, 11 * inch - 36, header_text)

        # Running Watermark Hash
        self.setFont("Helvetica", 7)
        self.drawRightString(8.5 * inch - 54, 11 * inch - 36, f"EVIDENCE HASH: {self.evidence_sha256[:24]}...")

        # Header dividing rule
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Running Footer
        self.line(54, 46, 8.5 * inch - 54, 46)
        footer_confidential = "CONFIDENTIAL - PREPARED FOR JUDICIAL / LAW ENFORCEMENT PROCEEDINGS UNDER SEC 63 BSA, 2023"
        self.drawString(54, 34, footer_confidential)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 34, page_str)

        self.restoreState()


def generate_forensic_pdf(
    email_data: Dict[str, Any],
    hops: List[Dict[str, Any]],
    analysis: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    audit_logs: List[Dict[str, Any]],
    examiner_name: str = "Principal Cyber Forensic Examiner",
    examiner_designation: str = "AICTE Cyber Security Cell, New Delhi",
) -> io.BytesIO:
    """Generate a court-admissible forensic PDF dossier for an email evidence object."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()
    
    # Custom forensic typography styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#475569"),
        spaceAfter=10,
    )
    section_h2 = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodySmall",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )
    code_style = ParagraphStyle(
        "CodeSmall",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("FORENSIC EXAMINATION DOSSIER & CHAIN OF CUSTODY REPORT", title_style))
    story.append(
        Paragraph(
            "<b>STATUTORY DECLARATION:</b> Electronic Evidence Admissibility Certificate under Section 63 "
            "of the Bharatiya Sakshya Adhiniyam, 2023 (Formerly Section 65B of Indian Evidence Act, 1872)",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # Evidence Overview & Cryptographic Hash Ledger
    story.append(Paragraph("1. EVIDENCE IDENTIFICATION & CRYPTOGRAPHIC LEDGER", section_h2))

    sha256 = email_data.get("sha256_hash", "UNKNOWN")
    md5 = email_data.get("md5_hash", "UNKNOWN")
    verdict = analysis.get("verdict", "UNKNOWN")
    threat_score = analysis.get("threat_score", 0.0)

    verdict_color = "#16a34a" if verdict == "BENIGN" else ("#ca8a04" if verdict == "SUSPICIOUS" else "#dc2626")

    overview_data = [
        [Paragraph("<b>Evidence UUID:</b>", body_style), Paragraph(f"<code>{email_data.get('id', '')}</code>", code_style)],
        [Paragraph("<b>File Name:</b>", body_style), Paragraph(email_data.get("file_name", "evidence.eml"), body_style)],
        [Paragraph("<b>File Size:</b>", body_style), Paragraph(f"{email_data.get('file_size_bytes', 0)} bytes", body_style)],
        [Paragraph("<b>SHA-256 Digest:</b>", body_style), Paragraph(f"<code>{sha256}</code>", code_style)],
        [Paragraph("<b>MD5 Digest:</b>", body_style), Paragraph(f"<code>{md5}</code>", code_style)],
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(email_data.get("subject", "") or "<i>(No Subject)</i>", body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(f"{email_data.get('sender_display', '')} &lt;{email_data.get('sender_email', '')}&gt;", body_style)],
        [Paragraph("<b>Ingestion Timestamp:</b>", body_style), Paragraph(str(email_data.get("ingested_at", "")), body_style)],
        [
            Paragraph("<b>Threat Evaluation:</b>", body_style),
            Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b> (Score: {threat_score}/100)</font>", body_style),
        ],
    ]

    overview_table = Table(overview_data, colWidths=[1.8 * inch, 5.2 * inch])
    overview_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(overview_table)
    story.append(Spacer(1, 10))

    # Protocol Authentication Verification
    story.append(Paragraph("2. PROTOCOL AUTHENTICATION & SENDER VALIDATION", section_h2))
    auth_data = [
        [
            Paragraph("<b>Mechanism</b>", body_style),
            Paragraph("<b>Verified Domain / Selector</b>", body_style),
            Paragraph("<b>Status</b>", body_style),
            Paragraph("<b>RFC 7489 Alignment</b>", body_style),
        ],
        [
            Paragraph("SPF (RFC 7208)", body_style),
            Paragraph(analysis.get("spf_domain", "N/A") or "N/A", body_style),
            Paragraph(f"<b>{analysis.get('spf_status', 'NONE')}</b>", body_style),
            Paragraph("Aligned" if analysis.get("dmarc_alignment_spf") else "Unaligned", body_style),
        ],
        [
            Paragraph("DKIM (RFC 6376)", body_style),
            Paragraph(f"d={analysis.get('dkim_domain', 'N/A')} s={analysis.get('dkim_selector', 'N/A')}", body_style),
            Paragraph(f"<b>{analysis.get('dkim_status', 'NONE')}</b>", body_style),
            Paragraph("Aligned" if analysis.get("dmarc_alignment_dkim") else "Unaligned", body_style),
        ],
        [
            Paragraph("DMARC (RFC 7489)", body_style),
            Paragraph(f"Policy: {analysis.get('dmarc_policy', 'none')}", body_style),
            Paragraph(f"<b>{analysis.get('dmarc_status', 'NONE')}</b>", body_style),
            Paragraph("PASSED" if analysis.get("dmarc_status") == "PASS" else "FAILED", body_style),
        ],
    ]
    auth_table = Table(auth_data, colWidths=[1.8 * inch, 2.4 * inch, 1.4 * inch, 1.4 * inch])
    auth_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(auth_table)
    story.append(Spacer(1, 10))

    # Reverse Hop-Traversal Table
    story.append(Paragraph("3. REVERSE HOP-TRAVERSAL NETWORK ROUTE (ORIGINATING MTA TRACE)", section_h2))
    hop_rows = [
        [
            Paragraph("<b>#</b>", body_style),
            Paragraph("<b>Node Type</b>", body_style),
            Paragraph("<b>Relaying IP</b>", body_style),
            Paragraph("<b>Geolocation</b>", body_style),
            Paragraph("<b>ASN / Operator</b>", body_style),
            Paragraph("<b>Latency</b>", body_style),
        ]
    ]

    for h in hops:
        node_display = h.get("node_type", "RELAY")
        if h.get("is_tor"):
            node_display += " [TOR]"
        geo_str = f"{h.get('geo_city') or ''}, {h.get('geo_country') or ''}".strip(", ") or "Unknown"
        asn_str = f"AS{h.get('asn_number') or 'N/A'} ({h.get('asn_org') or 'N/A'})"[:28]

        hop_rows.append([
            Paragraph(str(h.get("hop_order", "")), body_style),
            Paragraph(node_display, body_style),
            Paragraph(f"<code>{h.get('hop_ip', 'N/A')}</code>", code_style),
            Paragraph(geo_str, body_style),
            Paragraph(asn_str, body_style),
            Paragraph(f"{h.get('delay_seconds', 0.0):.1f}s", body_style),
        ])

    hop_table = Table(hop_rows, colWidths=[0.3 * inch, 1.4 * inch, 1.4 * inch, 1.5 * inch, 1.8 * inch, 0.6 * inch])
    hop_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(hop_table)
    story.append(Spacer(1, 10))

    # Extracted IOCs
    story.append(Paragraph("4. EXTRACTED FORENSIC INDICATORS OF COMPROMISE (DEFANGED)", section_h2))
    ioc_rows = [
        [
            Paragraph("<b>Type</b>", body_style),
            Paragraph("<b>Defanged Value</b>", body_style),
            Paragraph("<b>Context</b>", body_style),
            Paragraph("<b>Reputation</b>", body_style),
        ]
    ]
    for ioc in iocs[:12]:  # Limit to 12 items for clean report layout
        rep = ioc.get("reputation_score")
        rep_str = f"{rep:.0f}/100" if rep is not None else "N/A"
        ioc_rows.append([
            Paragraph(ioc.get("ioc_type", ""), body_style),
            Paragraph(f"<code>{ioc.get('ioc_value', '')[:48]}</code>", code_style),
            Paragraph(ioc.get("context", ""), body_style),
            Paragraph(rep_str, body_style),
        ])

    if len(ioc_rows) == 1:
        ioc_rows.append([Paragraph("No external indicators extracted", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])

    ioc_table = Table(ioc_rows, colWidths=[1.1 * inch, 3.7 * inch, 1.4 * inch, 0.8 * inch])
    ioc_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ])
    )
    story.append(ioc_table)
    story.append(Spacer(1, 12))

    # Statutory Certification & Sign-off Block (Section 63 BSA 2023)
    cert_text = (
        "<b>CERTIFICATE UNDER SECTION 63, BHARATIYA SAKSHYA ADHINIYAM, 2023:</b><br/>"
        "I hereby certify that the electronic record described herein was ingested, parsed, and verified "
        "by the automated forensic pipeline operating within standard parameters under my lawful control. "
        "The cryptographic SHA-256 and MD5 digests were generated at the instant of ingestion and sealed within "
        "an immutable evidence vault. No unauthorized alteration or data degradation occurred during transit or analysis."
    )
    cert_p = Paragraph(cert_text, ParagraphStyle("CertStyle", parent=body_style, fontSize=7.5, leading=10, textColor=colors.HexColor("#1e293b")))

    sign_data = [
        [cert_p],
        [
            Table(
                [
                    [Paragraph(f"<b>Examiner Name:</b> {examiner_name}", body_style), Paragraph("<b>Signature:</b> ___________________________", body_style)],
                    [Paragraph(f"<b>Designation:</b> {examiner_designation}", body_style), Paragraph(f"<b>Date:</b> {datetime.now(timezone.utc).strftime('%d-%b-%Y %H:%M:%S UTC')}", body_style)],
                    [Paragraph("<b>Institutional Authority:</b> AICTE Cyber Security Cell", body_style), Paragraph("<b>Official Stamp / Seal:</b> [SEAL AFFIXED]", body_style)],
                ],
                colWidths=[3.5 * inch, 3.5 * inch],
            )
        ],
    ]
    cert_table = Table(sign_data, colWidths=[7.0 * inch])
    cert_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#64748b")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )

    story.append(KeepTogether(cert_table))

    # Build document with custom canvas
    doc.build(story, canvasmaker=lambda *args, **kwargs: NumberedCanvas(*args, evidence_sha256=sha256, **kwargs))
    buffer.seek(0)
    return buffer
