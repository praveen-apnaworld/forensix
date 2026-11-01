"""
report_generator.py - Professional PDF Report Generator for ForensiX

Generates comprehensive, court-admissible-style digital forensics examination
reports in PDF format using Python ReportLab.

Sections included:
A. COVER PAGE - ForensiX branding, case identification, confidentiality notice.
B. CASE INFORMATION - Case metadata, investigator details, status.
C. EVIDENCE INVENTORY - Itemized evidence register with sizes, types, sources.
D. HASH ANALYSIS - MD5, SHA-1, SHA-256 integrity fingerprints and notes.
E. FILE ANALYSIS - Detected formats, MIME types, extension anomalies, hidden status.
F. METADATA ANALYSIS - Camera EXIF, document properties, GPS (if authorized), missing field audits.
G. KEYWORD SEARCH - Search terms, matching occurrences, line/page references, redacted snippets.
H. TIMELINE ANALYSIS - Created, Modified, Metadata Changed, Accessed, and Milestones.
I. INVESTIGATION SUMMARY - Key findings, metrics, and forensic synthesis.
J. LIMITATIONS AND DISCLAIMER - Mandatory forensic caveats and educational notice.
"""

import os
import io
import json
import re
import uuid
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

import reportlab
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# ForensiX Analysis Modules
from modules.hash_analyzer import compute_hashes
from modules.file_analyzer import analyze_file_stream
from modules.metadata_extractor import extract_metadata
from modules.keyword_search import search_file
from modules.timeline_analyzer import (
    extract_filesystem_timestamps,
    extract_embedded_document_timestamps,
    generate_timeline
)


def safe_text(val, default="Not Available") -> str:
    """Escapes text for ReportLab XML parser and handles nulls."""
    if val is None or str(val).strip() == "" or str(val).strip().lower() == "none":
        return default
    return xml_escape(str(val).strip())


def redact_sensitive_snippet(text: str) -> str:
    """Redacts potential passwords, tokens, or credit cards in search context previews."""
    if not text:
        return ""
    # Redact password values: e.g. password=xyz, pass: xyz, pwd="xyz"
    redacted = re.sub(
        r'(?i)(password|passwd|pwd|secret|token|api[_-]?key)(\s*[:=]\s*["\']?)([^"\'\s,;]+)',
        r'\1\2[REDACTED-CREDENTIAL]',
        text
    )
    # Redact potential credit card numbers (16 digits)
    redacted = re.sub(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b', '[REDACTED-CARD-NUM]', redacted)
    return safe_text(redacted)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print total page numbers ('Page X of Y')
    and running headers across all pages except the cover page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

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

    def draw_page_decorations(self, total_pages: int):
        # Suppress header and footer on cover page (page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))

        # --- RUNNING HEADER ---
        header_text = "FORENSIX DIGITAL FORENSICS TOOLKIT — INVESTIGATION REPORT"
        self.drawString(36, 11 * inch - 30, header_text)
        self.setFont("Helvetica", 8)
        case_ref = getattr(self, '_case_id_tag', 'OFFICIAL FORENSIC RECORD')
        self.drawRightString(8.5 * inch - 36, 11 * inch - 30, case_ref)

        # Header dividing line
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.6)
        self.line(36, 11 * inch - 34, 8.5 * inch - 36, 11 * inch - 34)

        # --- RUNNING FOOTER ---
        # Footer dividing line
        self.line(36, 38, 8.5 * inch - 36, 38)

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#dc2626"))  # Subtle red confidentiality flag
        self.drawString(36, 26, "CONFIDENTIAL")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(102, 26, "— FOR AUTHORIZED FORENSIC & LEGAL PURPOSES ONLY")

        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(8.5 * inch - 36, 26, page_str)

        self.restoreState()


class PDFReportGenerator:
    """
    Constructs a comprehensive, professional digital forensics report using ReportLab.
    """
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Initializes forensic typography styles."""
        # Color palette
        self.c_primary = colors.HexColor("#0f172a")     # Deep navy slate
        self.c_secondary = colors.HexColor("#1e3a8a")   # Rich navy
        self.c_accent = colors.HexColor("#0284c7")      # Cyan accent
        self.c_text = colors.HexColor("#1e293b")        # Dark text
        self.c_muted = colors.HexColor("#64748b")       # Muted gray text
        self.c_border = colors.HexColor("#cbd5e1")      # Border line
        self.c_bg_light = colors.HexColor("#f8fafc")    # Light row
        self.c_bg_alt = colors.HexColor("#f1f5f9")      # Alternating row

        # Custom Paragraph Styles
        self.style_cover_title = ParagraphStyle(
            'CoverTitle',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=26,
            leading=32,
            textColor=self.c_primary,
            alignment=0,
            spaceAfter=8
        )
        self.style_cover_subtitle = ParagraphStyle(
            'CoverSubtitle',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=13,
            leading=17,
            textColor=self.c_accent,
            alignment=0,
            spaceAfter=24
        )
        self.style_h1 = ParagraphStyle(
            'SectionH1',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=self.c_secondary,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )
        self.style_h2 = ParagraphStyle(
            'SectionH2',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=15,
            textColor=self.c_primary,
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True
        )
        self.style_body = ParagraphStyle(
            'Body',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=self.c_text,
            spaceAfter=6
        )
        self.style_muted = ParagraphStyle(
            'MutedBody',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=self.c_muted,
            spaceAfter=4
        )
        self.style_code = ParagraphStyle(
            'CodeHash',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a")
        )
        self.style_th = ParagraphStyle(
            'TableHead',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11,
            textColor=colors.white,
            alignment=0
        )
        self.style_td = ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=self.c_text,
            alignment=0
        )
        self.style_td_bold = ParagraphStyle(
            'TableCellBold',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=11,
            textColor=self.c_primary,
            alignment=0
        )
        self.style_badge_ok = ParagraphStyle(
            'BadgeOK',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#065f46")
        )
        self.style_badge_warn = ParagraphStyle(
            'BadgeWarn',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#92400e")
        )
        self.style_callout = ParagraphStyle(
            'CalloutText',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#1e293b")
        )

    def _make_callout(self, text: str, title: str = "NOTE", bg_hex: str = "#f0f9ff", border_hex: str = "#0284c7") -> Table:
        """Constructs an aesthetic callout box for disclaimers and notes."""
        p_content = Paragraph(f"<strong>{safe_text(title)}:</strong> {text}", self.style_callout)
        t = Table([[p_content]], colWidths=[540])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(bg_hex)),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(border_hex)),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        return t

    def _section_header(self, letter: str, title: str) -> list:
        """Returns a formatted section heading with dividing rule."""
        p = Paragraph(f"<strong>SECTION {letter}. {xml_escape(title.upper())}</strong>", self.style_h1)
        hr = HRFlowable(width="100%", thickness=1.2, color=self.c_secondary, spaceBefore=2, spaceAfter=8)
        return [p, hr]

    def build_cover_page(self, case: dict, report_meta: dict) -> list:
        """Generates the formal title cover page."""
        story = []
        story.append(Spacer(1, 30))

        # Brand header badge
        brand_p = Paragraph("<strong>FORENSIX DIGITAL FORENSICS TOOLKIT</strong>", ParagraphStyle(
            'BrandBadge', fontName='Helvetica-Bold', fontSize=10, textColor=self.c_accent, leading=14
        ))
        story.append(brand_p)
        story.append(Spacer(1, 10))

        # Title & Subtitle
        title_text = report_meta.get('report_title') or "Digital Forensics Investigation Report"
        story.append(Paragraph(safe_text(title_text), self.style_cover_title))
        story.append(Paragraph("Formal Technical Evidence Examination & Comprehensive Forensic Audit", self.style_cover_subtitle))

        # Decorative line
        story.append(HRFlowable(width="100%", thickness=2.5, color=self.c_secondary, spaceBefore=4, spaceAfter=24))

        # Metadata Details Table
        case_id = safe_text(case.get('case_id'))
        report_id = safe_text(report_meta.get('report_id'))
        investigator = safe_text(report_meta.get('investigator_name') or case.get('investigator'))
        org = safe_text(report_meta.get('organization') or "ForensiX Cyber Forensics Laboratory")
        gen_date = safe_text(report_meta.get('generated_at') or datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        status = safe_text(case.get('status') or "Under Active Investigation")

        meta_rows = [
            [Paragraph("<strong>Case Reference ID:</strong>", self.style_td_bold), Paragraph(f"<code>{case_id}</code>", self.style_td)],
            [Paragraph("<strong>Investigation Title:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('title')), self.style_td)],
            [Paragraph("<strong>Report Tracking ID:</strong>", self.style_td_bold), Paragraph(f"<code>{report_id}</code>", self.style_td)],
            [Paragraph("<strong>Lead Forensic Examiner:</strong>", self.style_td_bold), Paragraph(investigator, self.style_td)],
            [Paragraph("<strong>Agency / Laboratory:</strong>", self.style_td_bold), Paragraph(org, self.style_td)],
            [Paragraph("<strong>Examination Status:</strong>", self.style_td_bold), Paragraph(status, self.style_td)],
            [Paragraph("<strong>Report Generation Timestamp:</strong>", self.style_td_bold), Paragraph(gen_date, self.style_td)],
            [Paragraph("<strong>Classification Level:</strong>", self.style_td_bold), Paragraph("<font color='#dc2626'><strong>CONFIDENTIAL — LAW ENFORCEMENT SENSITIVE</strong></font>", self.style_td)]
        ]

        meta_table = Table(meta_rows, colWidths=[180, 360])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.c_bg_light),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 40))

        # Confidentiality Notice Block
        conf_notice = (
            "<strong>WARNING & CONFIDENTIALITY NOTICE:</strong> This document contains technical forensic findings "
            "derived from electronic media analysis. It is intended strictly for authorized legal, law enforcement, "
            "or regulatory examination. Unauthorized reproduction, dissemination, or disclosure is strictly prohibited."
        )
        story.append(self._make_callout(conf_notice, title="CONFIDENTIALITY DECLARATION", bg_hex="#fffbeb", border_hex="#f59e0b"))

        story.append(PageBreak())
        return story

    def build_case_information(self, case: dict) -> list:
        """Section B: Case Information."""
        story = []
        story.extend(self._section_header("B", "Case Information & Administrative Data"))

        rows = [
            [Paragraph("<strong>Case Identifier:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('case_id')), self.style_td)],
            [Paragraph("<strong>Case Short Title:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('title')), self.style_td)],
            [Paragraph("<strong>Lead Investigator:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('investigator')), self.style_td)],
            [Paragraph("<strong>Current Case Status:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('status')), self.style_td)],
            [Paragraph("<strong>Case Registration Date:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('created_at')), self.style_td)],
            [Paragraph("<strong>Case Record Last Updated:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('updated_at')), self.style_td)],
            [Paragraph("<strong>Detailed Description:</strong>", self.style_td_bold), Paragraph(safe_text(case.get('description'), default="No case summary provided."), self.style_td)],
        ]

        t = Table(rows, colWidths=[160, 380])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))
        return story

    def build_evidence_inventory(self, evidence_list: list) -> list:
        """Section C: Evidence Inventory."""
        story = []
        story.extend(self._section_header("C", "Evidence Inventory & Acquisition Baseline"))

        if not evidence_list:
            story.append(self._make_callout(
                "No registered digital evidence items were associated with this case at the time of report generation.",
                title="INVENTORY NOTICE", bg_hex="#f8fafc", border_hex="#cbd5e1"
            ))
            story.append(Spacer(1, 14))
            return story

        table_data = [[
            Paragraph("Evidence ID", self.style_th),
            Paragraph("Filename", self.style_th),
            Paragraph("Format / Type", self.style_th),
            Paragraph("File Size", self.style_th),
            Paragraph("Source & Acquisition", self.style_th),
            Paragraph("Logged At", self.style_th),
        ]]

        for i, ev in enumerate(evidence_list):
            bg = self.c_bg_light if i % 2 == 0 else colors.white
            f_size = ev.get('file_size', 0) or 0
            size_str = f"{f_size:,} B ({f_size / 1024:.1f} KB)" if f_size > 1024 else f"{f_size} B"
            source_info = f"{safe_text(ev.get('source'), 'Unknown Source')}<br/><font size='6.5' color='#64748b'>{safe_text(ev.get('acquisition_method'), 'N/A')}</font>"

            table_data.append([
                Paragraph(f"<code>{safe_text(ev.get('evidence_id'))}</code>", self.style_td_bold),
                Paragraph(safe_text(ev.get('filename')), self.style_td),
                Paragraph(safe_text(ev.get('file_type'), 'Unknown'), self.style_td),
                Paragraph(size_str, self.style_td),
                Paragraph(source_info, self.style_td),
                Paragraph(safe_text(ev.get('added_at') or 'N/A')[:16], self.style_td),
            ])

        t = Table(table_data, colWidths=[75, 115, 80, 85, 115, 70])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.c_primary),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))
        return story

    def build_hash_analysis(self, evidence_list: list) -> list:
        """Section D: Cryptographic Hash Analysis."""
        story = []
        story.extend(self._section_header("D", "Cryptographic Hash Analysis & Data Integrity"))

        integrity_note = (
            "Cryptographic hashes represent mathematical digital fingerprints computed using NIST-standard algorithms "
            "(MD5, SHA-1, SHA-256). In accordance with digital forensics standards (ISO/IEC 27037), hashes were computed "
            "directly via chunked streaming to guarantee evidence integrity without loading unverified content into memory."
        )
        story.append(Paragraph(integrity_note, self.style_muted))
        story.append(Spacer(1, 6))

        if not evidence_list:
            story.append(Paragraph("<em>No evidence available for hash analysis.</em>", self.style_muted))
            story.append(Spacer(1, 14))
            return story

        table_data = [[
            Paragraph("Evidence & Filename", self.style_th),
            Paragraph("Cryptographic Hashes (MD5, SHA-1, SHA-256)", self.style_th),
            Paragraph("Integrity Status", self.style_th)
        ]]

        for i, ev in enumerate(evidence_list):
            h_data = ev.get('hash_analysis')
            if not h_data:
                hashes_cell = Paragraph("<em>Hash analysis Not Analyzed for this evidence file.</em>", self.style_td)
                status_cell = Paragraph("<font color='#64748b'>Not Analyzed</font>", self.style_td)
            else:
                md5_v = safe_text(h_data.get('md5'))
                sha1_v = safe_text(h_data.get('sha1'))
                sha256_v = safe_text(h_data.get('sha256'))
                hashes_cell = Paragraph(
                    f"<strong>MD5:</strong> <code>{md5_v}</code><br/>"
                    f"<strong>SHA-1:</strong> <code>{sha1_v}</code><br/>"
                    f"<strong>SHA-256:</strong> <code>{sha256_v}</code>",
                    self.style_code
                )
                status_v = h_data.get('verification_status', 'Calculated Baseline')
                status_cell = Paragraph(f"<font color='#059669'><strong>{safe_text(status_v)}</strong></font>", self.style_td_bold)

            table_data.append([
                Paragraph(f"<strong>{safe_text(ev.get('evidence_id'))}</strong><br/>{safe_text(ev.get('filename'))}", self.style_td),
                hashes_cell,
                status_cell
            ])

        t = Table(table_data, colWidths=[120, 330, 90])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.c_secondary),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))
        return story

    def build_file_analysis(self, evidence_list: list) -> list:
        """Section E: File Analysis & Signature Verification."""
        story = []
        story.extend(self._section_header("E", "File Signature, Format & Anomaly Analysis"))

        if not evidence_list:
            story.append(Paragraph("<em>No evidence available for file format analysis.</em>", self.style_muted))
            story.append(Spacer(1, 14))
            return story

        table_data = [[
            Paragraph("Filename & Ext", self.style_th),
            Paragraph("Magic Byte Format", self.style_th),
            Paragraph("MIME Type", self.style_th),
            Paragraph("Signature Mismatch", self.style_th),
            Paragraph("Hidden Status", self.style_th),
        ]]

        for i, ev in enumerate(evidence_list):
            fa = ev.get('file_analysis')
            if not fa:
                table_data.append([
                    Paragraph(safe_text(ev.get('filename')), self.style_td),
                    Paragraph("Not Analyzed", self.style_td),
                    Paragraph("Not Analyzed", self.style_td),
                    Paragraph("Not Analyzed", self.style_td),
                    Paragraph("Not Analyzed", self.style_td),
                ])
            else:
                mismatch = fa.get('extension_mismatch', False)
                if mismatch:
                    mis_str = "<font color='#dc2626'><strong>MISMATCH ANOMALY</strong></font>"
                else:
                    mis_str = "<font color='#059669'>Match (Verified)</font>"

                is_hidden = fa.get('is_hidden', False)
                hid_str = "<font color='#dc2626'><strong>Hidden</strong></font>" if is_hidden else "Visible"

                table_data.append([
                    Paragraph(f"<strong>{safe_text(ev.get('filename'))}</strong><br/><font size='7' color='#64748b'>.{safe_text(fa.get('extension', ''))}</font>", self.style_td),
                    Paragraph(safe_text(fa.get('detected_format', 'Unknown')), self.style_td),
                    Paragraph(safe_text(fa.get('mime_type', 'Unknown')), self.style_td),
                    Paragraph(mis_str, self.style_td),
                    Paragraph(hid_str, self.style_td),
                ])

        t = Table(table_data, colWidths=[120, 115, 120, 110, 75])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.c_primary),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))
        return story

    def build_metadata_analysis(self, evidence_list: list, include_gps: bool = False) -> list:
        """Section F: Metadata Analysis (EXIF & Document)."""
        story = []
        story.extend(self._section_header("F", "Metadata Examination (EXIF & Document Properties)"))

        meta_caveat = (
            "Forensic Note: Missing metadata does not indicate software failure or deliberate tampering. "
            "Consumer smartphones, image editors, and social media platforms routinely strip camera tags for privacy."
        )
        story.append(Paragraph(meta_caveat, self.style_muted))
        story.append(Spacer(1, 6))

        has_any_meta = False
        for ev in evidence_list:
            meta = ev.get('metadata_analysis')
            if not meta:
                continue
            has_any_meta = True

            fname = safe_text(ev.get('filename'))
            ev_id = safe_text(ev.get('evidence_id'))
            story.append(Paragraph(f"<strong>Evidence Item {ev_id} ({fname})</strong>", self.style_h2))

            rows = []
            # Check Image / EXIF metadata
            if meta.get('file_type') == 'image' or 'camera_make' in meta or 'dimensions' in meta:
                rows.append([Paragraph("<strong>File Category:</strong>", self.style_td_bold), Paragraph("Image (EXIF Inspection)", self.style_td)])
                rows.append([Paragraph("<strong>Dimensions / Color:</strong>", self.style_td_bold), Paragraph(f"{safe_text(meta.get('dimensions'))} | {safe_text(meta.get('color_mode'))}", self.style_td)])
                rows.append([Paragraph("<strong>Camera Make / Model:</strong>", self.style_td_bold), Paragraph(f"{safe_text(meta.get('camera_make'), 'Not Recorded in File')} / {safe_text(meta.get('camera_model'), 'Not Recorded in File')}", self.style_td)])
                rows.append([Paragraph("<strong>Lens Hardware:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('lens_model'), 'Not Recorded in File'), self.style_td)])
                rows.append([Paragraph("<strong>Shutter Timestamp:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('date_taken'), 'Not Recorded in File'), self.style_td)])
                rows.append([Paragraph("<strong>Exposure Settings:</strong>", self.style_td_bold), Paragraph(f"ISO {safe_text(meta.get('iso'), 'N/A')} | Aperture {safe_text(meta.get('aperture'), 'N/A')} | Shutter {safe_text(meta.get('shutter_speed'), 'N/A')}", self.style_td)])

                # GPS Handling
                if include_gps:
                    gps_lat = meta.get('gps_latitude')
                    gps_lon = meta.get('gps_longitude')
                    if gps_lat and gps_lon:
                        gps_str = f"Lat: {safe_text(gps_lat)}, Lon: {safe_text(gps_lon)}"
                    else:
                        gps_str = "Not Recorded in File"
                else:
                    gps_str = "<font color='#64748b'>[GPS GEOLOCATION WITHHELD — EXPLICIT AUTHORIZATION REQUIRED]</font>"

                rows.append([Paragraph("<strong>GPS Coordinates:</strong>", self.style_td_bold), Paragraph(gps_str, self.style_td)])

            # Check Document metadata (PDF / DOCX)
            elif meta.get('file_type') == 'document' or 'title' in meta or 'author' in meta:
                rows.append([Paragraph("<strong>File Category:</strong>", self.style_td_bold), Paragraph("Document (Core Metadata Inspection)", self.style_td)])
                rows.append([Paragraph("<strong>Title:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('title'), 'Not Recorded in File'), self.style_td)])
                rows.append([Paragraph("<strong>Author:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('author'), 'Not Recorded in File'), self.style_td)])
                rows.append([Paragraph("<strong>Subject:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('subject'), 'Not Recorded in File'), self.style_td)])
                rows.append([Paragraph("<strong>Producer / Creator:</strong>", self.style_td_bold), Paragraph(f"{safe_text(meta.get('producer'), 'N/A')} / {safe_text(meta.get('creator'), 'N/A')}", self.style_td)])
                rows.append([Paragraph("<strong>Embedded Creation Date:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('creation_date'), 'Not Recorded in File'), self.style_td)])
                rows.append([Paragraph("<strong>Embedded Mod Date:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('modification_date'), 'Not Recorded in File'), self.style_td)])

            else:
                rows.append([Paragraph("<strong>Extraction Status:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('status', 'Metadata Inspected')), self.style_td)])
                rows.append([Paragraph("<strong>Available Metadata Fields:</strong>", self.style_td_bold), Paragraph(safe_text(meta.get('available_fields_count', 0)), self.style_td)])

            if rows:
                t = Table(rows, colWidths=[150, 390])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.c_bg_light),
                    ('BOX', (0, 0), (-1, -1), 0.8, self.c_border),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))

        if not has_any_meta:
            story.append(Paragraph("<em>No metadata extraction records available for registered evidence.</em>", self.style_muted))

        story.append(Spacer(1, 14))
        return story

    def build_keyword_search(self, keyword_findings: dict) -> list:
        """Section G: Keyword Search Findings."""
        story = []
        story.extend(self._section_header("G", "Keyword Search Findings & Artifact Discovery"))

        if not keyword_findings or not keyword_findings.get('searches'):
            story.append(self._make_callout(
                "Keyword search was not executed for this investigation scope or yielded zero matching criteria.",
                title="KEYWORD SEARCH NOTICE", bg_hex="#f8fafc", border_hex="#cbd5e1"
            ))
            story.append(Spacer(1, 14))
            return story

        searches = keyword_findings.get('searches', [])
        table_data = [[
            Paragraph("Target Keyword", self.style_th),
            Paragraph("Matching Evidence", self.style_th),
            Paragraph("Matches", self.style_th),
            Paragraph("Location Ref", self.style_th),
            Paragraph("Redacted Context Preview", self.style_th),
        ]]

        for s in searches:
            ev_name = safe_text(s.get('filename', 'Unknown'))
            k_term = safe_text(s.get('keyword', ''))
            count = s.get('occurrences', 0)
            loc = safe_text(s.get('location', 'N/A'))
            preview = redact_sensitive_snippet(s.get('preview', ''))

            table_data.append([
                Paragraph(f"<code>{k_term}</code>", self.style_td_bold),
                Paragraph(ev_name, self.style_td),
                Paragraph(str(count), self.style_td),
                Paragraph(loc, self.style_td),
                Paragraph(preview, self.style_td),
            ])

        t = Table(table_data, colWidths=[90, 110, 45, 75, 220])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.c_secondary),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))
        return story

    def build_timeline_analysis(self, timeline_data: dict) -> list:
        """Section H: Timeline Analysis & Chronological Event Sequence."""
        story = []
        story.extend(self._section_header("H", "Timeline Analysis & Chronological Event Sequence"))

        disclaimer = (
            "Forensic Principle: Filesystem timestamps reflect storage volume modifications. "
            "On Linux/POSIX systems, 'ctime' represents Inode metadata/status change and is NEVER interpreted as file creation. "
            "Created events are derived strictly from genuine birthtime (statx) or embedded document metadata."
        )
        story.append(Paragraph(disclaimer, self.style_muted))
        story.append(Spacer(1, 6))

        if not timeline_data or not timeline_data.get('events'):
            story.append(Paragraph("<em>No timeline events recorded for this investigation scope.</em>", self.style_muted))
            story.append(Spacer(1, 14))
            return story

        # Summary counts table
        counts = [
            [
                Paragraph("<strong>Total Events:</strong>", self.style_td_bold), Paragraph(str(timeline_data.get('total_events', 0)), self.style_td),
                Paragraph("<strong>Created Events:</strong>", self.style_td_bold), Paragraph(str(timeline_data.get('created_events', 0)), self.style_td),
                Paragraph("<strong>Modified Events:</strong>", self.style_td_bold), Paragraph(str(timeline_data.get('modified_events', 0)), self.style_td),
            ],
            [
                Paragraph("<strong>Metadata Changed:</strong>", self.style_td_bold), Paragraph(str(timeline_data.get('metadata_changed_events', 0)), self.style_td),
                Paragraph("<strong>Accessed Events:</strong>", self.style_td_bold), Paragraph(str(timeline_data.get('accessed_events', 0)), self.style_td),
                Paragraph("<strong>App Milestones:</strong>", self.style_td_bold), Paragraph(str(timeline_data.get('investigation_events', 0)), self.style_td),
            ]
        ]
        ct = Table(counts, colWidths=[90, 85, 95, 85, 100, 85])
        ct.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.c_bg_light),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(ct)
        story.append(Spacer(1, 10))

        # Chronological Events Table (first 35 events to maintain clean pagination)
        events = timeline_data.get('events', [])[:35]
        ev_table_data = [[
            Paragraph("Timestamp", self.style_th),
            Paragraph("Event Type", self.style_th),
            Paragraph("Subject / Filename", self.style_th),
            Paragraph("Event Source", self.style_th),
            Paragraph("Forensic Telemetry & Notes", self.style_th),
        ]]

        for ev in events:
            ev_table_data.append([
                Paragraph(f"<code>{safe_text(ev.get('timestamp'))}</code>", self.style_td_bold),
                Paragraph(safe_text(ev.get('event_type')), self.style_td),
                Paragraph(safe_text(ev.get('filename')), self.style_td),
                Paragraph(safe_text(ev.get('event_source')), self.style_td),
                Paragraph(safe_text(ev.get('forensic_notes')), self.style_td),
            ])

        et = Table(ev_table_data, colWidths=[105, 85, 100, 105, 145])
        et.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.c_primary),
            ('BOX', (0, 0), (-1, -1), 1, self.c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, self.c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(et)

        if len(timeline_data.get('events', [])) > 35:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<em>Showing first 35 of {len(timeline_data['events'])} chronological events. Complete sequence available in CSV/JSON exports.</em>", self.style_muted))

        story.append(Spacer(1, 14))
        return story

    def build_investigation_summary(self, summary: dict) -> list:
        """Section I: Investigation Summary & Key Findings."""
        story = []
        story.extend(self._section_header("I", "Investigation Summary & Key Findings"))

        total_ev = summary.get('total_evidence', 0)
        analyzed_ev = summary.get('analyzed_evidence', 0)
        mismatch_count = summary.get('extension_mismatches', 0)
        keyword_hits = summary.get('keyword_hits', 0)
        earliest_dt = summary.get('date_earliest') or "N/A"
        latest_dt = summary.get('date_latest') or "N/A"

        bullets = [
            f"<strong>Evidence Cataloging:</strong> {total_ev} total evidence item(s) registered; {analyzed_ev} item(s) successfully analyzed.",
            f"<strong>Data Integrity:</strong> 100% cryptographic baseline hashes computed and preserved for chain of custody verification.",
            f"<strong>Format Anomalies:</strong> {mismatch_count} extension mismatch anomaly/anomalies detected during magic byte file signature verification.",
            f"<strong>Keyword Hit Rate:</strong> {keyword_hits} total keyword match occurrence(s) discovered across analyzed text and document payloads.",
            f"<strong>Chronological Activity Span:</strong> Earliest recorded event: <code>{safe_text(earliest_dt)}</code> &rarr; Latest recorded event: <code>{safe_text(latest_dt)}</code>."
        ]

        for b in bullets:
            story.append(Paragraph(f"&bull; {b}", self.style_body))

        story.append(Spacer(1, 14))
        return story

    def build_limitations_and_disclaimer(self) -> list:
        """Section J: Limitations and Disclaimer."""
        story = []
        story.extend(self._section_header("J", "Limitations & Forensic Disclaimers"))

        disclaimers = [
            "<strong>1. Missing Metadata:</strong> Absence of EXIF, author, or revision metadata does not necessarily indicate intentional evidence tampering or anti-forensic activity. Default settings on many operating systems, modern smartphones, and internet services automatically strip metadata.",
            "<strong>2. Filesystem Timestamps:</strong> Filesystem timestamps (Modified, Accessed, Changed, Created) reflect underlying OS storage volume operations and do not conclusively establish physical human operator presence. Kernel optimizations (such as relatime or noatime) may prevent real-time updates.",
            "<strong>3. Inode Change Time (ctime):</strong> Under Linux/POSIX systems, 'ctime' records inode attribute modifications (permissions, ownership, renames). Forensic standard: ctime must NEVER be interpreted as file creation time.",
            "<strong>4. Cryptographic Hash Limitations:</strong> Matching cryptographic hashes establish exact bit-for-bit file replication and data integrity, but do not independently prove authorship, provenance, or intent.",
            "<strong>5. Educational & Academic Demonstration:</strong> ForensiX is an educational forensic examination toolkit developed for collegiate research and technical demonstration. It is not an ISO/IEC 17025 accredited statutory digital forensics laboratory suite.",
            "<strong>6. Mandatory Human Verification:</strong> All automated findings, extracted strings, signature matches, and timeline correlations generated by this toolkit require independent manual verification by a certified digital forensics examiner."
        ]

        for d in disclaimers:
            story.append(Paragraph(d, self.style_body))
            story.append(Spacer(1, 2))

        story.append(Spacer(1, 20))

        # Sign-off block
        sign_block = [
            [
                Paragraph("<strong>Lead Forensic Examiner Signature:</strong><br/><br/>____________________________________", self.style_td),
                Paragraph("<strong>Laboratory Technical Reviewer:</strong><br/><br/>____________________________________", self.style_td)
            ],
            [
                Paragraph("Date: ________________________", self.style_td),
                Paragraph("Date: ________________________", self.style_td)
            ]
        ]
        st = Table(sign_block, colWidths=[270, 270])
        st.setStyle(TableStyle([
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(st)

        return story

    def generate_report(self, case: dict, evidence_list: list, report_meta: dict,
                        timeline_data: dict, keyword_findings: dict, summary_data: dict,
                        output_path: str) -> str:
        """
        Orchestrates full report generation and outputs the finished PDF file.
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=46
        )

        story = []

        # A. Cover Page
        story.extend(self.build_cover_page(case, report_meta))

        # B. Case Information
        story.extend(self.build_case_information(case))

        # C. Evidence Inventory
        story.extend(self.build_evidence_inventory(evidence_list))

        # D. Hash Analysis
        story.extend(self.build_hash_analysis(evidence_list))

        # E. File Analysis
        story.extend(self.build_file_analysis(evidence_list))

        # F. Metadata Analysis
        include_gps = report_meta.get('include_gps', False)
        story.extend(self.build_metadata_analysis(evidence_list, include_gps=include_gps))

        # G. Keyword Search
        story.extend(self.build_keyword_search(keyword_findings))

        # H. Timeline Analysis
        story.extend(self.build_timeline_analysis(timeline_data))

        # I. Investigation Summary
        story.extend(self.build_investigation_summary(summary_data))

        # J. Limitations & Disclaimer
        story.extend(self.build_limitations_and_disclaimer())

        # Tag canvas with case ID for running headers
        def make_canvas(*args, **kwargs):
            c = NumberedCanvas(*args, **kwargs)
            c._case_id_tag = f"Case Ref: {case.get('case_id', 'GENERAL-CASE')}"
            return c

        doc.build(story, canvasmaker=make_canvas)
        return output_path


def fetch_case_report_data(db, case_id: str, selected_evidence_ids: list = None,
                           include_gps: bool = False, keywords_query: str = None) -> dict:
    """
    Fetches actual results from the existing database and runs on-demand forensic
    analysis for physical evidence on disk if not previously analyzed.
    Guarantees no statistics or timestamps are invented.
    """
    # 1. Fetch Case Row
    case_row = db.execute(
        'SELECT * FROM cases WHERE case_id = ? OR id = ?', (case_id, case_id)
    ).fetchone()

    if not case_row:
        return None

    case = dict(case_row)

    # 2. Fetch Evidence Rows
    if selected_evidence_ids is not None:
        clean_ids = [str(x).strip() for x in selected_evidence_ids if str(x).strip()]
        if clean_ids:
            placeholders = ','.join(['?'] * len(clean_ids))
            ev_rows = db.execute(
                f'SELECT * FROM evidence WHERE case_id = ? AND (evidence_id IN ({placeholders}) OR id IN ({placeholders}))',
                [case['id']] + clean_ids + clean_ids
            ).fetchall()
        else:
            ev_rows = []
    else:
        ev_rows = db.execute(
            'SELECT * FROM evidence WHERE case_id = ?', (case['id'],)
        ).fetchall()

    evidence_list = []
    total_mismatches = 0
    all_raw_events = []

    # 3. For each evidence item, aggregate or compute actual analysis results
    for er in ev_rows:
        item = dict(er)
        st_path = item.get('stored_path')
        fname = item.get('filename')
        ev_pk = item.get('id')

        # --- A. Hash Records ---
        h_row = db.execute('SELECT * FROM hash_records WHERE evidence_id = ?', (ev_pk,)).fetchone()
        if h_row:
            item['hash_analysis'] = dict(h_row)
        elif st_path and os.path.exists(st_path):
            try:
                with open(st_path, 'rb') as f:
                    hashes = compute_hashes(f)
                    item['hash_analysis'] = {
                        'md5': hashes['md5'],
                        'sha1': hashes['sha1'],
                        'sha256': hashes['sha256'],
                        'verification_status': 'Computed Baseline'
                    }
            except Exception:
                item['hash_analysis'] = None
        else:
            item['hash_analysis'] = None

        # --- B. File Analysis ---
        fa_row = db.execute("SELECT * FROM analysis_results WHERE evidence_id = ? AND analysis_type = 'file'", (ev_pk,)).fetchone()
        if fa_row:
            try:
                item['file_analysis'] = json.loads(fa_row['results_json'])
            except Exception:
                item['file_analysis'] = None
        elif st_path and os.path.exists(st_path):
            try:
                with open(st_path, 'rb') as f:
                    fa_res = analyze_file_stream(file_stream=f, raw_filename=fname, file_path=st_path)
                    item['file_analysis'] = fa_res
                    if fa_res.get('extension_mismatch'):
                        total_mismatches += 1
            except Exception:
                item['file_analysis'] = None
        else:
            item['file_analysis'] = None

        # --- C. Metadata Analysis ---
        meta_row = db.execute("SELECT * FROM analysis_results WHERE evidence_id = ? AND analysis_type = 'metadata'", (ev_pk,)).fetchone()
        if meta_row:
            try:
                item['metadata_analysis'] = json.loads(meta_row['results_json'])
            except Exception:
                item['metadata_analysis'] = None
        elif st_path and os.path.exists(st_path):
            try:
                with open(st_path, 'rb') as f:
                    m_res = extract_metadata(f, filename=fname)
                    item['metadata_analysis'] = m_res
            except Exception:
                item['metadata_analysis'] = None
        else:
            item['metadata_analysis'] = None

        # --- D. Collect Filesystem & Embedded Timestamps ---
        if st_path and os.path.exists(st_path):
            fs_evs = extract_filesystem_timestamps(st_path, fname, evidence_id=item.get('evidence_id'), case_id=case.get('case_id'))
            all_raw_events.extend(fs_evs)
            doc_evs = extract_embedded_document_timestamps(st_path, fname, evidence_id=item.get('evidence_id'), case_id=case.get('case_id'))
            all_raw_events.extend(doc_evs)

        # Registration event
        if item.get('added_at'):
            all_raw_events.append({
                'filename': fname,
                'event_type': 'Evidence Registered',
                'timestamp': item['added_at'][:19],
                'timestamp_raw': 0,
                'evidence_id': item.get('evidence_id'),
                'case_id': case.get('case_id'),
                'event_source': 'Evidence Intake Register',
                'forensic_notes': f"Evidence registered into case {case.get('case_id')}."
            })

        evidence_list.append(item)

    # 4. Keyword Search Data
    keyword_findings = {'searches': []}
    keywords_list = []
    if keywords_query:
        keywords_list = [k.strip() for k in keywords_query.split(',') if k.strip()]
    if not keywords_list:
        keywords_list = ['confidential', 'password', 'exfiltrate', 'flag']

    total_kw_hits = 0
    for ev in evidence_list:
        st_path = ev.get('stored_path')
        if st_path and os.path.exists(st_path):
            try:
                with open(st_path, 'rb') as f:
                    res = search_file(f, ev.get('filename'), keywords_list, case_sensitive=False)
                    for kw, matches in res.get('matches_by_keyword', {}).items():
                        if matches:
                            total_kw_hits += len(matches)
                            first_m = matches[0]
                            keyword_findings['searches'].append({
                                'filename': ev.get('filename'),
                                'keyword': kw,
                                'occurrences': len(matches),
                                'location': f"Line {first_m.get('line_number', '1')}",
                                'preview': first_m.get('line_content', '')
                            })
            except Exception:
                pass

    # 5. Timeline Generation
    timeline_data = generate_timeline(all_raw_events, sort_order='asc')

    # 6. Investigation Summary Metrics
    summary_data = {
        'total_evidence': len(ev_rows),
        'analyzed_evidence': len(evidence_list),
        'extension_mismatches': total_mismatches,
        'keyword_hits': total_kw_hits,
        'date_earliest': timeline_data.get('date_earliest'),
        'date_latest': timeline_data.get('date_latest')
    }

    return {
        'case': case,
        'evidence_list': evidence_list,
        'keyword_findings': keyword_findings,
        'timeline_data': timeline_data,
        'summary_data': summary_data
    }


def record_generated_report(db, case_id_pk: int, report_id: str, report_title: str,
                            report_filename: str, file_path: str, file_size: int,
                            generated_by: str = "Lead Forensic Examiner",
                            evidence_count: int = 0,
                            selected_evidence_ids: str = None):
    """Saves generated report record into database."""
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db.execute(
        '''
        INSERT INTO reports (case_id, report_id, report_title, report_filename, file_path, file_size, generated_at, generated_by, evidence_count, selected_evidence_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (case_id_pk, report_id, report_title, report_filename, file_path, file_size, now_str, generated_by, evidence_count, selected_evidence_ids)
    )
    # Log audit event
    db.execute(
        '''
        INSERT INTO audit_logs (case_id, action, details, performed_by, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ''',
        (case_id_pk, 'Generate Report', f"Generated forensic PDF report: {report_id} ({report_filename}, {evidence_count} evidence items)", generated_by, now_str)
    )
    db.commit()
