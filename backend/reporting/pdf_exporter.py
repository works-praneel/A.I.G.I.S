from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import os
from datetime import datetime

REPORT_DIR = "/app/reports"

SEVERITY_COLORS = {
    "critical": colors.HexColor("#c0392b"),
    "high":     colors.HexColor("#e67e22"),
    "medium":   colors.HexColor("#f1c40f"),
    "low":      colors.HexColor("#27ae60"),
    "info":     colors.HexColor("#2980b9"),
}

SEVERITY_BG = {
    "critical": colors.HexColor("#fde8e8"),
    "high":     colors.HexColor("#fef3e8"),
    "medium":   colors.HexColor("#fefbe8"),
    "low":      colors.HexColor("#eafaf1"),
    "info":     colors.HexColor("#eaf4fb"),
}

SCAN_TYPE_LABELS = {
    "file":       "File Scan",
    "url":        "URL Scan",
    "repository": "Repository Scan",
}


def _clean_target(target: str, scan_type: str) -> str:
    if scan_type == "file":
        basename = os.path.basename(target)
        if len(basename) > 37 and basename[36] == "_":
            return basename[37:]
        return basename
    return target


def export_pdf(
    job_id: str,
    vulnerabilities: list,
    scan_type: str = "file",
    target: str = ""
) -> str:

    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, f"{job_id}.pdf")

    doc = SimpleDocTemplate(
        path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = _build_styles()
    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    # Title and subtitle in a Table with fixed rowHeights so ReportLab
    # cannot collapse spacing. Paragraph+Spacer collapses when text has dots.
    story.append(Spacer(1, 0.4 * inch))

    cover_header = Table(
        [
            [Paragraph("A.I.G.I.S", styles["cover_title"])],
            [Paragraph(" ", styles["cover_gap"])],
            [Paragraph("Security Analysis Report", styles["cover_subtitle"])],
        ],
        colWidths=[7 * inch],
        rowHeights=[0.75 * inch, 0.25 * inch, 0.45 * inch],
    )
    cover_header.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(cover_header)
    story.append(Spacer(1, 0.3 * inch))

    story.append(HRFlowable(
        width="100%", thickness=2, color=colors.HexColor("#2c3e50")
    ))
    story.append(Spacer(1, 0.25 * inch))

    display_target = _clean_target(target, scan_type)
    scan_label = SCAN_TYPE_LABELS.get(scan_type, scan_type.capitalize())

    info_data = [
        ["Scan Type",      scan_label],
        ["Target",         display_target or "N/A"],
        ["Job ID",         job_id],
        ["Generated",      datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Total Findings", str(len(vulnerabilities))],
    ]

    info_table = Table(info_data, colWidths=[1.5 * inch, 5.5 * inch])
    info_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("TEXTCOLOR",     (0, 0), (-1, -1), colors.HexColor("#333333")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("LINEBELOW",     (0, -1), (-1, -1), 0, colors.white),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.35 * inch))

    # ── Severity summary ───────────────────────────────────────────────────────
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    cvss_ranges = {
        "critical": "9.0 – 10.0",
        "high":     "7.0 – 8.9",
        "medium":   "4.0 – 6.9",
        "low":      "0.1 – 3.9",
        "info":     "0.0",
    }

    summary_data = [["Severity", "Count", "CVSS Range"]]
    for sev in ["critical", "high", "medium", "low", "info"]:
        summary_data.append([
            sev.capitalize(), str(counts[sev]), cvss_ranges[sev]
        ])

    summary_table = Table(
        summary_data, colWidths=[2 * inch, 1.5 * inch, 2 * inch]
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID",           (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ALIGN",          (1, 0), (-1, -1), "CENTER"),
        ("PADDING",        (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(PageBreak())

    # ── Detailed findings ──────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", styles["section_title"]))
    story.append(Spacer(1, 0.15 * inch))

    if not vulnerabilities:
        story.append(Paragraph(
            "No vulnerabilities were detected in this scan.",
            styles["body"]
        ))
    else:
        for idx, vuln in enumerate(vulnerabilities, start=1):
            story.extend(_build_finding_block(idx, vuln, styles))

    doc.build(
        story,
        onFirstPage=_add_footer,
        onLaterPages=_add_footer
    )

    return path


def _build_finding_block(idx: int, vuln: dict, styles: dict):
    elements = []

    sev = vuln.get("severity", "info").lower()
    sev_color = SEVERITY_COLORS.get(sev, colors.grey)
    sev_bg = SEVERITY_BG.get(sev, colors.white)
    cvss = vuln.get("cvss_score", "N/A")
    cvss_rating = vuln.get("cvss_rating", "")
    tool = vuln.get("tool", "unknown").upper()
    test_id = vuln.get("test_id", "N/A") or "N/A"
    cwe = vuln.get("cwe", "N/A") or "N/A"
    location = vuln.get("location", "N/A") or "N/A"
    # Strip internal container path from location display
    # e.g. /app/uploads/uuid_Test File.py:13 → Test File.py:13
    if "/app/uploads/" in location:
        parts = location.split("/app/uploads/")[-1]
        if len(parts) > 37 and parts[36] == "_":
            parts = parts[37:]
        location = parts
    description = (
        vuln.get("description", "No description available.")
        or "No description available."
    )

    def safe(text):
        if not isinstance(text, str):
            text = str(text)
        return (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    header_data = [[
        Paragraph(
            f"<b>#{idx} [{sev.upper()}]</b> — {safe(tool)} / {safe(test_id)}",
            styles["finding_header"]
        ),
        Paragraph(
            f"<b>CVSS: {cvss}</b> ({cvss_rating})",
            styles["cvss_badge"]
        ),
    ]]
    header_table = Table(header_data, colWidths=[4.5 * inch, 2 * inch])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_bg),
        ("LINEBELOW",  (0, 0), (-1, 0), 1.5, sev_color),
        ("PADDING",    (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(header_table)

    meta_data = [[
        Paragraph(f"<b>CWE:</b> {safe(cwe)}", styles["meta_small"]),
        Paragraph(f"<b>Location:</b> {safe(location)}", styles["meta_small"]),
    ]]
    meta_table = Table(meta_data, colWidths=[3.25 * inch, 3.25 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
        ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#e0e0e0")),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)

    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph("<b>Description</b>", styles["field_label"]))
    elements.append(Paragraph(safe(description), styles["body"]))

    remediation_text = vuln.get("remediation", "").strip()
    if remediation_text:
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(Paragraph("<b>AI Remediation</b>", styles["field_label"]))
        for line in remediation_text.splitlines():
            line = line.strip()
            if not line:
                elements.append(Spacer(1, 0.04 * inch))
            elif line in ("EXPLANATION:", "FIX:", "EXAMPLE:"):
                elements.append(Paragraph(
                    f"<b>{line}</b>", styles["remediation_heading"]
                ))
            else:
                elements.append(Paragraph(
                    safe(line), styles["remediation_body"]
                ))

    elements.append(Spacer(1, 0.25 * inch))
    elements.append(HRFlowable(
        width="100%", thickness=0.5, color=colors.HexColor("#dddddd")
    ))
    elements.append(Spacer(1, 0.15 * inch))

    return elements


def _build_styles() -> dict:
    return {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=36,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#2c3e50"),
            alignment=TA_CENTER,
            leading=44,
        ),
        "cover_gap": ParagraphStyle(
            "cover_gap",
            fontSize=1,
            fontName="Helvetica",
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle",
            fontSize=15,
            fontName="Helvetica",
            textColor=colors.HexColor("#7f8c8d"),
            alignment=TA_CENTER,
            leading=20,
        ),
        "section_title": ParagraphStyle(
            "section_title",
            fontSize=16,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#2c3e50"),
            spaceAfter=6
        ),
        "finding_header": ParagraphStyle(
            "finding_header",
            fontSize=11,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#2c3e50")
        ),
        "cvss_badge": ParagraphStyle(
            "cvss_badge",
            fontSize=11,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#2c3e50"),
            alignment=TA_CENTER
        ),
        "field_label": ParagraphStyle(
            "field_label",
            fontSize=10,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#2c3e50"),
            spaceAfter=3
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=9,
            fontName="Helvetica",
            textColor=colors.HexColor("#333333"),
            leading=14,
            spaceAfter=4
        ),
        "meta": ParagraphStyle(
            "meta",
            fontSize=10,
            fontName="Helvetica",
            textColor=colors.HexColor("#555555"),
            spaceAfter=4
        ),
        "meta_small": ParagraphStyle(
            "meta_small",
            fontSize=9,
            fontName="Helvetica",
            textColor=colors.HexColor("#555555")
        ),
        "remediation_heading": ParagraphStyle(
            "remediation_heading",
            fontSize=9,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1a5276"),
            spaceAfter=2,
            spaceBefore=4
        ),
        "remediation_body": ParagraphStyle(
            "remediation_body",
            fontSize=9,
            fontName="Helvetica",
            textColor=colors.HexColor("#333333"),
            leading=13,
            leftIndent=10
        ),
    }


def _add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#999999"))
    canvas.drawString(
        0.75 * inch, 0.4 * inch,
        "A.I.G.I.S Security Report  |  Confidential"
    )
    canvas.drawRightString(
        letter[0] - 0.75 * inch, 0.4 * inch,
        f"Page {doc.page}"
    )
    canvas.restoreState()
