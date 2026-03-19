"""
PDF Report Generator — ReportLab
Produces professional vulnerability reports matching the project specification.
CVSS severity coloring: Critical=red, High=orange, Medium=yellow, Low=green
"""

import os
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.platypus.flowables import Flowable


SEVERITY_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High":     colors.HexColor("#EA580C"),
    "Medium":   colors.HexColor("#D97706"),
    "Low":      colors.HexColor("#16A34A"),
}

SEVERITY_BG = {
    "Critical": colors.HexColor("#FEE2E2"),
    "High":     colors.HexColor("#FFEDD5"),
    "Medium":   colors.HexColor("#FEF9C3"),
    "Low":      colors.HexColor("#DCFCE7"),
}

HEADER_COLOR  = colors.HexColor("#1E3A5F")
ALT_ROW_COLOR = colors.HexColor("#F1F5F9")


def generate_report(scan, results, output_path: str, user=None) -> str:
    """
    Generate a PDF vulnerability report.

    Args:
        scan:        Scan ORM object
        results:     List of ScanResult ORM objects
        output_path: Where to write the PDF
        user:        User ORM object (optional)

    Returns:
        output_path on success
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="VulnScan Vulnerability Report",
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Title block ───────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "title", parent=styles["Title"],
        textColor=HEADER_COLOR, fontSize=22, spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        "sub", parent=styles["Normal"],
        textColor=colors.HexColor("#64748B"), fontSize=10, spaceAfter=2,
    )

    story.append(Paragraph("VulnScan Vulnerability Report", title_style))
    story.append(Paragraph("Vulnerability Assessment Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=2, color=HEADER_COLOR))
    story.append(Spacer(1, 12))

    # ── Scan metadata table ───────────────────────────────────────────
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta_data = [
        ["Field",         "Value"],
        ["Target",        scan.target],
        ["Scan Type",     scan.scan_type.upper()],
        ["Status",        scan.status.upper()],
        ["Started",       str(scan.started_at)[:19] if scan.started_at else "—"],
        ["Completed",     str(scan.ended_at)[:19]   if scan.ended_at   else "—"],
        ["Generated",     now],
        ["Prepared For",  user.username if user else "—"],
    ]
    meta_table = Table(meta_data, colWidths=[2 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), HEADER_COLOR),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("BACKGROUND",  (0, 1), (0, -1), ALT_ROW_COLOR),
        ("FONTNAME",    (0, 1), (0, -1), "Helvetica-Bold"),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT_ROW_COLOR]),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 18))

    # ── Executive Summary ─────────────────────────────────────────────
    h2_style = ParagraphStyle(
        "h2", parent=styles["Heading2"],
        textColor=HEADER_COLOR, fontSize=14, spaceBefore=14, spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "body", parent=styles["Normal"], fontSize=9, spaceAfter=4, leading=14,
    )

    story.append(Paragraph("Executive Summary", h2_style))

    counts = {s: sum(1 for r in results if r.severity == s) for s in ["Critical","High","Medium","Low"]}
    total  = len(results)

    # Severity pill table
    sev_data = [["Critical", "High", "Medium", "Low", "Total"]]
    sev_vals = [str(counts["Critical"]), str(counts["High"]),
                str(counts["Medium"]),  str(counts["Low"]), str(total)]
    sev_data.append(sev_vals)

    sev_table = Table(sev_data, colWidths=[1.3 * inch] * 5)
    sev_table.setStyle(TableStyle([
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (0, 1), SEVERITY_BG["Critical"]),
        ("BACKGROUND", (1, 1), (1, 1), SEVERITY_BG["High"]),
        ("BACKGROUND", (2, 1), (2, 1), SEVERITY_BG["Medium"]),
        ("BACKGROUND", (3, 1), (3, 1), SEVERITY_BG["Low"]),
        ("TEXTCOLOR",  (0, 1), (0, 1), SEVERITY_COLORS["Critical"]),
        ("TEXTCOLOR",  (1, 1), (1, 1), SEVERITY_COLORS["High"]),
        ("TEXTCOLOR",  (2, 1), (2, 1), SEVERITY_COLORS["Medium"]),
        ("TEXTCOLOR",  (3, 1), (3, 1), SEVERITY_COLORS["Low"]),
        ("FONTNAME",   (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 1), (-1, 1), 16),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING",    (0, 0), (-1, -1), 8),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 10))

    risk_level = ("Critical" if counts["Critical"] > 0 else
                  "High"     if counts["High"]     > 0 else
                  "Medium"   if counts["Medium"]   > 0 else "Low")

    summary_text = (
        f"This report documents the results of a vulnerability scan conducted against "
        f"<b>{scan.target}</b>. A total of <b>{total}</b> security findings were identified. "
        f"The overall risk level is assessed as <b>{risk_level}</b>. "
        f"Findings are categorised by severity using the Common Vulnerability Scoring System (CVSS). "
        f"<b>This tool identifies and reports vulnerabilities only — it does not attempt to "
        f"exploit systems or fix identified weaknesses.</b> Remediation steps are provided for "
        f"each finding to guide system administrators."
    )
    story.append(Paragraph(summary_text, body_style))

    # Ethical disclaimer
    disclaimer = (
        "<i><b>Ethical Notice:</b> This scan was conducted with the intent of improving "
        "security posture. All scanning activities must be performed only on systems for "
        "which you have explicit authorisation. Unauthorized scanning may violate applicable laws.</i>"
    )
    story.append(Spacer(1, 6))
    story.append(Paragraph(disclaimer, ParagraphStyle(
        "disclaimer", parent=body_style,
        textColor=colors.HexColor("#64748B"), borderPadding=6,
        borderColor=colors.HexColor("#CBD5E1"), borderWidth=1,
    )))
    story.append(Spacer(1, 14))

    # ── Detailed Findings ─────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", h2_style))

    if not results:
        story.append(Paragraph("No vulnerabilities were detected during this scan.", body_style))
    else:
        for idx, result in enumerate(sorted(results, key=lambda r: {"Critical":0,"High":1,"Medium":2,"Low":3}.get(r.severity, 4))):
            sev_color = SEVERITY_COLORS.get(result.severity, colors.gray)
            sev_bg    = SEVERITY_BG.get(result.severity, colors.white)

            finding_header = [
                [
                    Paragraph(f"#{idx+1} — {result.finding_type.replace('_',' ').title()}", ParagraphStyle(
                        "fh", parent=body_style, fontName="Helvetica-Bold", fontSize=10
                    )),
                    Paragraph(result.severity, ParagraphStyle(
                        "sev", parent=body_style, fontName="Helvetica-Bold",
                        fontSize=10, textColor=sev_color, alignment=2
                    )),
                ]
            ]
            header_tbl = Table(finding_header, colWidths=[5 * inch, 1.5 * inch])
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, -1), sev_bg),
                ("PADDING",     (0, 0), (-1, -1), 6),
                ("LINEBELOW",   (0, 0), (-1, -1), 1, sev_color),
            ]))
            story.append(header_tbl)

            detail_data = []
            if result.port:
                detail_data.append(["Port / Protocol", f"{result.port}/{result.protocol or 'tcp'}"])
            if result.service:
                detail_data.append(["Service", result.service])
            if result.version:
                detail_data.append(["Version", result.version])
            if result.vulnerability:
                detail_data.append(["CVE ID",     result.vulnerability.cve_id])
                detail_data.append(["CVSS Score", str(result.vulnerability.cvss_score)])

            if detail_data:
                det_table = Table(detail_data, colWidths=[2 * inch, 4.5 * inch])
                det_table.setStyle(TableStyle([
                    ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE",  (0, 0), (-1, -1), 8),
                    ("GRID",      (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
                    ("PADDING",   (0, 0), (-1, -1), 5),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, ALT_ROW_COLOR]),
                ]))
                story.append(det_table)

            story.append(Paragraph("<b>Description:</b>", ParagraphStyle(
                "lbl", parent=body_style, fontName="Helvetica-Bold", spaceBefore=4
            )))
            story.append(Paragraph(result.description or "—", body_style))

            story.append(Paragraph("<b>Remediation:</b>", ParagraphStyle(
                "lbl", parent=body_style, fontName="Helvetica-Bold",
                textColor=HEADER_COLOR
            )))
            story.append(Paragraph(result.remediation or "No specific remediation available.", body_style))
            story.append(Spacer(1, 10))

    # ── Footer ────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")))
    story.append(Paragraph(
        f"Generated by VulnScan | {now}",
        ParagraphStyle("footer", parent=body_style,
                       textColor=colors.HexColor("#94A3B8"), alignment=1)
    ))

    doc.build(story)
    return output_path
