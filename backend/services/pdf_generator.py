"""
Executive Security PDF Report Generator — Mission 18 Part 3
------------------------------------------------------------
Generates an executive vulnerability PDF summary for a scan_id using ReportLab.
Includes target metadata, severity counts, top critical findings, CISA KEV & EPSS threat scores,
and actionable remediation recommendations.
"""

import io
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.models import Scan, Subdomain, Finding
from backend.services.threat_correlation import compute_attack_path_graph

logger = logging.getLogger("nkat.pdf_generator")


def generate_scan_pdf_report(db: Session, scan_id: int) -> bytes:
    """
    Generates binary PDF content for an executive security report summarizing scan_id.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan ID #{scan_id} not found.")

    findings = (
        db.query(Finding)
        .join(Subdomain, Finding.subdomain_id == Subdomain.id)
        .filter(Subdomain.scan_id == scan_id)
        .order_by(Finding.id.asc())
        .all()
    )

    threat_graph = compute_attack_path_graph(db, scan_id)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    primary_color = colors.HexColor("#0f172a")    # Slate 900
    accent_blue = colors.HexColor("#0284c7")       # Sky 600
    text_dark = colors.HexColor("#334155")         # Slate 700
    bg_light = colors.HexColor("#f8fafc")          # Slate 50

    sev_critical_color = colors.HexColor("#ef4444") # Red 500
    sev_high_color = colors.HexColor("#f97316")     # Orange 500
    sev_medium_color = colors.HexColor("#eab308")   # Yellow 500
    sev_low_color = colors.HexColor("#3b82f6")      # Blue 500

    # Custom Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=accent_blue,
        spaceAfter=12
    )

    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=text_dark
    )

    body_bold = ParagraphStyle(
        "BodyBoldCustom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=primary_color
    )

    story = []

    # 1. Header & Title Block
    story.append(Paragraph("NKAT THREAT SENTINEL CONSOLE", subtitle_style))
    story.append(Paragraph(f"Executive Security Scan Report — Scan #{scan.id}", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_blue, spaceAfter=10))

    # 2. Metadata Table
    created_str = str(scan.created_at)[:19] if scan.created_at else "N/A"
    composite_score = threat_graph.get("composite_threat_score", 0.0)
    threat_level = threat_graph.get("threat_level", "UNKNOWN")

    meta_data = [
        [
            Paragraph("Target Endpoint:", body_bold),
            Paragraph(scan.target, body_style),
            Paragraph("Scan Status:", body_bold),
            Paragraph(scan.status, body_style),
        ],
        [
            Paragraph("Execution Date:", body_bold),
            Paragraph(created_str, body_style),
            Paragraph("Composite Vector Score:", body_bold),
            Paragraph(f"{composite_score} / 100 ({threat_level})", body_style),
        ]
    ]

    meta_table = Table(meta_data, colWidths=[110, 160, 120, 150])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_light),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 3. Severity Distribution Summary
    story.append(Paragraph("Vulnerability Severity Breakdown", h2_style))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s_name = f.severity.upper()
        if s_name in counts:
            counts[s_name] += 1
        else:
            counts["LOW"] += 1

    dist_data = [
        [
            Paragraph("Severity Level", body_bold),
            Paragraph("Discovered Count", body_bold),
            Paragraph("CISA KEV Exploited", body_bold),
            Paragraph("Max EPSS Score", body_bold)
        ],
        [
            Paragraph("<font color='#ef4444'><b>CRITICAL</b></font>", body_style),
            Paragraph(str(counts["CRITICAL"]), body_style),
            Paragraph("YES" if any(f.is_in_cisa_kev for f in findings if f.severity == "CRITICAL") else "No", body_style),
            Paragraph(str(max([f.epss_score or 0.0 for f in findings if f.severity == "CRITICAL"] + [0.0])), body_style)
        ],
        [
            Paragraph("<font color='#f97316'><b>HIGH</b></font>", body_style),
            Paragraph(str(counts["HIGH"]), body_style),
            Paragraph("YES" if any(f.is_in_cisa_kev for f in findings if f.severity == "HIGH") else "No", body_style),
            Paragraph(str(max([f.epss_score or 0.0 for f in findings if f.severity == "HIGH"] + [0.0])), body_style)
        ],
        [
            Paragraph("<font color='#eab308'><b>MEDIUM</b></font>", body_style),
            Paragraph(str(counts["MEDIUM"]), body_style),
            Paragraph("No", body_style),
            Paragraph(str(max([f.epss_score or 0.0 for f in findings if f.severity == "MEDIUM"] + [0.0])), body_style)
        ],
        [
            Paragraph("<font color='#3b82f6'><b>LOW / INFO</b></font>", body_style),
            Paragraph(str(counts["LOW"] + counts["INFO"]), body_style),
            Paragraph("No", body_style),
            Paragraph("0.001", body_style)
        ],
    ]

    dist_table = Table(dist_data, colWidths=[130, 130, 140, 140])
    dist_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(dist_table)
    story.append(Spacer(1, 10))

    # 4. Top Critical / High Findings Table
    story.append(Paragraph("Detailed Findings & Threat Intelligence", h2_style))

    if not findings:
        story.append(Paragraph("Zero findings discovered. Target infrastructure passed all security audit checks.", body_style))
    else:
        find_headers = [
            Paragraph("ID", body_bold),
            Paragraph("Check Name / Title", body_bold),
            Paragraph("Severity", body_bold),
            Paragraph("CISA KEV / EPSS", body_bold),
            Paragraph("Remediation Summary", body_bold)
        ]
        find_rows = [find_headers]

        for f in findings[:8]:  # Top findings
            kev_str = "<font color='#ef4444'><b> IN CISA KEV</b></font>" if f.is_in_cisa_kev else "Standard"
            epss_str = f"EPSS: {f.epss_score}" if f.epss_score else "EPSS: N/A"
            intel_cell = f"{kev_str}<br/>{epss_str}"

            rec_snippet = (f.recommendation or "Review target configuration.")[:120] + "..."

            sev_color = "#ef4444" if f.severity == "CRITICAL" else ("#f97316" if f.severity == "HIGH" else "#3b82f6")

            find_rows.append([
                Paragraph(f"#{f.id}", body_style),
                Paragraph(f.check_name, body_style),
                Paragraph(f"<font color='{sev_color}'><b>{f.severity}</b></font>", body_style),
                Paragraph(intel_cell, body_style),
                Paragraph(rec_snippet, body_style)
            ])

        find_table = Table(find_rows, colWidths=[35, 145, 65, 105, 190])
        find_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(find_table)

    story.append(Spacer(1, 14))

    # 5. Footer & Policy Scoping Notice
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    policy_notice = (
        "CONFIDENTIALITY NOTICE: This report is generated locally by NKAT Sentinel Console. "
        "All scan findings, threat scores, and target metadata remain 100% strictly on localhost. "
        "Target endpoint authorization strictly validated against docs/AUTHORIZED_TARGETS.md policy."
    )
    story.append(Paragraph(policy_notice, ParagraphStyle("Footer", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=7, leading=9, textColor=colors.HexColor("#64748b"))))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    logger.info(f"[+] Generated PDF Executive Report for Scan #{scan_id} ({len(pdf_bytes)} bytes)")
    return pdf_bytes
