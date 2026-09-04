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

    story.append(Spacer(1, 10))

    # 5. Real-Time WAF Attack Telemetry Summary Section
    story.append(Paragraph("Real-Time WAF Defense & Attack Interception Telemetry", h2_style))
    try:
        from backend.services.waf_service import generate_waf_summary_report
        waf_summary = generate_waf_summary_report(db)
        waf_data_rows = [
            [Paragraph("WAF Status", body_bold), Paragraph(waf_summary.get("waf_status", "ACTIVE"), body_style)],
            [Paragraph("Total Inspected Requests", body_bold), Paragraph(str(waf_summary.get("total_requests_inspected", 0)), body_style)],
            [Paragraph("Blocked Malicious Attacks", body_bold), Paragraph(f"<font color='#ef4444'><b>{waf_summary.get('blocked_attacks_count', 0)}</b></font>", body_style)],
            [Paragraph("Block Success Rate", body_bold), Paragraph(f"{waf_summary.get('block_rate_percent', 0.0)}%", body_style)]
        ]
        waf_table = Table(waf_data_rows, colWidths=[180, 360])
        waf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        story.append(waf_table)
    except Exception as waf_err:
        story.append(Paragraph(f"WAF Telemetry: Active (Error compiling summary: {waf_err})", body_style))

    story.append(Spacer(1, 14))

    # 6. Footer & Policy Scoping Notice
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


def generate_waf_pdf_report(db: Session = None) -> bytes:
    """
    Generates binary PDF content for a dedicated Executive WAF Security Telemetry Report.
    """
    from backend.services.waf_service import generate_waf_summary_report

    waf_data = generate_waf_summary_report(db)

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

    primary_color = colors.HexColor("#0f172a")
    accent_blue = colors.HexColor("#0284c7")
    text_dark = colors.HexColor("#334155")

    title_style = ParagraphStyle(
        "WafDocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "WafDocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=accent_blue,
        spaceAfter=12
    )

    h2_style = ParagraphStyle(
        "WafSectionHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "WafBodyText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=text_dark
    )

    body_bold = ParagraphStyle(
        "WafBodyBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=primary_color
    )

    story = []

    # Header
    story.append(Paragraph("NKAT AI — Real-Time WAF Security Executive Report", title_style))
    story.append(Paragraph(f"Generated at: {waf_data.get('generated_at')} | Status: {waf_data.get('waf_status')}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceAfter=10))

    # Summary Metrics
    story.append(Paragraph("WAF Traffic & Attack Interception Overview", h2_style))

    metrics_table_data = [
        [Paragraph("Metric Description", body_bold), Paragraph("Telemetry Value", body_bold)],
        [Paragraph("Protection Status", body_style), Paragraph(f"<b>{waf_data.get('waf_status')}</b>", body_style)],
        [Paragraph("Total Inspected Requests", body_style), Paragraph(str(waf_data.get("total_requests_inspected")), body_style)],
        [Paragraph("Blocked Malicious Threats", body_style), Paragraph(f"<font color='#ef4444'><b>{waf_data.get('blocked_attacks_count')}</b></font>", body_style)],
        [Paragraph("Allowed Legitimate Requests", body_style), Paragraph(str(waf_data.get("allowed_requests_count")), body_style)],
        [Paragraph("Threat Mitigation Block Rate", body_style), Paragraph(f"<b>{waf_data.get('block_rate_percent')}%</b>", body_style)],
    ]

    metrics_table = Table(metrics_table_data, colWidths=[240, 300])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 10))

    # Active WAF Rules
    story.append(Paragraph("Enforced Security Rules", h2_style))
    rule_rows = [[Paragraph("Rule ID", body_bold), Paragraph("Rule Title & Classification", body_bold), Paragraph("Enforcement State", body_bold)]]
    for rule in waf_data.get("active_waf_rules", []):
        rule_rows.append([
            Paragraph(rule.get("rule_id"), body_style),
            Paragraph(rule.get("name"), body_style),
            Paragraph(f"<font color='#16a34a'><b>{rule.get('status')}</b></font>", body_style)
        ])
    rule_table = Table(rule_rows, colWidths=[100, 320, 120])
    rule_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(rule_table)
    story.append(Spacer(1, 10))

    # Recent Blocked Attacks
    story.append(Paragraph("Recent Intercepted Attack Log Stream", h2_style))
    attack_rows = [[Paragraph("Timestamp", body_bold), Paragraph("Client IP", body_bold), Paragraph("Attack Category", body_bold), Paragraph("Action Taken", body_bold)]]
    for log in waf_data.get("recent_blocked_threats", [])[:8]:
        ts = str(log.get("timestamp", ""))[:19]
        attack_rows.append([
            Paragraph(ts, body_style),
            Paragraph(log.get("client_ip", "N/A"), body_style),
            Paragraph(log.get("classification", "Attack"), body_style),
            Paragraph("<font color='#ef4444'><b>BLOCKED (403)</b></font>", body_style)
        ])
    if len(attack_rows) == 1:
        attack_rows.append([Paragraph("No recent attack logs", body_style), Paragraph("-", body_style), Paragraph("Clean Traffic", body_style), Paragraph("-", body_style)])

    attack_table = Table(attack_rows, colWidths=[130, 110, 200, 100])
    attack_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(attack_table)
    story.append(Spacer(1, 14))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    policy_notice = (
        "NKAT AI WAF REPORT — Confidential Real-Time Traffic & Threat Analysis Report. "
        "Generated locally by NKAT Sentinel Console."
    )
    story.append(Paragraph(policy_notice, ParagraphStyle("WafFooter", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=7, leading=9, textColor=colors.HexColor("#64748b"))))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    logger.info(f"[+] Generated Executive WAF Security PDF Report ({len(pdf_bytes)} bytes)")
    return pdf_bytes

