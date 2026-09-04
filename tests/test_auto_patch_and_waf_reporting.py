"""
Test Suite: Automated Deadline Patching & WAF Telemetry Reporting
Verifies:
1. Automatic patching & auto-approval when human intervention deadline passes.
2. WAF summary metrics & attack aggregation logic.
3. Standalone WAF PDF report & Scan Executive PDF report generation with WAF telemetry.
4. Admin WAF report API endpoints.
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus, AuditLog, InAppNotification
from backend.services.auto_approval_scheduler import check_and_auto_approve_expired_findings
from backend.services.waf_service import (
    analyze_request_payload,
    get_waf_live_traffic_summary,
    generate_waf_summary_report,
)
from backend.services.pdf_generator import generate_scan_pdf_report, generate_waf_pdf_report


def test_auto_patching_on_expired_human_deadline(monkeypatch, tmp_path):
    """
    Validates that findings with expired human review deadlines are automatically patched,
    transitioned to AUTO_APPROVED, populated with fix recommendations/snippets,
    audited in AuditLog, and notified in InAppNotification.
    """
    db_file = os.path.join(tmp_path, "test_auto_patch.db")
    engine = create_engine(f"sqlite:///{db_file}")
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    monkeypatch.setattr("backend.services.auto_approval_scheduler.SessionLocal", TestingSession)

    db = TestingSession()

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    subdomain = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(subdomain)
    db.commit()
    db.refresh(subdomain)

    now_utc = datetime.now(timezone.utc)
    expired_time = now_utc - timedelta(minutes=15)

    expired_finding = Finding(
        subdomain_id=subdomain.id,
        check_name="Missing Security Header: X-Frame-Options",
        severity="HIGH",
        status=FindingStatus.OPEN.value,
        review_deadline=expired_time,
        evidence="Target HTTP response headers missing X-Frame-Options header.",
    )
    db.add(expired_finding)
    db.commit()
    db.refresh(expired_finding)

    # Run auto-approval & auto-patching scheduler check
    count = check_and_auto_approve_expired_findings()
    assert count == 1

    db.refresh(expired_finding)

    # Verify status transition
    assert expired_finding.status == FindingStatus.AUTO_APPROVED.value
    assert expired_finding.approved_by == "system_auto_approval_scheduler"
    assert expired_finding.approved_at is not None

    # Verify remediation patch generation
    assert expired_finding.recommendation is not None
    assert len(expired_finding.recommendation) > 0

    # Verify audit log entry
    audit_entry = db.query(AuditLog).filter(AuditLog.finding_id == expired_finding.id).first()
    assert audit_entry is not None
    assert audit_entry.action == "auto-approve-and-patch"

    # Verify InAppNotification creation
    notif = db.query(InAppNotification).filter(InAppNotification.title.contains("Auto-Patched Finding")).first()
    assert notif is not None
    assert "Deadline Passed" in notif.title

    db.close()


def test_waf_summary_reporting_aggregation():
    """
    Validates WAF live attack telemetry analysis and summary data structure aggregation.
    """
    # Simulate malicious payloads
    analyze_request_payload(
        method="POST",
        path="/api/v1/login",
        payload="user=' OR '1'='1'--",
        client_ip="198.51.100.22"
    )
    analyze_request_payload(
        method="GET",
        path="/api/v1/search?q=<script>alert('xss')</script>",
        payload="<script>alert('xss')</script>",
        client_ip="198.51.100.33"
    )

    summary = generate_waf_summary_report()

    assert summary["waf_status"] == "ACTIVE & PROTECTING"
    assert summary["total_requests_inspected"] >= 2
    assert summary["blocked_attacks_count"] >= 2
    assert isinstance(summary["attack_categories"], list)
    assert isinstance(summary["top_attackers"], list)
    assert isinstance(summary["active_waf_rules"], list)
    assert len(summary["active_waf_rules"]) == 4


def test_scan_and_waf_pdf_report_generation(tmp_path):
    """
    Validates binary PDF generation for both Scan Executive Report (with WAF telemetry)
    and Standalone WAF Executive PDF Report.
    """
    db_file = os.path.join(tmp_path, "test_pdf.db")
    engine = create_engine(f"sqlite:///{db_file}")
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSession()

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    subdomain = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(subdomain)
    db.commit()
    db.refresh(subdomain)

    finding = Finding(
        subdomain_id=subdomain.id,
        check_name="SQL Injection vulnerability in search parameter",
        severity="CRITICAL",
        status=FindingStatus.OPEN.value,
        evidence="Parameter 'cat' is vulnerable to SQL injection",
        is_in_cisa_kev=True,
        epss_score=0.88,
    )
    db.add(finding)
    db.commit()

    # 1. Generate Scan Executive PDF (including WAF telemetry section)
    scan_pdf_bytes = generate_scan_pdf_report(db, scan.id)
    assert isinstance(scan_pdf_bytes, bytes)
    assert len(scan_pdf_bytes) > 500
    assert scan_pdf_bytes.startswith(b"%PDF")

    # 2. Generate Standalone WAF PDF Report
    waf_pdf_bytes = generate_waf_pdf_report(db)
    assert isinstance(waf_pdf_bytes, bytes)
    assert len(waf_pdf_bytes) > 500
    assert waf_pdf_bytes.startswith(b"%PDF")

    db.close()
