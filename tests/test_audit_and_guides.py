"""
Unit tests for Mission 11 Parts 3 & 4 — Vulnerability-specific human fix guides,
AUTO_APPROVED visual badging, and Audit Log trail persistence.
Includes X-API-Key headers for backend hardening compatibility.
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.database import Base, get_db
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus, AuditLog
from backend.services.remediation_advisor import generate_recommendation
from backend.services.audit_logger import log_audit_event
from dashboard.server import render_dashboard_html

API_KEY_HEADERS = {"X-API-Key": "nkat_secret_api_key_2026"}


def test_full_fix_guide_generation_all_categories():
    categories = [
        "Missing Security Header: Content-Security-Policy",
        "Exposed Git Repository",
        "SQL Injection Vulnerability",
        "Cross-Site Scripting (XSS)",
        "Exposed Swagger UI Documentation",
        "Exposed Anonymous FTP Directory",
        "Exposed Prometheus Metrics Endpoint",
        "Outdated Server Technology Fingerprint",
        "CVE-2023-12345 Software Vulnerability",
        "Unknown Unrecognized Security Anomaly",
    ]

    for cat in categories:
        rec = generate_recommendation({"check_name": cat, "severity": "HIGH", "evidence": "sample evidence"})
        assert "full_fix_guide" in rec
        guide = rec["full_fix_guide"]
        assert "plain_language_meaning" in guide and len(guide["plain_language_meaning"]) > 0
        assert "why_it_is_risky" in guide and len(guide["why_it_is_risky"]) > 0
        assert "fix_steps" in guide
        assert "nginx" in guide["fix_steps"]
        assert "apache" in guide["fix_steps"]
        assert "express_node" in guide["fix_steps"]
        assert "verification_steps" in guide and len(guide["verification_steps"]) > 0
        assert "rollback_note" in guide and len(guide["rollback_note"]) > 0


def test_audit_log_persistence_and_api(tmp_path, monkeypatch):
    db_file = os.path.join(tmp_path, "test_audit.db")
    engine = create_engine(f"sqlite:///{db_file}")
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    db = TestingSession()

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    subdomain = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(subdomain)
    db.commit()
    db.refresh(subdomain)

    f = Finding(
        subdomain_id=subdomain.id,
        check_name="SQL Injection",
        severity="HIGH",
        status=FindingStatus.OPEN.value,
    )
    db.add(f)
    db.commit()
    db.refresh(f)

    # 1. Approve
    client.patch(f"/api/v1/findings/{f.id}/approve", json={"approved_by": "lead_sec"}, headers=API_KEY_HEADERS)

    # 2. Rollback
    client.patch(f"/api/v1/findings/{f.id}/rollback", headers=API_KEY_HEADERS)

    # 3. Reject
    client.patch(f"/api/v1/findings/{f.id}/reject", json={"approved_by": "lead_sec"}, headers=API_KEY_HEADERS)

    # Query GET /api/v1/audit-logs
    res_logs = client.get("/api/v1/audit-logs")
    assert res_logs.status_code == 200
    logs_data = res_logs.json()
    assert len(logs_data) >= 3

    actions = [l["action"] for l in logs_data]
    assert "approve" in actions
    assert "rollback" in actions
    assert "reject" in actions

    app.dependency_overrides.clear()
    db.close()


def test_dashboard_rendering_auto_approved_badge_and_guides(tmp_path, monkeypatch):
    db_file = os.path.join(tmp_path, "test_dashboard_render.db")
    engine = create_engine(f"sqlite:///{db_file}")
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    monkeypatch.setattr("backend.database.SessionLocal", TestingSession)

    db = TestingSession()
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    subdomain = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(subdomain)
    db.commit()
    db.refresh(subdomain)

    f = Finding(
        subdomain_id=subdomain.id,
        check_name="Exposed Git Repository",
        severity="HIGH",
        status=FindingStatus.AUTO_APPROVED.value,
        approved_by="auto_approval_scheduler",
        review_deadline=datetime.now(timezone.utc) - timedelta(minutes=10)
    )
    db.add(f)
    db.commit()

    html_out = render_dashboard_html()
    assert " AUTO-APPROVED (TIMEOUT)" in html_out
    assert " HOW TO FIX" in html_out or "HOW TO FIX" in html_out
    assert "Nginx:" in html_out or "Nginx" in html_out
    assert "Apache:" in html_out or "Apache" in html_out

    db.close()
