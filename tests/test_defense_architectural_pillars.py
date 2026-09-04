"""
Unit and Integration Test Suite for the 4 Defense Automation Pillars:
Pillar 1: Continuous Event-Driven Scanning & CI/CD Webhooks
Pillar 2: Adaptive Organizational Context & Historical ML Triage
Pillar 3: Dynamic Unified Prioritization Index & SLA Tracking
Pillar 4: Finding Lifecycle Governance & Automated Fix Re-verification
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal, Base, engine
from backend.models import Scan, Subdomain, Finding, FindingStatus, FeedbackLabel, AuditLog
from backend.services.adaptive_ml import analyze_historical_decision_context
from backend.services.prioritization import (
    calculate_contextual_risk_score,
    determine_priority_tier,
    calculate_sla_deadline,
    enrich_finding_prioritization
)
from backend.services.governance import transition_finding_status, reverify_finding_target

client = TestClient(app)


from sqlalchemy import text

@pytest.fixture(autouse=True)
def setup_db():
    with engine.connect() as conn:
        def ensure_column(table_name: str, col_name: str, col_def: str):
            res = conn.execute(text(f"PRAGMA table_info({table_name});")).fetchall()
            existing_cols = [row[1] for row in res]
            if col_name not in existing_cols:
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def};"))
                conn.commit()

        ensure_column("findings", "priority_tier", "TEXT DEFAULT 'P3'")
        ensure_column("findings", "contextual_risk_score", "FLOAT")
        ensure_column("findings", "risk_acceptance_reason", "TEXT")
        ensure_column("findings", "reverified_at", "TIMESTAMP")
        ensure_column("findings", "sla_deadline", "TIMESTAMP")
        ensure_column("findings", "is_sla_breached", "BOOLEAN DEFAULT 0")
        ensure_column("findings", "historical_context_note", "TEXT")

    Base.metadata.create_all(bind=engine)
    yield


def test_pillar1_cicd_webhook_ingestion(monkeypatch):
    from backend.routers import events
    async def mock_async_scan(scan_id, url):
        return None

    monkeypatch.setattr(events, "_execute_scan_async", mock_async_scan)

    payload = {
        "event_type": "COMMIT_PUSH",
        "target_url": "http://127.0.0.1:3000",
        "commit_sha": "a1b2c3d4e5",
        "environment": "staging",
        "triggered_by": "GitHub_Actions"
    }
    response = client.post("/api/v1/events/webhook", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SCAN_TRIGGERED"
    assert "scan_id" in data
    assert data["triggered_by"] == "GitHub_Actions"


def test_pillar2_adaptive_historical_context():
    db: Session = SessionLocal()
    try:
        # Create dummy finding and feedback labels
        scan = Scan(target="http://example-test.local", status="COMPLETED")
        db.add(scan)
        db.commit()

        sub = Subdomain(scan_id=scan.id, hostname="example-test.local")
        db.add(sub)
        db.commit()

        finding = Finding(
            subdomain_id=sub.id,
            check_name="Test Header Rule",
            severity="LOW",
            evidence="Missing Header",
            status="OPEN"
        )
        db.add(finding)
        db.commit()

        # Add 3 False Positive feedback labels
        for _ in range(3):
            fb = FeedbackLabel(
                finding_id=finding.id,
                features_snapshot="check:Test Header Rule",
                human_label="FALSE_POSITIVE"
            )
            db.add(fb)
        db.commit()

        context = analyze_historical_decision_context(db, "Test Header Rule")
        assert context["total_reviews"] >= 3
        assert context["fp_rate"] >= 0.70
        assert context["fp_discount"] > 0.0
        assert "High historical False Positive rate" in context["historical_note"]
    finally:
        db.close()


def test_pillar3_dynamic_prioritization_matrix():
    # Test P1 Critical KEV finding
    score = calculate_contextual_risk_score(severity="CRITICAL", epss_score=0.85, is_in_cisa_kev=True, is_api_endpoint=True)
    tier = determine_priority_tier(score, severity="CRITICAL", epss_score=0.85, is_in_cisa_kev=True)
    assert score >= 75.0
    assert tier == "P1"

    # Test SLA Deadline calculation for P1
    now = datetime.now(timezone.utc)
    sla = calculate_sla_deadline("P1", now)
    assert (sla - now).days == 2

    # Test P4 Low finding
    low_score = calculate_contextual_risk_score(severity="LOW", epss_score=0.01, is_in_cisa_kev=False, is_api_endpoint=False)
    low_tier = determine_priority_tier(low_score, severity="LOW", epss_score=0.01, is_in_cisa_kev=False)
    assert low_tier == "P4"


def test_pillar4_governance_lifecycle_transitions():
    db: Session = SessionLocal()
    try:
        scan = Scan(target="http://example-gov.local", status="COMPLETED")
        db.add(scan)
        db.commit()

        sub = Subdomain(scan_id=scan.id, hostname="example-gov.local")
        db.add(sub)
        db.commit()

        finding = Finding(
            subdomain_id=sub.id,
            check_name="SQL Injection Governance Test",
            severity="CRITICAL",
            evidence="Error in SQL syntax",
            status="OPEN"
        )
        db.add(finding)
        db.commit()

        # 1. Valid transition: OPEN -> UNDER_TRIAGE
        ok, msg = transition_finding_status(db, finding, "UNDER_TRIAGE", actor="analyst")
        assert ok is True
        assert finding.status == "UNDER_TRIAGE"

        # 2. Valid transition: UNDER_TRIAGE -> IN_REMEDIATION
        ok, msg = transition_finding_status(db, finding, "IN_REMEDIATION", actor="dev_lead")
        assert ok is True
        assert finding.status == "IN_REMEDIATION"

        # 3. Invalid transition without reason for RISK_ACCEPTED
        ok, msg = transition_finding_status(db, finding, "RISK_ACCEPTED", actor="analyst")
        assert ok is False
        assert "Business justification" in msg

        # 4. Valid transition to RISK_ACCEPTED with reason
        ok, msg = transition_finding_status(db, finding, "RISK_ACCEPTED", actor="ciso", reason="Compensating WAF rule deployed.")
        assert ok is True
        assert finding.status == "RISK_ACCEPTED"
        assert finding.risk_acceptance_reason == "Compensating WAF rule deployed."
    finally:
        db.close()


def test_pillar4_automated_reverification():
    db: Session = SessionLocal()
    try:
        scan = Scan(target="http://127.0.0.1:8000", status="COMPLETED")
        db.add(scan)
        db.commit()

        sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1")
        db.add(sub)
        db.commit()

        finding = Finding(
            subdomain_id=sub.id,
            check_name="Exposed Git Repository",
            severity="HIGH",
            evidence="http://127.0.0.1/.git/HEAD",
            status="OPEN"
        )
        db.add(finding)
        db.commit()

        result = reverify_finding_target(db, finding.id)
        assert result["finding_id"] == finding.id
        assert result["is_reverified"] is True
        assert result["status"] == "RESOLVED"
    finally:
        db.close()
