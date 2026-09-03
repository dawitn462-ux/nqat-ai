"""
Unit tests for Mission 11 Part 2 — previous_state snapshot tracking,
PATCH /api/v1/findings/{id}/rollback endpoint, and Restore controls.
Includes X-API-Key headers for backend hardening compatibility.
"""

import os
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.database import Base, get_db
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus, FeedbackLabel
from backend.services.auto_approval_scheduler import check_and_auto_approve_expired_findings

API_KEY_HEADERS = {"X-API-Key": "nkat_secret_api_key_2026"}


def test_previous_state_snapshot_and_rollback_api(tmp_path, monkeypatch):
    # Setup isolated SQLite DB
    db_file = os.path.join(tmp_path, "test_rollback.db")
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
    monkeypatch.setattr("backend.services.auto_approval_scheduler.SessionLocal", TestingSession)

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

    # Finding 1: Human approve test
    f1 = Finding(
        subdomain_id=subdomain.id,
        check_name="XSS Vulnerability",
        severity="HIGH",
        status=FindingStatus.OPEN.value,
        evidence="<script>alert(1)</script>",
    )
    db.add(f1)
    db.commit()
    db.refresh(f1)

    # 1. Approve finding #1
    res_app = client.patch(f"/api/v1/findings/{f1.id}/approve", json={"approved_by": "sec_analyst"}, headers=API_KEY_HEADERS)
    assert res_app.status_code == 200
    data_app = res_app.json()
    assert data_app["status"] == "RESOLVED"
    assert data_app["approved_by"] == "sec_analyst"
    assert data_app["previous_state"] is not None
    snap1 = json.loads(data_app["previous_state"])
    assert snap1["status"] == "OPEN"

    # 2. Rollback finding #1
    res_roll = client.patch(f"/api/v1/findings/{f1.id}/rollback", headers=API_KEY_HEADERS)
    assert res_roll.status_code == 200
    data_roll = res_roll.json()
    assert data_roll["status"] == "OPEN"
    assert data_roll["approved_at"] is None
    assert data_roll["approved_by"] is None

    # Check feedback label for rollback
    fb_label = db.query(FeedbackLabel).filter(FeedbackLabel.finding_id == f1.id, FeedbackLabel.human_label == "rollback").first()
    assert fb_label is not None

    # Finding 2: Auto-approval rollback test
    now_utc = datetime.now(timezone.utc)
    f2 = Finding(
        subdomain_id=subdomain.id,
        check_name="Outdated Header",
        severity="LOW",
        status=FindingStatus.OPEN.value,
        review_deadline=now_utc - timedelta(minutes=5),
        evidence="Missing HSTS",
    )
    db.add(f2)
    db.commit()
    db.refresh(f2)

    # Trigger auto-approval scheduler
    count = check_and_auto_approve_expired_findings()
    assert count == 1

    db.refresh(f2)
    assert f2.status == "AUTO_APPROVED"
    assert f2.previous_state is not None
    snap2 = json.loads(f2.previous_state)
    assert snap2["status"] == "OPEN"

    # Rollback auto-approved finding via API
    res_roll2 = client.patch(f"/api/v1/findings/{f2.id}/rollback", headers=API_KEY_HEADERS)
    assert res_roll2.status_code == 200
    data_roll2 = res_roll2.json()
    assert data_roll2["status"] == "OPEN"
    assert data_roll2["approved_at"] is None
    assert data_roll2["approved_by"] is None

    app.dependency_overrides.clear()
    db.close()
