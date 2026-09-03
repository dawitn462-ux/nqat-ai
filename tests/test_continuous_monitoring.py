"""
Unit and Integration Tests for Part 3 — Continuous Monitoring + In-App Notifications.
Tests notification DB persistence, API endpoints (GET, PATCH read, POST read-all, DELETE),
continuous monitoring re-scan cycle, and new-finding detection logic.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import DomainTarget, DomainVerificationStatus, InAppNotification, Finding, Subdomain, Scan, ScanStatus
from backend.services.auth_service import seed_default_organization_and_user
from backend.services.continuous_monitoring_scheduler import run_continuous_monitoring_cycle, start_continuous_monitoring_scheduler, shutdown_continuous_monitoring_scheduler

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_monitoring_test_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    db = TestingSessionLocal()
    seed_res = seed_default_organization_and_user(db)
    org_id = seed_res["organization_id"]
    db.close()

    yield TestingSessionLocal, engine, org_id
    app.dependency_overrides.clear()


def test_notification_api_lifecycle(setup_monitoring_test_db):
    TestingSessionLocal, _, org_id = setup_monitoring_test_db
    db = TestingSessionLocal()

    # Create dummy notifications directly in DB
    n1 = InAppNotification(
        organization_id=org_id,
        title="NEW HIGH FINDING: SQL Injection",
        message="New SQL Injection vulnerability detected.",
        severity="HIGH",
        is_read=False
    )
    n2 = InAppNotification(
        organization_id=org_id,
        title="NEW CRITICAL FINDING: Remote Code Execution",
        message="RCE detected on target server.",
        severity="CRITICAL",
        is_read=False
    )
    db.add_all([n1, n2])
    db.commit()
    db.refresh(n1)
    db.refresh(n2)

    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # 1. GET /api/v1/notifications
    res = client.get("/api/v1/notifications", headers=headers)
    assert res.status_code == 200
    items = res.json()
    assert len(items) == 2

    # 2. GET /api/v1/notifications?unread_only=true
    unread_res = client.get("/api/v1/notifications?unread_only=true", headers=headers)
    assert unread_res.status_code == 200
    assert len(unread_res.json()) == 2

    # 3. PATCH /api/v1/notifications/{n1.id}/read
    patch_res = client.patch(f"/api/v1/notifications/{n1.id}/read", json={"is_read": True}, headers=headers)
    assert patch_res.status_code == 200
    assert patch_res.json()["is_read"] is True

    # Check unread count is now 1
    unread_res2 = client.get("/api/v1/notifications?unread_only=true", headers=headers)
    assert len(unread_res2.json()) == 1

    # 4. POST /api/v1/notifications/read-all
    read_all_res = client.post("/api/v1/notifications/read-all", headers=headers)
    assert read_all_res.status_code == 200

    unread_res3 = client.get("/api/v1/notifications?unread_only=true", headers=headers)
    assert len(unread_res3.json()) == 0

    # 5. DELETE /api/v1/notifications/{n2.id}
    del_res = client.delete(f"/api/v1/notifications/{n2.id}", headers=headers)
    assert del_res.status_code == 204

    db.close()


def test_continuous_monitoring_rescan_and_new_finding_detection(setup_monitoring_test_db):
    TestingSessionLocal, _, org_id = setup_monitoring_test_db
    db = TestingSessionLocal()

    # 1. Add VERIFIED DomainTarget
    domain_rec = DomainTarget(
        organization_id=org_id,
        domain="monitor-test.org",
        target_url="http://monitor-test.org",
        verification_token="nkat-verify-12345",
        verification_method="dns_txt",
        status=DomainVerificationStatus.VERIFIED.value
    )
    db.add(domain_rec)
    db.commit()
    domain_id = domain_rec.id

    # Mock _execute_scan_async to simulate a scan creating a new finding
    async def mock_execute_scan(scan_id, target_url):
        from backend.services.continuous_monitoring_scheduler import SessionLocal
        d = SessionLocal()
        sub = Subdomain(scan_id=scan_id, hostname="monitor-test.org", ip_address="127.0.0.1")
        d.add(sub)
        d.commit()
        d.refresh(sub)

        f = Finding(
            subdomain_id=sub.id,
            check_name="Missing Content-Security-Policy Header",
            severity="MEDIUM",
            evidence="CSP header missing",
            status="OPEN"
        )
        d.add(f)
        d.commit()

    with patch("backend.services.continuous_monitoring_scheduler.SessionLocal", return_value=db):
        with patch("backend.services.scan_service._execute_scan_async", side_effect=mock_execute_scan):
            notif_count = run_continuous_monitoring_cycle()
            assert notif_count >= 1

    # Check notification persisted
    notifs = db.query(InAppNotification).filter(InAppNotification.organization_id == org_id).all()
    assert len(notifs) >= 1
    assert "Missing Content-Security-Policy Header" in notifs[0].title
    assert notifs[0].domain_id == domain_id

    db.close()


def test_continuous_monitoring_scheduler_lifecycle():
    scheduler = start_continuous_monitoring_scheduler(interval_minutes=60)
    assert scheduler.running is True
    shutdown_continuous_monitoring_scheduler()
