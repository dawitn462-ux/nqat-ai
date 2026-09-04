"""
Part 5 End-to-End Test Suite — Full Platform Workflow Integration.
Verifies the complete end-to-end user lifecycle:
1. Signup & Account Registration (/api/v1/auth/register) -> JWT Token
2. Website Target Submission (/api/v1/domains/submit) -> Verification Challenge Token
3. Mandatory Target Ownership Verification (/api/v1/domains/{id}/verify) -> Status VERIFIED
4. Scan Pipeline Launch (/api/v1/scan) -> Authorized target scan dispatch
5. Continuous Monitoring & In-App Security Notifications (/api/v1/notifications) -> Alert generated & marked read
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
from backend.services.continuous_monitoring_scheduler import run_continuous_monitoring_cycle

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_e2e_db():
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
    seed_default_organization_and_user(db)
    db.close()

    yield TestingSessionLocal, engine
    app.dependency_overrides.clear()


def test_full_end_to_end_user_workflow(setup_e2e_db):
    client = TestClient(app)

    # -------------------------------------------------------------
    # Step 1: User Signup & Registration -> Receive Bearer JWT Token
    # -------------------------------------------------------------
    reg_payload = {
        "username": "e2e_security_analyst",
        "email": "analyst@e2e-cyber.org",
        "password": "StrongE2EPassword2026!",
        "organization_name": "E2E Cyber Defense Corp"
    }
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 200, f"Registration failed: {reg_res.text}"
    auth_data = reg_res.json()
    assert "access_token" in auth_data
    jwt_token = auth_data["access_token"]
    org_id = auth_data["organization_id"]
    assert auth_data["username"] == "e2e_security_analyst"

    # Step 1.5: Verify User Email (required for dashboard & domain submission)
    from backend.models import User
    from backend.auth import create_access_token
    TestingSessionLocal, _ = setup_e2e_db
    db = TestingSessionLocal()
    user_rec = db.query(User).filter(User.username == "e2e_security_analyst").first()
    if user_rec:
        user_rec.is_email_verified = True
        db.commit()
        jwt_token = create_access_token({
            "user_id": user_rec.id,
            "username": user_rec.username,
            "role": user_rec.role,
            "organization_id": org_id,
            "is_email_verified": True
        })
        auth_headers = {"Authorization": f"Bearer {jwt_token}"}
    db.close()

    # -------------------------------------------------------------
    # Step 2: Website Submission -> Receive Challenge Token
    # -------------------------------------------------------------
    sub_payload = {
        "domain": "e2e-target.org",
        "verification_method": "file"
    }
    sub_res = client.post("/api/v1/domains/submit", json=sub_payload, headers=auth_headers)
    assert sub_res.status_code == 201, f"Domain submission failed: {sub_res.text}"
    domain_data = sub_res.json()
    domain_id = domain_data["id"]
    challenge_token = domain_data["verification_token"]
    assert domain_data["status"] == "PENDING"
    assert challenge_token.startswith("nkat-verify-")

    # Confirm unverified scan attempt is rejected with 403 Forbidden
    unverified_scan_res = client.post("/api/v1/scan", json={"target": "http://e2e-target.org"}, headers=auth_headers)
    assert unverified_scan_res.status_code == 403
    assert "NOT authorized" in unverified_scan_res.json().get("detail", "")

    # -------------------------------------------------------------
    # Step 3: Mandatory Domain Ownership Verification
    # -------------------------------------------------------------
    with patch("backend.services.domain_verification_service.verify_file_ownership", return_value=(True, "Ownership file verified")):
        verify_res = client.post(f"/api/v1/domains/{domain_id}/verify", json={"verification_method": "file"}, headers=auth_headers)
        assert verify_res.status_code == 200, f"Domain verification failed: {verify_res.text}"
        verified_data = verify_res.json()
        assert verified_data["status"] == "VERIFIED"
        assert verified_data["verified_at"] is not None

    # -------------------------------------------------------------
    # Step 4: Dispatch Autonomous Scan for Verified Domain
    # -------------------------------------------------------------
    with patch("backend.routers.scans.run_scan_pipeline_background"):
        scan_res = client.post("/api/v1/scan", json={"target": "http://e2e-target.org"}, headers=auth_headers)
        assert scan_res.status_code == 201, f"Scan dispatch failed: {scan_res.text}"
        scan_data = scan_res.json()
        scan_id = scan_data["id"]
        assert scan_data["target"] == "http://e2e-target.org"
        assert scan_data["organization_id"] == org_id

    # -------------------------------------------------------------
    # Step 5: Continuous Monitoring & In-App Security Notifications
    # -------------------------------------------------------------
    # Simulate a monitoring cycle detecting a new vulnerability
    TestingSessionLocal, _ = setup_e2e_db
    db = TestingSessionLocal()

    async def mock_execute_scan(s_id, t_url):
        sub = Subdomain(scan_id=s_id, hostname="e2e-target.org", ip_address="127.0.0.1")
        db.add(sub)
        db.commit()

        f = Finding(
            subdomain_id=sub.id,
            check_name="SQL Injection in Login Component",
            severity="CRITICAL",
            evidence="' OR '1'='1 parameter injection",
            status="OPEN"
        )
        db.add(f)
        db.commit()

    with patch("backend.services.continuous_monitoring_scheduler.SessionLocal", return_value=db):
        with patch("backend.services.scan_service._execute_scan_async", side_effect=mock_execute_scan):
            with patch("backend.services.domain_verification_service.verify_file_ownership", return_value=(True, "Re-verified")):
                notif_count = run_continuous_monitoring_cycle()
                assert notif_count >= 1

    # Retrieve notifications via API authenticated with user JWT
    notif_res = client.get("/api/v1/notifications", headers=auth_headers)
    assert notif_res.status_code == 200
    notif_list = notif_res.json()
    assert len(notif_list) >= 1

    target_notif = notif_list[0]
    assert "SQL Injection" in target_notif["title"]
    assert target_notif["severity"] == "CRITICAL"
    assert target_notif["is_read"] is False

    # Mark notification as read via API
    notif_id = target_notif["id"]
    read_res = client.patch(f"/api/v1/notifications/{notif_id}/read", json={"is_read": True}, headers=auth_headers)
    assert read_res.status_code == 200
    assert read_res.json()["is_read"] is True

    # Verify unread count is now 0
    unread_res = client.get("/api/v1/notifications?unread_only=true", headers=auth_headers)
    assert unread_res.status_code == 200
    assert len(unread_res.json()) == 0

    db.close()
