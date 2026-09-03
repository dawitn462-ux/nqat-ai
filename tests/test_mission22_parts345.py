"""
Unit & Integration Tests for Mission 22 Parts 3, 4 & 5:
- Part 3: Re-verification check before scheduled continuous-monitoring re-scans.
- Part 4: 30-day verification expiry enforcement.
- Part 5: Audit logging and scan pause verification upon re-verification failure or expiry.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import DomainTarget, DomainVerificationStatus, DomainVerificationMethod, DomainAuditLog, Scan
from backend.services.auth_service import seed_default_organization_and_user
from backend.services.continuous_monitoring_scheduler import run_continuous_monitoring_cycle

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_parts345_test_db():
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


def test_part3_and_part5_reverification_failure_pauses_rescan_and_logs_audit(setup_parts345_test_db):
    TestingSessionLocal, _ = setup_parts345_test_db
    db = TestingSessionLocal()

    # 1. Create a VERIFIED domain target
    domain_rec = DomainTarget(
        organization_id=1,
        domain="challenge-removed.org",
        target_url="http://challenge-removed.org",
        verification_token="nkat-verify-token123",
        verification_method="dns_txt",
        status=DomainVerificationStatus.VERIFIED.value,
        verified_at=datetime.now(timezone.utc)
    )
    db.add(domain_rec)
    db.commit()
    domain_id = domain_rec.id

    # 2. Mock DNS re-verification returning FAILURE (token was deleted by domain owner)
    with patch("backend.services.domain_verification_service.verify_dns_txt_ownership", return_value=(False, "TXT record _nkat-challenge.challenge-removed.org not found")):
        with patch("backend.services.continuous_monitoring_scheduler.SessionLocal", return_value=db):
            notif_count = run_continuous_monitoring_cycle()

    # 3. Verify domain target status was updated to FAILED and scan was skipped
    rec_after = db.query(DomainTarget).filter(DomainTarget.id == domain_id).first()
    assert rec_after.status == DomainVerificationStatus.FAILED.value
    assert "TXT record" in rec_after.last_error

    scans = db.query(Scan).filter(Scan.target == "http://challenge-removed.org").all()
    assert len(scans) == 0, "Scan must be skipped for domain targets failing re-verification!"

    # 4. Verify audit log contains FAILED_REVERIFICATION entry with explanation
    audit_logs = db.query(DomainAuditLog).filter(DomainAuditLog.domain == "challenge-removed.org").all()
    fail_audit = next((a for a in audit_logs if a.result == "FAILED_REVERIFICATION"), None)

    assert fail_audit is not None
    assert "failed" in fail_audit.details.lower() or "missing" in fail_audit.details.lower()
    db.close()


def test_part4_30_day_verification_expiry_blocks_scans(setup_parts345_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    TestingSessionLocal, _ = setup_parts345_test_db
    db = TestingSessionLocal()

    # 1. Create a domain target verified 31 days ago (>30 days expiry)
    expired_time = datetime.now(timezone.utc) - timedelta(days=31)
    domain_rec = DomainTarget(
        organization_id=1,
        domain="expired-corp.com",
        target_url="http://expired-corp.com",
        verification_token="nkat-verify-expired999",
        verification_method="dns_txt",
        status=DomainVerificationStatus.VERIFIED.value,
        verified_at=expired_time
    )
    db.add(domain_rec)
    db.commit()
    expired_id = domain_rec.id

    # 2. Manual scan attempt via API MUST be rejected with HTTP 403
    scan_res = client.post("/api/v1/scan", json={"target": "http://expired-corp.com"}, headers=headers)
    assert scan_res.status_code == 403
    assert "EXPIRED" in scan_res.json().get("detail", "") or "re-verification" in scan_res.json().get("detail", "").lower()

    # 3. Scheduled continuous monitoring re-scan cycle MUST skip expired target
    with patch("backend.services.continuous_monitoring_scheduler.SessionLocal", return_value=db):
        run_continuous_monitoring_cycle()

    expired_after = db.query(DomainTarget).filter(DomainTarget.id == expired_id).first()
    assert expired_after.status == DomainVerificationStatus.EXPIRED.value

    scans = db.query(Scan).filter(Scan.target == "http://expired-corp.com").all()
    assert len(scans) == 0, "Scan must be skipped for expired domain targets!"

    # 4. Confirm EXPIRED audit log entry was created
    audit_logs = db.query(DomainAuditLog).filter(DomainAuditLog.domain == "expired-corp.com").all()
    expired_audit = next((a for a in audit_logs if a.result == "EXPIRED"), None)
    assert expired_audit is not None
    assert "30 days" in expired_audit.details.lower()
    db.close()


def test_part3_successful_reverification_allows_rescan(setup_parts345_test_db):
    TestingSessionLocal, _ = setup_parts345_test_db
    db = TestingSessionLocal()

    # 1. Create a VERIFIED domain target
    domain_rec = DomainTarget(
        organization_id=1,
        domain="active-rescan-target.org",
        target_url="http://active-rescan-target.org",
        verification_token="nkat-verify-active123",
        verification_method="dns_txt",
        status=DomainVerificationStatus.VERIFIED.value,
        verified_at=datetime.now(timezone.utc) - timedelta(days=2)
    )
    db.add(domain_rec)
    db.commit()
    active_id = domain_rec.id

    async def mock_execute_scan(s_id, t_url):
        pass

    # 2. Mock DNS re-verification returning SUCCESS
    with patch("backend.services.domain_verification_service.verify_dns_txt_ownership", return_value=(True, "Verified DNS TXT")):
        with patch("backend.services.scan_service._execute_scan_async", side_effect=mock_execute_scan):
            with patch("backend.services.continuous_monitoring_scheduler.SessionLocal", return_value=db):
                run_continuous_monitoring_cycle()

    # 3. Verify scan record was dispatched and status updated
    active_after = db.query(DomainTarget).filter(DomainTarget.id == active_id).first()
    assert active_after.status == DomainVerificationStatus.VERIFIED.value

    scans = db.query(Scan).filter(Scan.target == "http://active-rescan-target.org").all()
    assert len(scans) == 1

    # 4. Verify REVERIFIED audit entry
    audit_logs = db.query(DomainAuditLog).filter(DomainAuditLog.domain == "active-rescan-target.org").all()
    reverified_audit = next((a for a in audit_logs if a.result == "REVERIFIED"), None)
    assert reverified_audit is not None
    db.close()

