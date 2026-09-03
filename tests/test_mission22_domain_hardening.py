"""
Unit & Integration Tests for Mission 22: Domain Verification Hardening.
Part 1 — Rate limiting (Max 3 domain submissions per user per day).
Part 2 — Full audit trail logging (user_id, domain, method, timestamp, result).
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.services.auth_service import seed_default_organization_and_user, create_user_account
from backend.auth import create_access_token

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_domain_hardening_test_db():
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


def test_domain_submission_rate_limiting_max_3_per_day(setup_domain_hardening_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # Submissions 1, 2, 3 must succeed
    for i in range(1, 4):
        domain = f"test-target-{i}.com"
        res = client.post(
            "/api/v1/domains/submit",
            json={"domain": domain, "verification_method": "dns_txt"},
            headers=headers
        )
        assert res.status_code == 201, f"Submission {i} failed: {res.text}"
        data = res.json()
        assert data["domain"] == domain

    # Submission 4 must be rejected with HTTP 429 Rate Limited
    res_4th = client.post(
        "/api/v1/domains/submit",
        json={"domain": "test-target-4.com", "verification_method": "dns_txt"},
        headers=headers
    )
    assert res_4th.status_code == 429
    detail = res_4th.json().get("detail", "")
    assert "rate limit exceeded" in detail.lower() or "maximum 3" in detail.lower()


def test_full_audit_trail_logging(setup_domain_hardening_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # 1. Submit domain 1 (successful)
    sub1 = client.post(
        "/api/v1/domains/submit",
        json={"domain": "audit-corp-1.com", "verification_method": "dns_txt"},
        headers=headers
    )
    assert sub1.status_code == 201
    domain_1_id = sub1.json()["id"]

    # 2. Trigger failed verification check
    with patch("backend.services.domain_verification_service.verify_dns_txt_ownership", return_value=(False, "TXT token mismatch")):
        verify_fail = client.post(
            f"/api/v1/domains/{domain_1_id}/verify",
            json={"verification_method": "dns_txt"},
            headers=headers
        )
        assert verify_fail.status_code == 200
        assert verify_fail.json()["status"] == "FAILED"

    # 3. Trigger successful verification check
    with patch("backend.services.domain_verification_service.verify_dns_txt_ownership", return_value=(True, "TXT verified")):
        verify_pass = client.post(
            f"/api/v1/domains/{domain_1_id}/verify",
            json={"verification_method": "dns_txt"},
            headers=headers
        )
        assert verify_pass.status_code == 200
        assert verify_pass.json()["status"] == "VERIFIED"

    # 4. Fetch full audit log
    audit_res = client.get("/api/v1/domains/audit-log", headers=headers)
    assert audit_res.status_code == 200
    audit_entries = audit_res.json()

    assert len(audit_entries) >= 3

    # Check fields of audit entries
    results = [entry["result"] for entry in audit_entries]
    domains = [entry["domain"] for entry in audit_entries]

    assert "SUBMITTED" in results
    assert "FAILED" in results
    assert "VERIFIED" in results
    assert all("audit-corp-1.com" in d for d in domains)

    for entry in audit_entries:
        assert "user_id" in entry
        assert "domain" in entry
        assert "method" in entry
        assert "timestamp" in entry
        assert "result" in entry


def test_rate_limit_and_audit_logged_for_rate_limited_attempt(setup_domain_hardening_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # Fill up limit of 3
    for i in range(1, 4):
        client.post("/api/v1/domains/submit", json={"domain": f"lim-domain-{i}.com"}, headers=headers)

    # 4th attempt (rejected)
    res_exceeded = client.post("/api/v1/domains/submit", json={"domain": "lim-domain-4.com"}, headers=headers)
    assert res_exceeded.status_code == 429

    # Verify RATE_LIMITED audit entry was persisted
    audit_res = client.get("/api/v1/domains/audit-log", headers=headers)
    audit_entries = audit_res.json()
    rate_limited_entry = next((e for e in audit_entries if e["result"] == "RATE_LIMITED"), None)

    assert rate_limited_entry is not None
    assert rate_limited_entry["domain"] == "lim-domain-4.com"
    assert "exceeded" in rate_limited_entry["details"].lower()
