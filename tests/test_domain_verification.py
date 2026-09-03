"""
Unit and Integration Tests for Website Submission + Mandatory Ownership Verification (Part 2).
Tests domain submission, challenge token generation, DNS TXT & HTTP File verification,
scoped authorized target enforcement, 403 rejection for unverified targets, and scan pipeline dispatch for verified targets.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.services.auth_service import seed_default_organization_and_user

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_domain_test_db():
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


def test_domain_submission_creates_token_and_instructions(setup_domain_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    res = client.post(
        "/api/v1/domains/submit",
        json={"domain": "example-corp.com", "verification_method": "dns_txt"},
        headers=headers
    )
    assert res.status_code == 201
    data = res.json()

    assert data["domain"] == "example-corp.com"
    assert data["status"] == "PENDING"
    assert data["verification_token"].startswith("nkat-verify-")
    assert data["dns_txt_record_name"] == "_nkat-challenge.example-corp.com"
    assert data["dns_txt_record_value"] == data["verification_token"]
    assert "/.well-known/nkat-verification.txt" in data["file_verification_url"]


def test_unverified_domain_scan_rejected_with_403(setup_domain_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # Attempt scan against an unverified domain
    res = client.post(
        "/api/v1/scan",
        json={"target": "https://unverified-security-target.com"},
        headers=headers
    )
    assert res.status_code == 403
    detail = res.json().get("detail", "")
    assert "NOT authorized" in detail or "Mandatory ownership verification" in detail


def test_file_based_ownership_verification_success_and_scan_dispatch(setup_domain_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # 1. Submit domain
    submit_res = client.post(
        "/api/v1/domains/submit",
        json={"domain": "https://verified-company.org", "verification_method": "file"},
        headers=headers
    )
    assert submit_res.status_code == 201
    domain_obj = submit_res.json()
    domain_id = domain_obj["id"]
    token = domain_obj["verification_token"]

    # 2. Mock HTTP file verification returning success
    with patch("backend.services.domain_verification_service.verify_file_ownership", return_value=(True, "Verified HTTP File")):
        verify_res = client.post(
            f"/api/v1/domains/{domain_id}/verify",
            json={"verification_method": "file"},
            headers=headers
        )
        assert verify_res.status_code == 200
        v_data = verify_res.json()
        assert v_data["status"] == "VERIFIED"
        assert v_data["verified_at"] is not None

    # 3. Dispatch scan against newly verified domain (must now succeed!)
    with patch("backend.routers.scans.run_scan_pipeline_background"):
        scan_res = client.post(
            "/api/v1/scan",
            json={"target": "https://verified-company.org"},
            headers=headers
        )
        assert scan_res.status_code == 201
        scan_data = scan_res.json()
        assert scan_data["target"] == "https://verified-company.org"
        assert scan_data["status"] == "PENDING"


def test_dns_txt_ownership_verification_failure(setup_domain_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # 1. Submit domain
    submit_res = client.post(
        "/api/v1/domains/submit",
        json={"domain": "fail-target.net", "verification_method": "dns_txt"},
        headers=headers
    )
    domain_id = submit_res.json()["id"]

    # 2. Mock DNS verification returning failure
    with patch("backend.services.domain_verification_service.verify_dns_txt_ownership", return_value=(False, "TXT record not found")):
        verify_res = client.post(
            f"/api/v1/domains/{domain_id}/verify",
            json={"verification_method": "dns_txt"},
            headers=headers
        )
        assert verify_res.status_code == 200
        data = verify_res.json()
        assert data["status"] == "FAILED"
        assert "TXT record not found" in data["last_error"]

    # Scan attempt on failed domain target must be rejected
    scan_res = client.post(
        "/api/v1/scan",
        json={"target": "http://fail-target.net"},
        headers=headers
    )
    assert scan_res.status_code == 403


def test_list_and_delete_domains(setup_domain_test_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # Submit domain
    sub_res = client.post(
        "/api/v1/domains/submit",
        json={"domain": "to-be-deleted.com"},
        headers=headers
    )
    domain_id = sub_res.json()["id"]

    # List domains
    list_res = client.get("/api/v1/domains", headers=headers)
    assert list_res.status_code == 200
    domains = list_res.json()
    assert any(d["id"] == domain_id for d in domains)

    # Delete domain
    del_res = client.delete(f"/api/v1/domains/{domain_id}", headers=headers)
    assert del_res.status_code == 204

    # Verify domain is removed
    list_res2 = client.get("/api/v1/domains", headers=headers)
    domains2 = list_res2.json()
    assert not any(d["id"] == domain_id for d in domains2)
