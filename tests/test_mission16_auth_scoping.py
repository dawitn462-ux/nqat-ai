"""
Unit tests for Mission 16 Parts 2–4 — Local JWT Login, Endpoint Protection, and Organization Scoping.
"""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import Organization, User, UserRole, Scan, ScanStatus
from backend.services.auth_service import get_password_hash, seed_default_organization_and_user

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_auth_scoping_db():
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
    yield TestingSessionLocal, engine
    app.dependency_overrides.clear()


def test_login_and_organization_scan_scoping(setup_auth_scoping_db):
    TestingSessionLocal, _ = setup_auth_scoping_db
    db = TestingSessionLocal()

    # Seed Default Org and User
    seed_res = seed_default_organization_and_user(db)
    org_id = seed_res["organization_id"]

    client = TestClient(app)

    # 1. Login with valid credentials
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin_secret_2026"}
    )
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert token_data["organization_id"] == org_id
    token = token_data["access_token"]

    # 2. Trigger scan authenticated via Bearer JWT token
    headers = {"Authorization": f"Bearer {token}"}
    scan_res = client.post(
        "/api/v1/scan",
        json={"target": "http://localhost:3000"},
        headers=headers
    )
    assert scan_res.status_code == 201
    scan_obj = scan_res.json()
    assert scan_obj["organization_id"] == org_id

    # 3. Test invalid login credentials
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong_password"}
    )
    assert bad_login.status_code == 401

    db.close()


def test_unauthenticated_request_rejected(setup_auth_scoping_db):
    client = TestClient(app)
    # Attempt scan with no token and no API key
    res = client.post("/api/v1/scan", json={"target": "http://localhost:3000"})
    assert res.status_code == 401


def test_data_privacy_documentation_exists():
    privacy_doc_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs", "DATA_PRIVACY.md")
    assert os.path.exists(privacy_doc_path) is True
    with open(privacy_doc_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Single-Machine Local Operation" in content
        assert "Zero External Network Transmission" in content
