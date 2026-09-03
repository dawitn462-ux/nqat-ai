"""
Verification Test — Confirm third-party domains (owasp.org, google.com) are strictly REJECTED with HTTP 403.
---------------------------------------------------------------------------------------------------------
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.services.auth_service import seed_default_organization_and_user

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_rejection_db():
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


def test_owasp_org_scan_rejected_with_403(setup_rejection_db):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    # Attempting scan against unverified third-party domain http://owasp.org
    res_owasp = client.post("/api/v1/scan", json={"target": "http://owasp.org"}, headers=headers)
    assert res_owasp.status_code == 403, f"owasp.org scan should be rejected with 403, got {res_owasp.status_code}"
    detail_owasp = res_owasp.json().get("detail", "")
    assert "NOT authorized" in detail_owasp or "Mandatory ownership verification" in detail_owasp

    # Attempting scan against unverified third-party domain http://google.com
    res_google = client.post("/api/v1/scan", json={"target": "http://google.com"}, headers=headers)
    assert res_google.status_code == 403, f"google.com scan should be rejected with 403, got {res_google.status_code}"
    detail_google = res_google.json().get("detail", "")
    assert "NOT authorized" in detail_google or "Mandatory ownership verification" in detail_google
