"""
Unit tests for Mission 14 — Organization-Level Backend Hardening (/api/v1/ Versioning, X-API-Key Auth, Rate Limiting, Error Handling).
"""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_test_db():
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
    yield
    app.dependency_overrides.clear()


def test_api_v1_healthcheck():
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "v1"


def test_state_changing_endpoint_requires_api_key():
    client = TestClient(app)
    # Without X-API-Key -> 401 Unauthorized
    res = client.post("/api/v1/scan", json={"target": "http://localhost:3000"})
    assert res.status_code == 401
    data = res.json()
    assert "error" in data
    assert "X-API-Key" in data["detail"]

    # With invalid X-API-Key -> 401 Unauthorized
    res = client.post("/api/v1/scan", json={"target": "http://localhost:3000"}, headers={"X-API-Key": "wrong_key"})
    assert res.status_code == 401


from unittest.mock import patch

def test_state_changing_endpoint_with_valid_api_key():
    client = TestClient(app)
    with patch("backend.routers.scans.run_scan_pipeline_background"):
        res = client.post(
            "/api/v1/scan",
            json={"target": "http://localhost:3000"},
            headers={"X-API-Key": VALID_API_KEY}
        )
        assert res.status_code == 201
        data = res.json()
        assert "id" in data
        assert data["target"] == "http://localhost:3000"


def test_global_exception_handler_shape():
    client = TestClient(app)
    res = client.get("/api/v1/scan/9999999")
    assert res.status_code == 404
    data = res.json()
    assert data["error"] == "HTTPException"
    assert data["status_code"] == 404
    assert "not found" in data["detail"].lower()
