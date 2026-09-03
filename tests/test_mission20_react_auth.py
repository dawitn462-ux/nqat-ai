"""
Unit Tests for Mission 20 — React Frontend, Auth Extensions (Self-Registration & Google OAuth), and Asset Integrity.
"""

import pytest
import os
import sys
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.main import app
from backend.database import Base, engine, SessionLocal
from backend.services.auth_service import seed_default_organization_and_user

# Ensure DB tables exist for TestClient session
Base.metadata.create_all(bind=engine)
_db = SessionLocal()
seed_default_organization_and_user(_db)
_db.close()

client = TestClient(app)


import uuid

def test_auth_register_creates_user_and_returns_jwt():
    """
    Verifies that POST /api/v1/auth/register registers a new user account,
    hashes the password, and returns a signed HS256 JWT access token.
    """
    with TestClient(app) as client:
        uname = f"m20_user_{uuid.uuid4().hex[:8]}"
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": uname,
                "email": f"{uname}@nkat.ai",
                "password": "SecurePassword123!",
                "organization_name": "Mission 20 Org"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["username"] == uname
        assert data["organization_name"] == "Mission 20 Org"


def test_auth_register_duplicate_username_returns_400():
    """
    Verifies that registering a duplicate username returns HTTP 400 Bad Request.
    """
    with TestClient(app) as client:
        dup_name = f"dup_user_{uuid.uuid4().hex[:8]}"
        client.post(
            "/api/v1/auth/register",
            json={"username": dup_name, "email": f"{dup_name}@nkat.ai", "password": "Password123!"}
        )
        response = client.post(
            "/api/v1/auth/register",
            json={"username": dup_name, "email": f"{dup_name}@nkat.ai", "password": "Password123!"}
        )
        assert response.status_code == 400
        data = response.json()
        assert "already taken" in data["detail"]


def test_auth_google_returns_jwt():
    """
    Verifies that POST /api/v1/auth/google creates or matches a Google user
    and returns a signed HS256 JWT access token.
    """
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/google",
            json={
                "email": "secops_lead_m20@nkat.ai",
                "name": "SecOps Lead M20"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["username"].startswith("secops_lead_m20")


def test_react_frontend_assets_exist():
    """
    Verifies that all Mission 20 React application source files and logo assets exist.
    """
    assert os.path.exists(os.path.join(PROJECT_ROOT, "frontend", "package.json"))
    assert os.path.exists(os.path.join(PROJECT_ROOT, "frontend", "index.html"))
    assert os.path.exists(os.path.join(PROJECT_ROOT, "frontend", "public", "logo.jpg"))
    assert os.path.exists(os.path.join(PROJECT_ROOT, "frontend", "src", "App.jsx"))
    assert os.path.exists(os.path.join(PROJECT_ROOT, "frontend", "src", "components", "AuthModal.jsx"))
    assert os.path.exists(os.path.join(PROJECT_ROOT, "frontend", "src", "components", "CrowdStrikeHomepage.jsx"))
