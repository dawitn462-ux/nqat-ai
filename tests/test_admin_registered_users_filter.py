import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal
from backend.models import User, Organization
from backend.services.auth_service import seed_default_organization_and_user

client = TestClient(app)

def test_admin_registered_users_filter():
    db = SessionLocal()
    try:
        seed_default_organization_and_user(db)
        
        headers = {"X-API-Key": "nkat_secret_api_key_2026"}

        # 1. Fetch registered users only (default registered_only=true)
        res_registered = client.get("/api/v1/admin/users?registered_only=true", headers=headers)
        assert res_registered.status_code == 200
        registered_users = res_registered.json()
        assert isinstance(registered_users, list)
        
        # Verify default system admin ('admin') is NOT in registered_users
        admin_in_registered = [u for u in registered_users if u["username"] == "admin"]
        assert len(admin_in_registered) == 0

        # 2. Fetch all users (registered_only=false)
        res_all = client.get("/api/v1/admin/users?registered_only=false", headers=headers)
        assert res_all.status_code == 200
        all_users = res_all.json()
        
        # Verify default system admin ('admin') IS in all_users
        admin_in_all = [u for u in all_users if u["username"] == "admin"]
        assert len(admin_in_all) == 1
        assert admin_in_all[0]["is_default"] is True
    finally:
        db.close()
