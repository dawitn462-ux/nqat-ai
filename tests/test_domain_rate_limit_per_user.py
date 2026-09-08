"""
Unit test confirming that domain verification token generation and target submission rate limits
are strictly enforced SEPARATELY per each user (3 per user per 24 hours).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.services.auth_service import seed_default_organization_and_user
from backend.auth import create_access_token
from backend.models import User


@pytest.fixture(autouse=True)
def setup_rate_limit_db():
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

    # Create User 2
    u2 = User(
        organization_id=1,
        email="user2@company.com",
        username="user2",
        password_hash="hash2",
        role="analyst",
        is_email_verified=True
    )
    db.add(u2)
    db.commit()
    db.refresh(u2)
    u2_id = u2.id
    db.close()

    yield TestingSessionLocal, engine, u2_id
    app.dependency_overrides.clear()


def test_per_user_domain_submission_token_rate_limit(setup_rate_limit_db):
    TestingSessionLocal, engine, u2_id = setup_rate_limit_db
    client = TestClient(app)

    token_user1 = create_access_token(data={"sub": "admin", "user_id": 1, "organization_id": 1, "role": "admin", "is_email_verified": True})
    token_user2 = create_access_token(data={"sub": "user2", "user_id": u2_id, "organization_id": 1, "role": "analyst", "is_email_verified": True})

    headers_u1 = {"Authorization": f"Bearer {token_user1}"}
    headers_u2 = {"Authorization": f"Bearer {token_user2}"}

    # User 1 submits 3 domains (reaching 3/3 quota)
    for i in range(1, 4):
        res = client.post("/api/v1/domains/submit", json={"domain": f"u1-target-{i}.com"}, headers=headers_u1)
        assert res.status_code == 201, f"User 1 submission {i} should succeed, got {res.status_code}"

    # User 1 quota check
    q_u1 = client.get("/api/v1/domains/quota", headers=headers_u1).json()
    assert q_u1["user_id"] == 1
    assert q_u1["used_24h"] == 3
    assert q_u1["remaining_24h"] == 0

    # User 1 attempts 4th domain -> MUST be rate limited (429)
    res_u1_fourth = client.post("/api/v1/domains/submit", json={"domain": "u1-target-4.com"}, headers=headers_u1)
    assert res_u1_fourth.status_code == 429
    assert "rate limit" in res_u1_fourth.json()["detail"].lower()

    # User 2 quota check prior to submission (0/3 used)
    q_u2_before = client.get("/api/v1/domains/quota", headers=headers_u2).json()
    assert q_u2_before["user_id"] == u2_id
    assert q_u2_before["used_24h"] == 0
    assert q_u2_before["remaining_24h"] == 3

    # User 2 submits 3 domains -> MUST succeed independently of User 1's limit!
    for i in range(1, 4):
        res = client.post("/api/v1/domains/submit", json={"domain": f"u2-target-{i}.com"}, headers=headers_u2)
        assert res.status_code == 201, f"User 2 submission {i} should succeed independently, got {res.status_code}"

    # User 2 quota check after 3 submissions
    q_u2_after = client.get("/api/v1/domains/quota", headers=headers_u2).json()
    assert q_u2_after["user_id"] == u2_id
    assert q_u2_after["used_24h"] == 3
    assert q_u2_after["remaining_24h"] == 0

    # User 2 attempts 4th domain -> MUST be rate limited (429)
    res_u2_fourth = client.post("/api/v1/domains/submit", json={"domain": "u2-target-4.com"}, headers=headers_u2)
    assert res_u2_fourth.status_code == 429
