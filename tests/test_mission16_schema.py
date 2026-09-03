"""
Unit tests for Mission 16 Part 1 — Local-First Multi-User Schema Structure
Defines & verifies:
- Organizations table & seeding ('Default Organization').
- Users table with passlib bcrypt password hashing (never stored as plain-text).
- UserRole enum ('admin', 'analyst', 'viewer').
- Foreign key relationships between Organization, User, and Scan models.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import Organization, User, UserRole, Scan, ScanStatus
from backend.services.auth_service import get_password_hash, verify_password, seed_default_organization_and_user


@pytest.fixture(autouse=True)
def setup_schema_test_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    yield TestingSessionLocal
    Base.metadata.drop_all(bind=engine)


def test_password_hashing_passlib():
    raw_pwd = "SuperSecretPassword2026!"
    hashed = get_password_hash(raw_pwd)
    
    assert hashed != raw_pwd
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    assert verify_password(raw_pwd, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_organization_and_user_models(setup_schema_test_db):
    TestingSessionLocal = setup_schema_test_db
    db = TestingSessionLocal()

    org = Organization(name="CyberSec Corp")
    db.add(org)
    db.commit()
    db.refresh(org)

    assert org.id is not None
    assert org.name == "CyberSec Corp"

    pwd_hash = get_password_hash("analyst_pwd")
    user = User(
        organization_id=org.id,
        username="analyst_jane",
        password_hash=pwd_hash,
        role=UserRole.ANALYST.value
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    assert user.id is not None
    assert user.organization_id == org.id
    assert user.role == "analyst"
    assert verify_password("analyst_pwd", user.password_hash) is True

    # Test Scan FK association
    scan = Scan(
        organization_id=org.id,
        target="http://localhost:3000",
        status=ScanStatus.COMPLETED.value
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    assert scan.organization_id == org.id
    assert scan.organization.name == "CyberSec Corp"

    db.close()


def test_seed_default_organization_and_user(setup_schema_test_db):
    TestingSessionLocal = setup_schema_test_db
    db = TestingSessionLocal()

    seed_res = seed_default_organization_and_user(db)
    assert seed_res["organization_id"] is not None
    assert seed_res["username"] == "admin"

    # Verify DB records
    org = db.query(Organization).filter(Organization.name == "Default Organization").first()
    assert org is not None

    admin_usr = db.query(User).filter(User.username == "admin").first()
    assert admin_usr is not None
    assert admin_usr.role == "admin"
    assert verify_password("admin_secret_2026", admin_usr.password_hash) is True

    db.close()
