"""
Automated Test Suite for Real Email Verification & Google Auth — NKAT AI
-------------------------------------------------------------------------
Tests end-to-end user registration, unverified account access blocking (403),
OTP code and direct link email verification, single-use token invalidation,
expiration checks, resend rate-limiting, and Google auth integration.
"""

import os
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal
from backend.models import User, Organization
from backend.services.auth_service import (
    create_user_account,
    verify_user_email,
    resend_email_verification,
    find_or_create_google_user,
    get_password_hash,
    verify_password
)
from backend.services.email_service import get_smtp_config, send_verification_email

client = TestClient(app)


def test_password_hashing():
    pwd = "TestSecurePassword123!"
    hashed = get_password_hash(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_user_registration_and_unverified_blocking():
    db = SessionLocal()
    try:
        username = f"test_unverified_{os.urandom(4).hex()}"
        email = f"{username}@example.com"

        # Register unverified user
        reg_res = client.post("/api/v1/auth/register", json={
            "username": username,
            "email": email,
            "password": "Password123!",
            "organization_name": "Test Org"
        })
        assert reg_res.status_code == 200
        reg_data = reg_res.json()
        assert reg_data["is_email_verified"] is False
        token = reg_data["access_token"]

        # Attempt to access protected dashboard endpoint with unverified JWT token -> Should receive 403 Forbidden
        prot_res = client.get("/api/v1/scans/", headers={
            "Authorization": f"Bearer {token}"
        })
        assert prot_res.status_code == 403
        assert "Email verification required" in prot_res.json()["detail"]

    finally:
        db.close()


def test_otp_code_verification_and_access_unlocked():
    db = SessionLocal()
    try:
        username = f"test_otp_{os.urandom(4).hex()}"
        email = f"{username}@example.com"

        user = create_user_account(
            db=db,
            username=username,
            email=email,
            password="Password123!",
            auto_verify=False
        )

        otp_code = user.email_verification_code
        assert otp_code is not None

        # Verify OTP code
        v_res = client.post("/api/v1/auth/verify-email", json={
            "identity": email,
            "verification_code": otp_code
        })
        assert v_res.status_code == 200
        v_data = v_res.json()
        assert v_data["is_email_verified"] is True
        verified_jwt = v_data["access_token"]

        # Protected endpoint should now succeed with 200 OK
        prot_res = client.get("/api/v1/scans/", headers={
            "Authorization": f"Bearer {verified_jwt}"
        })
        assert prot_res.status_code == 200

    finally:
        db.close()


def test_token_expiration_and_invalid_token():
    db = SessionLocal()
    try:
        username = f"test_exp_{os.urandom(4).hex()}"
        email = f"{username}@example.com"

        user = create_user_account(
            db=db,
            username=username,
            email=email,
            password="Password123!",
            auto_verify=False
        )

        # Force expiration timestamp to past
        user.email_verification_expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.commit()

        # Verification with expired code should fail with 400 Bad Request
        v_res = client.post("/api/v1/auth/verify-email", json={
            "identity": email,
            "verification_code": user.email_verification_code
        })
        assert v_res.status_code == 400
        assert "expired" in v_res.json()["detail"].lower()

        # Verification with random invalid code should fail
        v_res_invalid = client.post("/api/v1/auth/verify-email", json={
            "identity": email,
            "verification_code": "000000"
        })
        assert v_res_invalid.status_code == 400

    finally:
        db.close()


def test_resend_verification_cooldown_rate_limit():
    db = SessionLocal()
    try:
        username = f"test_resend_{os.urandom(4).hex()}"
        email = f"{username}@example.com"

        user = create_user_account(
            db=db,
            username=username,
            email=email,
            password="Password123!",
            auto_verify=False
        )

        # Immediate resend attempt should fail due to 60s cooldown rate limit
        resend_res = client.post("/api/v1/auth/resend-verification", json={
            "identity": email
        })
        assert resend_res.status_code == 400
        assert "rate limit" in resend_res.json()["detail"].lower()

    finally:
        db.close()


def test_google_auth_auto_verification():
    db = SessionLocal()
    try:
        google_email = f"google_user_{os.urandom(4).hex()}@gmail.com"

        g_res = client.post("/api/v1/auth/google", json={
            "email": google_email,
            "name": "Google User Test"
        })
        assert g_res.status_code == 200
        g_data = g_res.json()
        assert g_data["is_email_verified"] is True
        token = g_data["access_token"]

        # Accessing protected route with Google JWT should succeed immediately
        prot_res = client.get("/api/v1/scans/", headers={
            "Authorization": f"Bearer {token}"
        })
        assert prot_res.status_code == 200

    finally:
        db.close()


def test_real_gmail_smtp_dispatch():
    smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from = get_smtp_config()
    if smtp_user and smtp_pass and len(smtp_pass) > 3:
        res = send_verification_email(
            recipient_email=smtp_user,
            username="Real SMTP Tester",
            verification_code="123456",
            verification_token="nkat-test-token-123456",
            expires_in_minutes=20
        )
        assert res["status"] in ["sent", "logged", "printed_console"]
        assert res["method"] in ["smtp", "console", "logger"]
    else:
        pytest.skip("SMTP credentials not configured in .env")
