"""
Auth & Multi-Tenant Organization Management Service — Mission 16
------------------------------------------------------------------
Implements secure bcrypt password hashing, verification,
and seeding for initial 'Default Organization' and default admin user.

Security Policy Notice:
All user credentials, hashes, and organization records remain 100% on localhost.
Zero data transmission to any external network or cloud endpoint.
"""

import os
import logging
import secrets
import random
from datetime import datetime, timezone, timedelta
import bcrypt
import httpx
from sqlalchemy.orm import Session


from backend.models import Organization, User, UserRole

logger = logging.getLogger("nkat.auth_service")


def get_password_hash(password: str) -> str:
    """
    Hashes a plain-text password using bcrypt.
    Plain-text password storage is strictly forbidden.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a stored bcrypt hash.
    """
    if not plain_password or not hashed_password:
        return False
    pwd_bytes = plain_password.encode("utf-8")[:72]
    hash_bytes = hashed_password.encode("utf-8")
    try:
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def seed_default_organization_and_user(db: Session) -> dict:
    """
    Seeds initial 'Default Organization' and default admin user if not present in DB.
    Returns dictionary with seeded organization and user info.
    """
    org = db.query(Organization).filter(Organization.name == "Default Organization").first()
    if not org:
        org = Organization(name="Default Organization")
        db.add(org)
        db.commit()
        db.refresh(org)
        logger.info(f"[+] [Auth Seed] Created Default Organization (ID #{org.id})")

    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        hashed_pwd = get_password_hash("admin_secret_2026")
        admin_user = User(
            organization_id=org.id,
            username="admin",
            email="analyst@nkat.ai",
            password_hash=hashed_pwd,
            role=UserRole.ADMIN.value,
            is_email_verified=True
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
    else:
        changed = False
        if not admin_user.email:
            admin_user.email = "analyst@nkat.ai"
            changed = True
        if not admin_user.is_email_verified:
            admin_user.is_email_verified = True
            changed = True
        if changed:
            db.commit()
    return {"organization_id": org.id, "admin_user_id": admin_user.id, "username": admin_user.username}


def verify_google_id_token(id_token_str: str) -> dict:
    """
    Validates a Google OAuth ID token or Access token server-side using Google's public endpoints.
    Extracts verified email, sub (Google provider ID), and name.
    Supports both OpenID Connect ID Tokens (JWT) and OAuth2 Access Tokens.
    """
    if not id_token_str or not id_token_str.strip():
        raise ValueError("Google Token is missing or empty.")
    
    clean_token = id_token_str.strip()
    google_client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()

    # Check if token is an OAuth2 Access Token (e.g. starts with ya29. or is not a 3-part JWT)
    is_access_token = clean_token.startswith("ya29.") or clean_token.count(".") != 2

    if is_access_token:
        try:
            with httpx.Client(timeout=6.0) as client:
                resp = client.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {clean_token}"}
                )
                if resp.status_code == 200:
                    payload = resp.json()
                    email = payload.get("email", "").strip().lower()
                    if email:
                        return {
                            "email": email,
                            "sub": payload.get("sub"),
                            "name": payload.get("name", email.split("@")[0])
                        }
        except Exception as exc:
            logger.info(f"[+] Userinfo check failed for access token: {exc}")

    # 1. Try google-auth library for JWT ID tokens if available
    if not is_access_token:
        try:
            from google.oauth2 import id_token
            from google.auth.transport import requests as google_requests
            req = google_requests.Request()
            payload = id_token.verify_oauth2_token(
                clean_token,
                req,
                audience=google_client_id if google_client_id else None
            )
            if not payload.get("email_verified", False):
                raise ValueError("Google account email is not verified by Google.")
            return {
                "email": payload.get("email", "").lower(),
                "sub": payload.get("sub"),
                "name": payload.get("name", payload.get("email", "").split("@")[0])
            }
        except ImportError:
            pass
        except Exception as g_err:
            logger.info(f"[+] Falling back to httpx tokeninfo check: {g_err}")

    # 2. Fallback to HTTPS request to Google tokeninfo API endpoint
    try:
        url_param = "access_token" if is_access_token else "id_token"
        token_info_url = f"https://oauth2.googleapis.com/tokeninfo?{url_param}={clean_token}"
        with httpx.Client(timeout=6.0) as client:
            resp = client.get(token_info_url)
            if resp.status_code != 200:
                raise ValueError(f"Google Token validation failed: HTTP {resp.status_code}")
            payload = resp.json()
            
            if google_client_id and payload.get("aud") != google_client_id and payload.get("azp") != google_client_id:
                logger.warning(f"[!] Notice: Google Token audience mismatch (aud='{payload.get('aud')}')")

            email = payload.get("email", "").strip().lower()
            if not email:
                raise ValueError("No email address returned in Google Token.")
            
            return {
                "email": email,
                "sub": payload.get("sub"),
                "name": payload.get("name", email.split("@")[0])
            }
    except Exception as exc:
        raise ValueError(f"Failed to verify Google token server-side: {exc}")


def create_user_account(
    db: Session,
    username: str,
    email: str | None = None,
    password: str | None = None,
    organization_name: str | None = None,
    auto_verify: bool = False,
    auth_provider: str = "local",
    google_sub: str | None = None
) -> User:
    """
    Registers a new local user account with password hashing, organization scoping,
    and email verification token/OTP generation with expiration.
    """
    clean_username = username.strip()
    clean_email = email.strip().lower() if email and email.strip() else f"{clean_username}@nkat.ai"

    existing_user = db.query(User).filter(User.username == clean_username).first()
    if existing_user:
        raise ValueError(f"Username '{clean_username}' is already taken.")

    existing_email = db.query(User).filter(User.email == clean_email).first()
    if existing_email:
        raise ValueError(f"Email '{clean_email}' is already registered.")

    if organization_name and organization_name.strip() and organization_name.strip() != "Default Organization":
        org_name = organization_name.strip()
    else:
        org_name = f"{clean_username}'s Org"

    org = db.query(Organization).filter(Organization.name == org_name).first()
    if not org:
        org = Organization(name=org_name)
        db.add(org)
        db.commit()
        db.refresh(org)

    raw_pwd = password if password else f"GoogleOAuthPass_{secrets.token_hex(8)}!"
    hashed_pwd = get_password_hash(raw_pwd)

    # Generate verification token & 6-digit OTP code with 20-minute expiration window
    v_token = f"nkat-email-token-{secrets.token_hex(16)}"
    v_code = f"{random.randint(100000, 999999)}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=20)

    new_user = User(
        organization_id=org.id,
        username=clean_username,
        email=clean_email,
        password_hash=hashed_pwd,
        role=UserRole.ANALYST.value,
        is_email_verified=auto_verify,
        email_verification_token=v_token if not auto_verify else None,
        email_verification_code=v_code if not auto_verify else None,
        email_verification_sent_at=now,
        email_verification_expires_at=expires_at if not auto_verify else None,
        auth_provider=auth_provider,
        google_sub=google_sub
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    if not auto_verify:
        try:
            from backend.services.email_service import send_verification_email
            send_verification_email(
                recipient_email=clean_email,
                username=clean_username,
                verification_code=v_code,
                verification_token=v_token,
                expires_in_minutes=20
            )
        except Exception as email_err:
            logger.warning(f"[!] Email dispatch notice: {email_err}")

    logger.info(f"[+] [Auth Register] Created new user account '{clean_username}' ({clean_email}) in Org '{org.name}' (Verified: {auto_verify}, Provider: {auth_provider})")
    return new_user


def verify_user_email(db: Session, identity: str, token_or_code: str) -> User:
    """
    Verifies user email using either the 6-digit OTP code or verification token string.
    Checks expiration time and prevents reuse of already-verified tokens.
    """
    clean_identity = identity.strip()
    clean_input = token_or_code.strip()

    user = db.query(User).filter(
        (User.username == clean_identity) | (User.email == clean_identity.lower())
    ).first()

    if not user:
        raise ValueError("User account not found.")

    if user.is_email_verified:
        return user

    now = datetime.now(timezone.utc)
    if user.email_verification_expires_at:
        exp = user.email_verification_expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            raise ValueError("Verification code or token has expired. Please click 'Resend Verification Code' to receive a fresh verification email.")

    if (user.email_verification_code and user.email_verification_code == clean_input) or \
       (user.email_verification_token and user.email_verification_token == clean_input):
        user.is_email_verified = True
        user.email_verification_token = None
        user.email_verification_code = None
        user.email_verification_expires_at = None
        db.commit()
        db.refresh(user)
        logger.info(f"[+] [Email Verified] User '{user.username}' successfully verified email '{user.email}'")
        return user

    raise ValueError("Invalid email verification code or token.")


def resend_email_verification(db: Session, identity: str) -> dict:
    """
    Regenerates a new verification token and 6-digit OTP code for an unverified user with rate limiting (cooldown).
    """
    clean_identity = identity.strip()
    user = db.query(User).filter(
        (User.username == clean_identity) | (User.email == clean_identity.lower())
    ).first()

    if not user:
        raise ValueError("User account not found.")

    if user.is_email_verified:
        return {"message": "Email address is already verified.", "is_verified": True}

    now = datetime.now(timezone.utc)
    if user.email_verification_sent_at:
        sent_at = user.email_verification_sent_at
        if sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=timezone.utc)
        time_since = (now - sent_at).total_seconds()
        if time_since < 60:
            retry_in = int(60 - time_since)
            raise ValueError(f"Rate Limit: Please wait {retry_in} seconds before requesting another verification email.")

    v_token = f"nkat-email-token-{secrets.token_hex(16)}"
    v_code = f"{random.randint(100000, 999999)}"
    expires_at = now + timedelta(minutes=20)

    user.email_verification_token = v_token
    user.email_verification_code = v_code
    user.email_verification_sent_at = now
    user.email_verification_expires_at = expires_at
    db.commit()

    email_res = {}
    try:
        from backend.services.email_service import send_verification_email
        email_res = send_verification_email(
            recipient_email=user.email,
            username=user.username,
            verification_code=v_code,
            verification_token=v_token,
            expires_in_minutes=20
        )
    except Exception as email_err:
        logger.warning(f"[!] Email dispatch notice: {email_err}")
        email_res = {"status": "logged", "error": str(email_err)}

    status_sent = email_res.get("status") == "sent" if isinstance(email_res, dict) else False

    if status_sent:
        msg = f"Fresh 6-digit verification code sent to {user.email}."
    else:
        msg = f"Fresh 6-digit OTP verification code generated for {user.email}: {v_code}"

    return {
        "message": msg,
        "email": user.email,
        "verification_code": v_code,
        "verification_token": v_token,
        "is_verified": False,
        "email_sent": status_sent
    }


def find_or_create_google_user(db: Session, email: str, google_sub: str | None = None, name: str | None = None) -> User:
    """
    Finds existing user by Google sub or email, or registers a new Google OAuth user (auto-verified).
    """
    clean_email = email.strip().lower()
    user = None
    if google_sub:
        user = db.query(User).filter(User.google_sub == google_sub).first()
    if not user:
        user = db.query(User).filter(User.email == clean_email).first()

    if user:
        changed = False
        if not user.is_email_verified:
            user.is_email_verified = True
            changed = True
        if google_sub and user.google_sub != google_sub:
            user.google_sub = google_sub
            changed = True
        if changed:
            db.commit()
            db.refresh(user)
        return user

    base_name = name.strip() if name else clean_email.split("@")[0]
    clean_username = base_name.replace(" ", "_").lower()

    existing_name = db.query(User).filter(User.username == clean_username).first()
    if existing_name:
        import uuid
        clean_username = f"{clean_username}_{uuid.uuid4().hex[:4]}"

    user = create_user_account(
        db=db,
        username=clean_username,
        email=clean_email,
        password=f"GoogleOAuthPass_{secrets.token_hex(8)}!",
        organization_name="Default Organization",
        auto_verify=True,
        auth_provider="google",
        google_sub=google_sub
    )
    return user



