"""
API Security & Authentication Module — Local JWT & API Key Validation.
----------------------------------------------------------------------
Provides PyJWT encoding/decoding and unified FastAPI dependency (verify_api_key / verify_user_or_api_key)
accepting either a valid Bearer JWT token or X-API-Key header.

Local Data Privacy Notice:
All JWT creation, signature checks, and user context resolutions occur 100% locally.
Zero network transmission or third-party cloud authentication identity providers.
"""

import os
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, status, Depends
from dotenv import load_dotenv

load_dotenv()

EXPECTED_API_KEY = os.getenv("API_KEY", "nkat_secret_api_key_2026")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "nkat_local_jwt_secret_key_2026_super_secure_32bytes")
JWT_ALGORITHM = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours local session duration


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a locally signed HS256 JWT access token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a locally signed HS256 JWT access token.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session token.")


def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> Dict[str, Any]:
    """
    FastAPI dependency validating authentication via Bearer JWT token or X-API-Key header.
    Rejects missing or invalid credentials with HTTP 401 Unauthorized.
    """
    # 1. Check for Bearer JWT token first
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        payload = decode_access_token(token)
        return {
            "auth_type": "jwt",
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "role": payload.get("role", "analyst"),
            "organization_id": payload.get("organization_id", 1),
        }

    # 2. Check X-API-Key fallback header
    if x_api_key and x_api_key == EXPECTED_API_KEY:
        return {
            "auth_type": "api_key",
            "user_id": 1,
            "username": "api_key_user",
            "role": "admin",
            "organization_id": 1,
        }

    # 3. Reject if neither is valid
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication. Provide a valid Bearer JWT token or X-API-Key header."
    )


verify_user_or_api_key = verify_api_key


def require_admin_role(auth_context: Dict[str, Any] = Depends(verify_api_key)) -> Dict[str, Any]:
    """
    Enforces admin-only access control by verifying the JWT's role claim or admin API key.
    Raises HTTP 403 Forbidden if user role is not 'admin'.
    """
    role = auth_context.get("role", "").lower()
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Admin role required for activity reports & governance operations."
        )
    return auth_context
