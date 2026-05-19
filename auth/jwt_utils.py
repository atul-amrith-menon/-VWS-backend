"""
auth/jwt_utils.py — JWT Token Creation & Validation
=====================================================
Provides stateless access tokens (15 min) and refresh tokens (7 days).
Both are signed HS256 JWTs. The refresh token's raw string is also stored
(hashed) in the DB via models/auth_db.py so it can be revoked server-side.

Environment variables:
    JWT_SECRET   — signing key (MUST be set in production)
    JWT_ALGORITHM — default "HS256"
"""

import os
import jwt
from datetime import datetime, timedelta, timezone

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY      = os.getenv("JWT_SECRET", "vultix-dev-secret-CHANGE-IN-PROD")
ALGORITHM       = os.getenv("JWT_ALGORITHM", "HS256")
# 60 min gives enough headroom for long scans; the frontend auto-refreshes
# on 401, so even this can be extended safely in production.
ACCESS_EXPIRE   = timedelta(minutes=60)
REFRESH_EXPIRE  = timedelta(days=7)


# ─────────────────────────────────────────────────────────────────────────────
# Token creation
# ─────────────────────────────────────────────────────────────────────────────

def create_access_token(user_id: int, username: str) -> str:
    """
    Create a short-lived (15 min) access token.

    Payload claims:
        sub      — user ID (as string, per JWT spec)
        username — display name (avoids a DB round-trip on every request)
        type     — "access"  (guards against refresh token misuse)
        exp      — expiry timestamp (UTC)
    """
    payload = {
        "sub":      str(user_id),
        "username": username,
        "type":     "access",
        "exp":      datetime.now(timezone.utc) + ACCESS_EXPIRE,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    """
    Create a long-lived (7 day) refresh token.

    Only contains 'sub' and 'type'. Username is intentionally omitted
    so the client can't read PII from the HttpOnly cookie payload.
    """
    payload = {
        "sub":  str(user_id),
        "type": "refresh",
        "exp":  datetime.now(timezone.utc) + REFRESH_EXPIRE,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ─────────────────────────────────────────────────────────────────────────────
# Token validation
# ─────────────────────────────────────────────────────────────────────────────

def decode_token(token: str) -> dict:
    """
    Decode and verify a JWT.

    Raises:
        jwt.ExpiredSignatureError  — token is past its `exp` claim
        jwt.InvalidTokenError      — bad signature, wrong algorithm, malformed
    The caller (FastAPI dependency) converts these into HTTP 401 responses.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def decode_access_token(token: str) -> dict:
    """
    Decode and verify an access token specifically.
    Raises jwt.InvalidTokenError if `type` claim is not "access".
    """
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Not an access token")
    return payload


def decode_refresh_token(token: str) -> dict:
    """
    Decode and verify a refresh token specifically.
    Raises jwt.InvalidTokenError if `type` claim is not "refresh".
    """
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise jwt.InvalidTokenError("Not a refresh token")
    return payload
