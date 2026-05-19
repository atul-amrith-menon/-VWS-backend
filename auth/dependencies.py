"""
auth/dependencies.py — FastAPI Dependency Injection for Auth
=============================================================
Provides `get_current_user` — a reusable dependency injected into every
protected endpoint via `Depends(get_current_user)`.

Usage in any route:
    @app.get("/api/scan/{scan_id}")
    async def get_scan(
        scan_id: int,
        current_user: dict = Depends(get_current_user),
    ):
        ...  # current_user = {"user_id": 3, "username": "alice"}
"""

import jwt
from fastapi import Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from auth.jwt_utils import decode_access_token

# ── OAuth2 scheme ─────────────────────────────────────────────────────────────
# `tokenUrl` must match the login endpoint path so Swagger UI's
# "Authorize" button works out-of-the-box during development.
# auto_error=False allows us to fallback to query parameters (for EventSource)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# Shared 401 exception — reused to keep error messages consistent
_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    query_token: str = Query(None, alias="token")
) -> dict:
    """
    FastAPI dependency that extracts and validates the Bearer access token.
    Falls back to the 'token' query parameter for EventSource (SSE) requests
    which cannot send custom headers.

    Returns:
        {"user_id": int, "username": str}

    Raises:
        HTTP 401 — token missing, expired, or invalid
    """
    actual_token = token or query_token
    if not actual_token:
        raise _CREDENTIALS_EXCEPTION

    try:
        payload = decode_access_token(actual_token)
        user_id  = int(payload["sub"])
        username = payload["username"]
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise _CREDENTIALS_EXCEPTION

    return {"user_id": user_id, "username": username}
