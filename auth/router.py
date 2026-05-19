"""
auth/router.py — FastAPI Authentication Router
===============================================
Replaces auth/routes.py (Flask Blueprint).

Endpoints:
    POST /api/auth/register   — create account, return access token
    POST /api/auth/login      — OAuth2 password flow, return access + set refresh cookie
    POST /api/auth/refresh    — exchange refresh cookie for new access token
    POST /api/auth/logout     — revoke refresh token, clear cookie
    GET  /api/auth/me         — return current user info (requires Bearer token)

Token strategy:
    Access token  → 15 min JWT in Authorization: Bearer header  (JSON response body)
    Refresh token → 7 day JWT in 'refresh_token' HttpOnly cookie (never JS-readable)

CSRF mitigation:
    The refresh endpoint reads the token from a SameSite=Lax HttpOnly cookie.
    SameSite=Lax blocks cross-origin POSTs from third-party sites, so no
    explicit CSRF token is needed for this flow.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, field_validator
import jwt

from auth.jwt_utils import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    REFRESH_EXPIRE,
)
from auth.dependencies import get_current_user
from models.auth_db import (
    create_user,
    validate_user,
    get_user_by_id,
    store_refresh_token,
    validate_refresh_token,
    revoke_refresh_token,
    revoke_all_user_tokens,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ── Cookie name constant ───────────────────────────────────────────────────────
_REFRESH_COOKIE = "refresh_token"
_REFRESH_MAX_AGE = int(REFRESH_EXPIRE.total_seconds())  # 604800 seconds


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic request/response schemas
# ─────────────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

    @field_validator("username")
    @classmethod
    def username_length(cls, v: str) -> str:
        if len(v.strip()) < 3:
            raise ValueError("Username must be at least 3 characters")
        return v.strip()

    @field_validator("password")
    @classmethod
    def password_length(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    user_id: int


# ─────────────────────────────────────────────────────────────────────────────
# Helper — set / clear the refresh-token HttpOnly cookie
# ─────────────────────────────────────────────────────────────────────────────

def _set_refresh_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=_REFRESH_COOKIE,
        value=raw_token,
        httponly=True,       # JS cannot read this cookie — XSS-safe
        samesite="lax",      # blocks cross-site POST CSRF
        secure=False,        # set True in production (requires HTTPS)
        max_age=_REFRESH_MAX_AGE,
        path="/api/auth",    # scoped: only sent to /api/auth/* endpoints
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=_REFRESH_COOKIE, path="/api/auth")


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new account",
)
async def register(body: RegisterRequest, response: Response):
    """
    Create a new user account and immediately issue tokens.
    Returns an access token in the response body and sets the
    refresh token as an HttpOnly cookie.
    """
    success, result = await create_user(body.username, body.email, body.password)
    if not success:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=result)

    user_id: int = result  # type: ignore[assignment]

    access_token  = create_access_token(user_id, body.username)
    refresh_token = create_refresh_token(user_id)
    await store_refresh_token(user_id, refresh_token)

    _set_refresh_cookie(response, refresh_token)

    return TokenResponse(
        access_token=access_token,
        username=body.username,
        user_id=user_id,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login — OAuth2 Password flow",
)
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    Standard OAuth2 Password flow (form fields: `username` + `password`).

    Returns an access token in the JSON body and sets the refresh token
    as an HttpOnly cookie. The Swagger UI "Authorize" button uses this
    endpoint automatically.

    Note: `username` field accepts either the username OR email address,
    matching the behaviour of the original Flask login.
    """
    user = await validate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token  = create_access_token(user["id"], user["username"])
    refresh_token = create_refresh_token(user["id"])
    await store_refresh_token(user["id"], refresh_token)

    _set_refresh_cookie(response, refresh_token)

    return TokenResponse(
        access_token=access_token,
        username=user["username"],
        user_id=user["id"],
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token using HttpOnly cookie",
)
async def refresh_access_token(request: Request, response: Response):
    """
    Issue a new access token using the refresh token stored in the
    HttpOnly cookie. Implements token rotation: the old refresh token
    is revoked and a new one is issued.

    The client never needs to handle the refresh token directly — the
    browser sends the cookie automatically on requests to /api/auth/*.
    """
    raw_refresh = request.cookies.get(_REFRESH_COOKIE)
    if not raw_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )

    # 1. Verify JWT signature + expiry
    try:
        payload = decode_refresh_token(raw_refresh)
    except jwt.InvalidTokenError:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalid or expired",
        )

    # 2. Verify token exists in DB (handles server-side revocation)
    user = await validate_refresh_token(raw_refresh)
    if not user:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked",
        )

    # 3. Rotate: revoke old, issue new
    await revoke_refresh_token(raw_refresh)
    new_refresh = create_refresh_token(user["id"])
    await store_refresh_token(user["id"], new_refresh)
    new_access = create_access_token(user["id"], user["username"])

    _set_refresh_cookie(response, new_refresh)

    return TokenResponse(
        access_token=new_access,
        username=user["username"],
        user_id=user["id"],
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout — revoke refresh token",
)
async def logout(
    request: Request,
    response: Response,
    current_user: dict = Depends(get_current_user),
):
    """
    Revoke the current refresh token and clear the cookie.
    The access token becomes useless after its 15-minute TTL.
    Use `logout_everywhere` to revoke all sessions for this user.
    """
    raw_refresh = request.cookies.get(_REFRESH_COOKIE)
    if raw_refresh:
        await revoke_refresh_token(raw_refresh)
    _clear_refresh_cookie(response)
    return {"success": True, "message": "Logged out"}


@router.post(
    "/logout-everywhere",
    status_code=status.HTTP_200_OK,
    summary="Revoke ALL sessions for the current user",
)
async def logout_everywhere(
    response: Response,
    current_user: dict = Depends(get_current_user),
):
    """Invalidate every refresh token belonging to this user (all devices)."""
    await revoke_all_user_tokens(current_user["user_id"])
    _clear_refresh_cookie(response)
    return {"success": True, "message": "All sessions revoked"}


@router.get(
    "/me",
    summary="Return current user info",
)
async def get_me(current_user: dict = Depends(get_current_user)):
    """
    Returns the authenticated user's public profile.
    Requires a valid Bearer access token in the Authorization header.
    """
    user = await get_user_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Never return the password hash
    return {
        "user_id":    user["id"],
        "username":   user["username"],
        "email":      user["email"],
        "created_at": user["created_at"],
    }
