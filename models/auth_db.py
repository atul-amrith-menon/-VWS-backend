"""
models/auth_db.py — Async Authentication Database Layer (SQLModel + MySQL)
=========================================================================
Replaces the old aiosqlite raw-SQL layer.

Key differences from the original:
  - Uses SQLModel (Pydantic + SQLAlchemy 2.0) for table definitions.
  - Connects to MySQL asynchronously via aiomysql.
  - All public helper functions preserve the same return types so that
    auth/dependencies.py and all FastAPI routes remain untouched.
  - Passwords are hashed with bcrypt via passlib.
  - Refresh tokens are stored as SHA-256 hashes — raw tokens never hit the DB.

Environment variables required (.env):
    MYSQL_URL = mysql+aiomysql://user:password@localhost:3306/vultix
"""

import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from passlib.context import CryptContext

from sqlmodel import SQLModel, Field, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text

# ── Config ────────────────────────────────────────────────────────────────────

MYSQL_URL: str = os.getenv(
    "MYSQL_URL",
    "mysql+aiomysql://root:password@localhost:3306/vultix",
)

# bcrypt context — auto-handles future algorithm upgrades
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Async Engine & Session Factory ────────────────────────────────────────────

engine = create_async_engine(
    MYSQL_URL,
    echo=False,          # Set True temporarily to see raw SQL during debugging
    pool_pre_ping=True,  # Drop stale connections automatically
    pool_recycle=1800,   # Recycle connections every 30 minutes
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── SQLModel Table Definitions ────────────────────────────────────────────────

class User(SQLModel, table=True):
    __tablename__ = "users"

    id:         Optional[int] = Field(default=None, primary_key=True)
    username:   str           = Field(index=True, unique=True, nullable=False, max_length=150)
    email:      str           = Field(index=True, unique=True, nullable=False, max_length=255)
    password:   str           = Field(nullable=False)
    created_at: str           = Field(nullable=False)


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id:         Optional[int] = Field(default=None, primary_key=True)
    user_id:    int           = Field(foreign_key="users.id", nullable=False, index=True)
    token_hash: str           = Field(unique=True, nullable=False, max_length=64)
    expires_at: str           = Field(nullable=False)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_token(raw_token: str) -> str:
    """SHA-256 hash of a raw token. Stored in DB; raw token goes to client."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _expires_str(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def _user_to_dict(user: User) -> dict:
    """Convert a SQLModel User object to a plain dict (mirrors old aiosqlite Row behaviour)."""
    return {
        "id":         user.id,
        "username":   user.username,
        "email":      user.email,
        "password":   user.password,
        "created_at": user.created_at,
    }


# ── Schema Initialisation ─────────────────────────────────────────────────────

async def init_auth_db() -> None:
    """Create all tables if they do not already exist. Called once at startup."""
    async with engine.begin() as conn:
        # Enable FK enforcement for the current session (MySQL-specific)
        await conn.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        await conn.run_sync(SQLModel.metadata.create_all)


# ── User Management ───────────────────────────────────────────────────────────

async def create_user(
    username: str, email: str, password: str
) -> Tuple[bool, int | str]:
    """
    Register a new user.

    Returns:
        (True,  user_id)        — success
        (False, error_message)  — username/email already taken
    """
    hashed = _pwd_ctx.hash(password)

    async with AsyncSessionLocal() as session:
        # Check uniqueness
        existing_username = (
            await session.execute(select(User).where(User.username == username))
        ).scalars().first()
        if existing_username:
            return False, "Username already taken"

        existing_email = (
            await session.execute(select(User).where(User.email == email))
        ).scalars().first()
        if existing_email:
            return False, "Email already registered"

        new_user = User(
            username=username,
            email=email,
            password=hashed,
            created_at=_now_utc(),
        )
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)
        return True, new_user.id  # type: ignore[return-value]


async def validate_user(username_or_email: str, password: str) -> dict | None:
    """
    Validate login credentials. Accepts username OR email.

    Returns the user dict on success, None on failure.
    Timing-safe: always runs bcrypt verify even if the user is not found.
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(
                (User.username == username_or_email) | (User.email == username_or_email)
            )
        )
        user = result.scalars().first()

    if user is None:
        _pwd_ctx.dummy_verify()
        return None

    if _pwd_ctx.verify(password, user.password):
        return _user_to_dict(user)
    return None


async def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user by their primary key."""
    async with AsyncSessionLocal() as session:
        user = await session.get(User, user_id)
        return _user_to_dict(user) if user else None


# ── Refresh-Token Management ──────────────────────────────────────────────────

async def store_refresh_token(user_id: int, raw_token: str, days: int = 7) -> None:
    """
    Persist the SHA-256 hash of a refresh token.

    The raw token is returned to the client in an HttpOnly cookie.
    Only the hash lives in the DB — a stolen dump cannot be replayed.
    """
    token_hash = _hash_token(raw_token)
    expires_at = _expires_str(days)

    async with AsyncSessionLocal() as session:
        # Remove any existing token for this user (one active token per user)
        existing = (
            await session.execute(
                select(RefreshToken).where(RefreshToken.user_id == user_id)
            )
        ).scalars().all()
        for tok in existing:
            await session.delete(tok)

        session.add(RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        ))
        await session.commit()


async def validate_refresh_token(raw_token: str) -> dict | None:
    """
    Verify a raw refresh token (from the HttpOnly cookie) against the DB.

    Returns the user dict if valid and not expired, otherwise None.
    Expired tokens are purged on first encounter.
    """
    token_hash = _hash_token(raw_token)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        token_row = result.scalars().first()

        if token_row is None:
            return None

        # Check expiry
        expires_at = datetime.strptime(token_row.expires_at, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        if datetime.now(timezone.utc) > expires_at:
            await session.delete(token_row)
            await session.commit()
            return None

        # Fetch the associated user
        user = await session.get(User, token_row.user_id)
        return _user_to_dict(user) if user else None


async def revoke_refresh_token(raw_token: str) -> None:
    """Remove a single refresh token (called on logout)."""
    token_hash = _hash_token(raw_token)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        token_row = result.scalars().first()
        if token_row:
            await session.delete(token_row)
            await session.commit()


async def revoke_all_user_tokens(user_id: int) -> None:
    """Remove ALL refresh tokens for a user (logout-everywhere / password change)."""
    async with AsyncSessionLocal() as session:
        tokens = (
            await session.execute(
                select(RefreshToken).where(RefreshToken.user_id == user_id)
            )
        ).scalars().all()
        for tok in tokens:
            await session.delete(tok)
        await session.commit()
