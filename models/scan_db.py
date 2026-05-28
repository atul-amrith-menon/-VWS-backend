"""
models/scan_db.py — Async Scan & Vulnerability Database Layer (SQLModel + MySQL)
==============================================================================
Consolidated database layer utilizing SQLModel and the centralized MySQL connection pool.
All functions are asynchronous and maintain 100% backward-compatible schemas and signatures.
"""

import os
from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlmodel import SQLModel, Field, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, delete, update, Column, Integer, ForeignKey, Text, case

from models.auth_db import AsyncSessionLocal, engine

# ── Risk weights for threat score ─────────────────────────────────────────────
_RISK_WEIGHTS = {"High": 15, "Medium": 8, "Low": 3, "Info": 1}
_CRITICAL_TYPES = {
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal",
    "Sensitive Data Exposure",
    "Server-Side Template Injection (SSTI)",  # RCE-capable — highest severity
}

# ── SQLModel Table Definitions ────────────────────────────────────────────────

class Scan(SQLModel, table=True):
    __tablename__ = "scans"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(default=0, nullable=False, index=True)
    target_url: str = Field(nullable=False, max_length=2000)
    scan_date: str = Field(nullable=False, max_length=50)
    status: str = Field(default="running", max_length=50)
    total_vulns: int = Field(default=0)
    high: int = Field(default=0)
    medium: int = Field(default=0)
    low: int = Field(default=0)
    info: int = Field(default=0)
    threat_score: int = Field(default=0)
    duration_seconds: float = Field(default=0.0)


class Vulnerability(SQLModel, table=True):
    __tablename__ = "vulnerabilities"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        )
    )
    vuln_type: str = Field(nullable=False, max_length=255)
    risk_level: str = Field(nullable=False, max_length=50)
    url: str = Field(nullable=False, max_length=2048)
    description: str = Field(sa_column=Column(Text, nullable=False))
    evidence: str = Field(sa_column=Column(Text, nullable=True))
    solution: str = Field(sa_column=Column(Text, nullable=True))


# ── Conversion Helpers ────────────────────────────────────────────────────────

def _scan_to_dict(scan: Scan) -> dict:
    """Convert a SQLModel Scan object to a dict mirroring raw Row behavior."""
    return {
        "id": scan.id,
        "user_id": scan.user_id,
        "target_url": scan.target_url,
        "scan_date": scan.scan_date,
        "status": scan.status,
        "total_vulns": scan.total_vulns,
        "high": scan.high,
        "medium": scan.medium,
        "low": scan.low,
        "info": scan.info,
        "threat_score": scan.threat_score,
        "duration_seconds": scan.duration_seconds,
    }


def _vuln_to_dict(vuln: Vulnerability) -> dict:
    """Convert a SQLModel Vulnerability object to a dict mirroring raw Row behavior."""
    return {
        "id": vuln.id,
        "scan_id": vuln.scan_id,
        "vuln_type": vuln.vuln_type,
        "risk_level": vuln.risk_level,
        "url": vuln.url,
        "description": vuln.description,
        "evidence": vuln.evidence or "",
        "solution": vuln.solution or "",
    }


# ── Schema Initialisation ─────────────────────────────────────────────────────

async def init_db() -> None:
    """Create scans and vulnerabilities tables in MySQL if they do not exist."""
    async with engine.begin() as conn:
        # Enable foreign keys just in case and create tables
        await conn.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        await conn.run_sync(SQLModel.metadata.create_all)


# ── Scan CRUD ─────────────────────────────────────────────────────────────────

async def create_scan(target_url: str, user_id: int) -> int:
    """Insert a new scan record owned by user_id and return its auto-generated ID."""
    async with AsyncSessionLocal() as session:
        new_scan = Scan(
            user_id=user_id,
            target_url=target_url,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status="running",
        )
        session.add(new_scan)
        await session.commit()
        await session.refresh(new_scan)
        return new_scan.id  # type: ignore[return-value]


async def get_scan(scan_id: int, user_id: int | None = None) -> dict | None:
    """
    Fetch a single scan record by ID.
    If user_id is provided, the scan is only returned if it belongs to that user.
    """
    async with AsyncSessionLocal() as session:
        statement = select(Scan).where(Scan.id == scan_id)
        if user_id is not None:
            statement = statement.where(Scan.user_id == user_id)
        result = await session.execute(statement)
        scan = result.scalars().first()
        return _scan_to_dict(scan) if scan else None


async def get_all_scans(user_id: int) -> list[dict]:
    """Return all scan records belonging to user_id, most recent first."""
    async with AsyncSessionLocal() as session:
        statement = select(Scan).where(Scan.user_id == user_id).order_by(Scan.id.desc())
        result = await session.execute(statement)
        scans = result.scalars().all()
        return [_scan_to_dict(s) for s in scans]


async def update_scan_status(scan_id: int, status: str) -> None:
    """Update just the status column of a scan (e.g. 'error', 'cancelled')."""
    async with AsyncSessionLocal() as session:
        statement = (
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status=status)
        )
        await session.execute(statement)
        await session.commit()


async def update_scan_results(
    scan_id: int,
    vulns: list[dict],
    duration: float,
    threat_score: int = 0,
) -> None:
    """
    Write the final summary row after a scan completes (or is cancelled).
    Counts vulns by severity and marks status as 'completed'.
    """
    high   = sum(1 for v in vulns if v.get("risk_level") == "High")
    medium = sum(1 for v in vulns if v.get("risk_level") == "Medium")
    low    = sum(1 for v in vulns if v.get("risk_level") == "Low")
    info   = sum(1 for v in vulns if v.get("risk_level") == "Info")

    async with AsyncSessionLocal() as session:
        statement = (
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                status="completed",
                total_vulns=len(vulns),
                high=high,
                medium=medium,
                low=low,
                info=info,
                threat_score=threat_score,
                duration_seconds=round(duration, 2),
            )
        )
        await session.execute(statement)
        await session.commit()


async def delete_scan(scan_id: int, user_id: int) -> bool:
    """
    Delete a scan and its vulnerabilities only if it belongs to user_id.
    Leverages database-level ON DELETE CASCADE.
    """
    async with AsyncSessionLocal() as session:
        statement = select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
        result = await session.execute(statement)
        scan = result.scalars().first()
        if not scan:
            return False
        
        await session.delete(scan)
        await session.commit()
        return True


# ── Vulnerability CRUD ────────────────────────────────────────────────────────

async def delete_scan_vulnerabilities(scan_id: int) -> None:
    """
    Delete all vulnerability rows for a scan.
    """
    async with AsyncSessionLocal() as session:
        statement = delete(Vulnerability).where(Vulnerability.scan_id == scan_id)
        await session.execute(statement)
        await session.commit()


async def delete_vulnerability_by_key(scan_id: int, vuln_type: str, url: str) -> None:
    """Delete a single vulnerability row matching scan_id, vuln_type, and url."""
    async with AsyncSessionLocal() as session:
        statement = (
            delete(Vulnerability)
            .where(
                Vulnerability.scan_id == scan_id,
                Vulnerability.vuln_type == vuln_type,
                Vulnerability.url == url,
            )
        )
        await session.execute(statement)
        await session.commit()


async def save_vulnerability(scan_id: int, vuln: dict) -> None:
    """Insert a single vulnerability record linked to a scan."""
    async with AsyncSessionLocal() as session:
        new_vuln = Vulnerability(
            scan_id=scan_id,
            vuln_type=vuln["vuln_type"],
            risk_level=vuln["risk_level"],
            url=vuln["url"],
            description=vuln["description"],
            evidence=vuln.get("evidence", ""),
            solution=vuln.get("solution", ""),
        )
        session.add(new_vuln)
        await session.commit()


async def get_vulnerabilities(scan_id: int) -> list[dict]:
    """Return all vulnerabilities for a scan, ordered High → Medium → Low → Info."""
    async with AsyncSessionLocal() as session:
        statement = (
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan_id)
            .order_by(
                case(
                    (Vulnerability.risk_level == "High", 1),
                    (Vulnerability.risk_level == "Medium", 2),
                    (Vulnerability.risk_level == "Low", 3),
                    else_=4,
                )
            )
        )
        result = await session.execute(statement)
        vulns = result.scalars().all()
        return [_vuln_to_dict(v) for v in vulns]


# ── Threat score helper ───────────────────────────────────────────────────────

def calculate_threat_score(vulnerabilities: list[dict]) -> int:
    """
    Calculate a 0-100 threat score from a list of vulnerability dicts.
    """
    if not vulnerabilities:
        return 0

    raw = sum(_RISK_WEIGHTS.get(v.get("risk_level", "Info"), 1) for v in vulnerabilities)

    has_critical = any(v.get("vuln_type") in _CRITICAL_TYPES for v in vulnerabilities)
    if has_critical:
        raw += 15

    score = min(int(raw * 100 / 150), 100)
    return max(score, 5) if vulnerabilities else 0
