"""
models/scan_db.py — Async Scan & Vulnerability Database Layer
==============================================================
Drop-in async replacement for the old synchronous models/database.py.

All functions are `async def` using `aiosqlite` so they never block
the FastAPI event loop. The SQLite schema is identical to the original
so the existing `vultix.db` file works without any migration.

Public API (mirrors old database.py):
    init_db()
    create_scan(target_url, user_id)         -> int
    save_vulnerability(scan_id, vuln)
    update_scan_results(scan_id, vulns, duration, threat_score)
    update_scan_status(scan_id, status)
    get_scan(scan_id, user_id)               -> dict | None
    get_vulnerabilities(scan_id)             -> list[dict]
    get_all_scans(user_id)                   -> list[dict]
    delete_scan(scan_id, user_id)
"""

import os
import aiosqlite
from datetime import datetime

# ── Database path ─────────────────────────────────────────────────────────────
DB_PATH = os.getenv(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vultix.db"),
)


# ── Risk weights for threat score ─────────────────────────────────────────────
_RISK_WEIGHTS = {"High": 15, "Medium": 8, "Low": 3, "Info": 1}
_CRITICAL_TYPES = {
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal",
    "Sensitive Data Exposure",
    "Server-Side Template Injection (SSTI)",  # RCE-capable — highest severity
}


# ─────────────────────────────────────────────────────────────────────────────
# Schema initialisation
# ─────────────────────────────────────────────────────────────────────────────

async def init_db() -> None:
    """Create tables if they don't exist. Called once at application startup."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id          INTEGER NOT NULL DEFAULT 0,
                target_url       TEXT    NOT NULL,
                scan_date        TEXT    NOT NULL,
                status           TEXT    DEFAULT 'running',
                total_vulns      INTEGER DEFAULT 0,
                high             INTEGER DEFAULT 0,
                medium           INTEGER DEFAULT 0,
                low              INTEGER DEFAULT 0,
                info             INTEGER DEFAULT 0,
                threat_score     INTEGER DEFAULT 0,
                duration_seconds REAL    DEFAULT 0
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                vuln_type   TEXT    NOT NULL,
                risk_level  TEXT    NOT NULL,
                url         TEXT    NOT NULL,
                description TEXT    NOT NULL,
                evidence    TEXT    DEFAULT '',
                solution    TEXT    DEFAULT '',
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # ── Safe migration: add user_id to existing databases ─────────────────
        # This handles the case where the DB already exists without user_id.
        # SQLite does not support IF NOT EXISTS on ALTER TABLE, so we check the
        # column list manually and only alter if it's missing.
        cursor = await db.execute("PRAGMA table_info(scans)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "user_id" not in columns:
            # DEFAULT 0 keeps all existing scan rows intact (they belong to no user).
            await db.execute(
                "ALTER TABLE scans ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0"
            )

        await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Scan CRUD
# ─────────────────────────────────────────────────────────────────────────────

async def create_scan(target_url: str, user_id: int) -> int:
    """Insert a new scan record owned by user_id and return its auto-generated ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO scans (user_id, target_url, scan_date, status) VALUES (?, ?, ?, ?)",
            (user_id, target_url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "running"),
        )
        await db.commit()
        return cursor.lastrowid  # type: ignore[return-value]


async def get_scan(scan_id: int, user_id: int | None = None) -> dict | None:
    """
    Fetch a single scan record by ID.
    If user_id is provided, the scan is only returned if it belongs to that user.
    Returns None if not found or if it belongs to a different user.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if user_id is not None:
            cursor = await db.execute(
                "SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)
            )
        else:
            # Internal use only (e.g. worker updating status — no user context)
            cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_all_scans(user_id: int) -> list[dict]:
    """Return all scan records belonging to user_id, most recent first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC", (user_id,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def update_scan_status(scan_id: int, status: str) -> None:
    """Update just the status column of a scan (e.g. 'error', 'cancelled').
    Called by the background worker — no user_id check needed here."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE scans SET status = ? WHERE id = ?",
            (status, scan_id),
        )
        await db.commit()


async def update_scan_results(
    scan_id: int,
    vulns: list[dict],
    duration: float,
    threat_score: int = 0,
) -> None:
    """
    Write the final summary row after a scan completes (or is cancelled).
    Counts vulns by severity and marks status as 'completed'.
    Called by the background worker — no user_id check needed here.
    """
    high   = sum(1 for v in vulns if v.get("risk_level") == "High")
    medium = sum(1 for v in vulns if v.get("risk_level") == "Medium")
    low    = sum(1 for v in vulns if v.get("risk_level") == "Low")
    info   = sum(1 for v in vulns if v.get("risk_level") == "Info")

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """UPDATE scans
               SET status = 'completed', total_vulns = ?, high = ?, medium = ?,
                   low = ?, info = ?, threat_score = ?, duration_seconds = ?
               WHERE id = ?""",
            (len(vulns), high, medium, low, info, threat_score, round(duration, 2), scan_id),
        )
        await db.commit()


async def delete_scan(scan_id: int, user_id: int) -> bool:
    """
    Delete a scan and its vulnerabilities only if it belongs to user_id.
    Returns True if deleted, False if the scan was not found or does not belong
    to this user (so the API can return 404 appropriately).
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        cursor = await db.execute(
            "DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)
        )
        await db.commit()
        return cursor.rowcount > 0  # type: ignore[return-value]


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability CRUD
# ─────────────────────────────────────────────────────────────────────────────

async def delete_scan_vulnerabilities(scan_id: int) -> None:
    """
    Delete all vulnerability rows for a scan.
    Called by the AI pipeline to clear incremental saves before re-inserting
    the final deduplicated set, ensuring no duplicate rows persist.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        await db.commit()


async def save_vulnerability(scan_id: int, vuln: dict) -> None:
    """Insert a single vulnerability record linked to a scan."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO vulnerabilities
               (scan_id, vuln_type, risk_level, url, description, evidence, solution)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                vuln["vuln_type"],
                vuln["risk_level"],
                vuln["url"],
                vuln["description"],
                vuln.get("evidence", ""),
                vuln.get("solution", ""),
            ),
        )
        await db.commit()


async def get_vulnerabilities(scan_id: int) -> list[dict]:
    """Return all vulnerabilities for a scan, ordered High → Medium → Low → Info."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM vulnerabilities
               WHERE scan_id = ?
               ORDER BY CASE risk_level
                   WHEN 'High'   THEN 1
                   WHEN 'Medium' THEN 2
                   WHEN 'Low'    THEN 3
                   ELSE 4
               END""",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Threat score helper (moved here so tasks.py can import without circular deps)
# ─────────────────────────────────────────────────────────────────────────────

def calculate_threat_score(vulnerabilities: list[dict]) -> int:
    """
    Calculate a 0-100 threat score from a list of vulnerability dicts.
    Higher = more critical. Kept as a plain (sync) function — it's CPU-only,
    no I/O, safe to call from async context without to_thread().
    """
    if not vulnerabilities:
        return 0

    raw = sum(_RISK_WEIGHTS.get(v.get("risk_level", "Info"), 1) for v in vulnerabilities)

    has_critical = any(v.get("vuln_type") in _CRITICAL_TYPES for v in vulnerabilities)
    if has_critical:
        raw += 15

    score = min(int(raw * 100 / 150), 100)
    return max(score, 5) if vulnerabilities else 0
