"""
main.py — Vultix FastAPI Application Entry Point
=================================================
Replaces app.py (Flask monolith).

Key differences from the original:
  - ASGI (Uvicorn) instead of WSGI (Flask dev server)
  - All route handlers are `async def`
  - Auth is stateless JWT Bearer (no server-side sessions)
  - Background scanning is queued into Redis via Taskiq (no threading.Thread)
  - Scan progress is streamed via SSE (no polling endpoint)
  - DB calls are async (aiosqlite via models/scan_db.py)

Startup order (lifespan):
  1. init_db()       — create scans / vulnerabilities tables
  2. init_auth_db()  — create users / refresh_tokens tables
  3. broker.startup()— connect Taskiq to Redis

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import json
import os
from contextlib import asynccontextmanager

# Load .env before any module that reads os.getenv() at import time
from dotenv import load_dotenv
load_dotenv()

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from auth import auth_router
from auth.dependencies import get_current_user
from broker import broker
from models.auth_db import init_auth_db
from models.scan_db import (
    create_scan,
    delete_scan,
    get_all_scans,
    get_scan,
    get_vulnerabilities,
    init_db,
)

# ── Redis connection (shared across SSE connections) ──────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


# ─────────────────────────────────────────────────────────────────────────────
# Application lifespan — startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs once at startup before the first request, and once on shutdown.
    Replaces Flask's @app.before_request init pattern.
    """
    # ── Startup ───────────────────────────────────────────────────────────────
    await init_db()
    await init_auth_db()
    await broker.startup()
    print("[Vultix] Database and Taskiq broker ready.")
    yield
    # ── Shutdown ──────────────────────────────────────────────────────────────
    await broker.shutdown()
    print("[Vultix] Taskiq broker shut down.")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Vultix API",
    description="Enterprise-grade web vulnerability scanner — async FastAPI backend.",
    version="2.0.0",
    lifespan=lifespan,
    # Swagger UI available at /docs  |  ReDoc at /redoc
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow the Vite dev server and production build origin to call the API.
# Credentials=True is required for the refresh-token HttpOnly cookie.
# NOTE: Both :5173 and :5174 are listed because Vite auto-increments the port
# when 5173 is already in use. Set FRONTEND_ORIGIN in .env for production.
_CORS_ORIGINS = list({
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    os.getenv("FRONTEND_ORIGIN", ""),
} - {""})

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,        # Required for Set-Cookie / Cookie headers
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# ── Mount auth router (/api/auth/...) ─────────────────────────────────────────
app.include_router(auth_router)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic request schemas
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url: str
    use_ai: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Scan routes
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/api/scan",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a new vulnerability scan",
    tags=["scans"],
)
async def start_scan(
    body: ScanRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Validate the target URL, create a scan record, then enqueue the job
    into Redis via Taskiq. Returns the scan_id *instantly* — the actual
    scanning happens in the worker process.

    Replaces the old Flask POST /scan which called threading.Thread directly.
    """
    target_url = body.target_url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")

    # Normalise scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    # Create DB record first so we have a scan_id to return
    scan_id = await create_scan(target_url, current_user["user_id"])

    # Enqueue into Redis — worker picks this up asynchronously
    # Import here to avoid circular imports (tasks.py imports broker which
    # imports from main indirectly via scan_db)
    if body.use_ai:
        from scanner.tasks import run_ai_scan_task
        await run_ai_scan_task.kiq(target_url, scan_id)
    else:
        from scanner.tasks import run_scan_task
        await run_scan_task.kiq(target_url, scan_id)

    return {"scan_id": scan_id, "status": "queued", "target_url": target_url}


@app.get(
    "/api/scan/stream/{scan_id}",
    summary="Stream scan progress via Server-Sent Events",
    tags=["scans"],
)
async def scan_stream(
    scan_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Opens an SSE stream for the given scan_id.

    The Taskiq worker publishes JSON progress payloads to the Redis channel
    `scan:<scan_id>`. This endpoint subscribes to that channel and forwards
    each message as an SSE event to the browser.

    Authentication:
        Accepts a Bearer token via the Authorization header (axios/fetch calls)
        OR a `token` query parameter (for EventSource which cannot send headers).

    Frontend usage (query-param method for EventSource):
        const token = localStorage.getItem('token');
        const es = new EventSource(`/api/scan/stream/42?token=${token}`);
        es.onmessage = (e) => {
            const { phase, progress, message } = JSON.parse(e.data);
        };
    """
    async def event_generator():
        r = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r.pubsub()
        channel = f"scan:{scan_id}"
        await pubsub.subscribe(channel)

        try:
            # Send an immediate heartbeat so the browser confirms the connection
            # is alive. Without this, some browsers show the stream as "pending"
            # and fire onerror prematurely.
            yield {"data": json.dumps({"phase": "Connected", "progress": 0, "message": "Stream connected", "heartbeat": True})}

            # Retrieve any cached progress payload from Redis so that page navigations
            # do not reset the visible progress percentage to 0%.
            cached_progress = await r.get(f"scan:progress:{scan_id}")
            if cached_progress:
                yield {"data": cached_progress}

            # Before streaming live events, check if the scan already finished.
            # This handles the case where the client reconnects after a brief
            # disconnect and the scan completed in the interim.
            existing = await get_scan(scan_id, current_user["user_id"])
            if existing and existing["status"] in ("completed", "error", "cancelled"):
                yield {
                    "data": json.dumps({
                        "phase":    existing["status"].capitalize(),
                        "progress": 100,
                        "message":  f"Scan {existing['status']}.",
                        "done":     True,
                        "status":   existing["status"],
                    })
                }
                return

            # Stream live progress from the Redis pub/sub channel
            async for message in pubsub.listen():
                # Check if the client disconnected to avoid writing to a dead stream
                if await request.is_disconnected():
                    break

                if message["type"] != "message":
                    continue

                data = json.loads(message["data"])
                yield {"data": json.dumps(data)}

                # Stop streaming once the scan reaches a terminal state
                if data.get("progress", 0) >= 100 or data.get("done"):
                    break

        finally:
            await pubsub.unsubscribe(channel)
            await r.aclose()

    return EventSourceResponse(event_generator(), ping=20)


@app.get(
    "/api/scan/{scan_id}",
    summary="Get scan record and vulnerabilities",
    tags=["scans"],
)
async def get_scan_detail(
    scan_id: int,
    current_user: dict = Depends(get_current_user),
):
    """Return a scan record plus its vulnerability list."""
    scan = await get_scan(scan_id, current_user["user_id"])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Return vulnerabilities even for running scans so the frontend can
    # display findings in real-time as they are saved by the background worker.
    vulns = await get_vulnerabilities(scan_id)

    return {"scan": scan, "vulnerabilities": vulns}


@app.get(
    "/api/scans",
    summary="List all scans (history)",
    tags=["scans"],
)
async def list_scans(current_user: dict = Depends(get_current_user)):
    """Return all scan records belonging to the logged-in user, most recent first."""
    scans = await get_all_scans(current_user["user_id"])
    return {"scans": scans}


@app.get(
    "/api/scan/{scan_id}/report",
    summary="Get full report for a completed scan",
    tags=["scans"],
)
async def get_report(
    scan_id: int,
    current_user: dict = Depends(get_current_user),
):
    """Return the scan summary and ordered vulnerability list for report rendering."""
    scan = await get_scan(scan_id, current_user["user_id"])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = await get_vulnerabilities(scan_id)
    return {"scan": scan, "vulnerabilities": vulns}


@app.post(
    "/api/scan/{scan_id}/cancel",
    summary="Cancel a running scan",
    tags=["scans"],
)
async def cancel_scan_endpoint(
    scan_id: int,
    current_user: dict = Depends(get_current_user),
):
    """
    Publish a cancel signal to the Redis channel `scan:cancel:<scan_id>`.
    The Taskiq worker monitors this channel and stops at the next phase
    checkpoint, saving partial results before exiting.
    """
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        scan = await get_scan(scan_id, current_user["user_id"])
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan["status"] != "running":
            return {"success": False, "message": f"Scan is already {scan['status']}"}

        await r.publish(f"scan:cancel:{scan_id}", "cancel")
        return {
            "success": True,
            "scan_id": scan_id,
            "message": "Cancel signal sent. Scan will stop at the next phase.",
        }
    finally:
        await r.aclose()


@app.delete(
    "/api/scan/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan record",
    tags=["scans"],
)
async def delete_scan_endpoint(
    scan_id: int,
    current_user: dict = Depends(get_current_user),
):
    """Delete a scan and all its vulnerability records. Only the owner can delete."""
    deleted = await delete_scan(scan_id, current_user["user_id"])
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")


# ─────────────────────────────────────────────────────────────────────────────
# Health check (no auth required — used by load balancers / Docker health)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok", "version": "2.0.0"}


# ─────────────────────────────────────────────────────────────────────────────
# Dev entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_excludes=["*.db", "__pycache__"],
    )
