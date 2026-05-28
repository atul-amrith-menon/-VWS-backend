"""
scanner/tasks.py — Taskiq Worker Tasks
=======================================
Replaces the threading.Thread pattern in scanner_engine.py.

Two tasks are defined:
    run_scan_task(target_url, scan_id)     — traditional scanner pipeline
    run_ai_scan_task(target_url, scan_id) — AI-powered scan (vLLM / LoRA)

Architecture:
    ┌─────────────┐   kiq()    ┌───────────────┐   BRPOP   ┌────────────┐
    │  FastAPI    │ ─────────► │  Redis List   │ ────────► │  Worker   │
    │  main.py   │            │  (task queue) │           │  process  │
    └─────────────┘            └───────────────┘           └─────┬──────┘
                                                                  │ PUBLISH
                               ┌───────────────┐                  ▼
    ┌─────────────┐  SUBSCRIBE │  Redis PubSub │ ◄──── scan:{id} progress
    │  Browser    │ ◄───────── │  channel      │
    │  SSE stream │            └───────────────┘
    └─────────────┘

Sync scanner modules are run via asyncio.to_thread() so they never block
the worker's event loop. No rewrite of the sub-scanners is needed.

Cancellation:
    FastAPI publishes a message to scan:cancel:{scan_id}.
    The worker subscribes on a background task and sets a per-scan
    asyncio.Event when the signal arrives.

Progress payload shape (published to scan:{scan_id}):
    {
        "phase":      str,   # human-readable phase name
        "progress":   int,   # 0-100
        "message":    str,   # detail message shown on the frontend
        "done":       bool,  # True only on the final event
        "vulns_found": int,  # live count of vulnerabilities found so far
    }

Optimizations (v3):
    1. Smart Evidence Truncation   — caps merged evidence to 3 instances.
    2. Concurrent Baseline Scanners— SQLi/XSS/SSTI/Misconfig/Advanced run
                                     in parallel threads via asyncio.gather().
    3. Real-time DB Saving         — findings saved immediately as each
                                     scanner finishes; DB counts updated live.
    4. Crawl Cache Sharing         — crawl_data passed to ai_orchestrator so
                                     fallback loops never re-crawl the target.
    5. Adaptive AI Semaphore       — vLLM health checked at startup; concurrency
                                     scaled 2 → 3 → 4 based on server load.
    6. WAF Pre-detection Wiring    — waf_info passed to scan_vulnerability_with_ai
                                     so AI agents apply evasion on Attempt 1.
"""

import asyncio
import json
import os
import threading
import time
from typing import Optional
from urllib.parse import urlparse

import redis.asyncio as aioredis

from broker import broker
from models.scan_db import (
    calculate_threat_score,
    delete_scan_vulnerabilities,
    delete_vulnerability_by_key,
    get_scan,
    save_vulnerability,
    update_scan_results,
    update_scan_status,
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication helper (v2 — smart evidence truncation)
# ─────────────────────────────────────────────────────────────────────────────

_MAX_EVIDENCE_INSTANCES = 3   # Max distinct evidence blocks stored per finding


def _deduplicate_vulns(vulns: list) -> list:
    """
    Collapse duplicate vulnerability findings into a single entry.

    Two findings are considered duplicates when they share the same
    `vuln_type` AND `url`.  When duplicates are found:
      - The first occurrence is kept as the base.
      - Each subsequent duplicate's `evidence` is appended to the base
        (separated by a visible delimiter) up to _MAX_EVIDENCE_INSTANCES.
      - If more than _MAX_EVIDENCE_INSTANCES duplicates exist, a short
        "(+ X more instances detected)" note is appended instead to avoid
        bloating SQLite rows and the frontend rendering.
      - The base `description` is updated to note multiple instances.

    The ordering is preserved: the first occurrence's risk_level and
    severity are kept, since the scanners already rank the worst case first.
    """
    seen: dict = {}    # key -> index in `result`
    counts: dict = {}  # key -> number of evidence blocks already stored
    result: list = []

    for vuln in vulns:
        key = (vuln.get("vuln_type", "").strip().lower(),
               vuln.get("url", "").strip().rstrip("/").lower())

        if key not in seen:
            seen[key]   = len(result)
            counts[key] = 1
            result.append(dict(vuln))   # work on a copy
        else:
            base          = result[seen[key]]
            extra_evidence = (vuln.get("evidence") or "").strip()

            if extra_evidence and extra_evidence not in (base.get("evidence") or ""):
                if counts[key] < _MAX_EVIDENCE_INSTANCES:
                    # Still within the evidence cap — append full block
                    delimiter = "\n\n--- [Additional Instance] ---\n"
                    base["evidence"] = (base.get("evidence") or "") + delimiter + extra_evidence
                    counts[key] += 1
                elif "(+ " not in (base.get("evidence") or ""):
                    # First overflow — replace trailing content with a compact note
                    overflow_note = f"\n\n... (+ more instances detected — evidence capped at {_MAX_EVIDENCE_INSTANCES} for clarity)"
                    base["evidence"] = (base.get("evidence") or "") + overflow_note

            # Mark the description so the reader knows there are multiple hits
            if "(multiple instances)" not in (base.get("description") or "").lower():
                base["description"] = (base.get("description") or "") + " (multiple instances detected)"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Progress publisher
# ─────────────────────────────────────────────────────────────────────────────

async def _publish(
    r: aioredis.Redis,
    scan_id: int,
    phase: str,
    progress: int,
    message: str,
    done: bool = False,
    vulns_found: int = 0,
    vulnerabilities: Optional[list] = None,
) -> None:
    """Publish a progress event to the Redis channel and cache the latest state.

    vulns_found: real-time count of vulnerabilities found so far (streamed to UI).
    """
    payload_dict = {
        "phase":       phase,
        "progress":    progress,
        "message":     message,
        "done":        done,
        "vulns_found": vulns_found,
    }
    if vulnerabilities is not None:
        payload_dict["vulnerabilities"] = vulnerabilities

    payload = json.dumps(payload_dict)
    # Cache the latest progress state in Redis for 2 hours (7200 seconds)
    # This prevents the UI from resetting to 0% if the user navigates away and returns.
    await r.set(f"scan:progress:{scan_id}", payload, ex=7200)
    await r.publish(f"scan:{scan_id}", payload)


# ─────────────────────────────────────────────────────────────────────────────
# Cancellation monitor
# ─────────────────────────────────────────────────────────────────────────────

async def _watch_cancel(scan_id: int, cancel_event: asyncio.Event) -> None:
    """
    Background coroutine that subscribes to scan:cancel:{scan_id}.
    Sets cancel_event when a cancel signal arrives so the main task
    loop can check it between phases.
    """
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:cancel:{scan_id}")
    try:
        async for msg in pubsub.listen():
            if msg["type"] == "message":
                cancel_event.set()
                break
    finally:
        await pubsub.unsubscribe(f"scan:cancel:{scan_id}")
        await r.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# Helper — save partial results and mark scan cancelled
# ─────────────────────────────────────────────────────────────────────────────

async def _finish_cancelled(
    r: aioredis.Redis,
    scan_id: int,
    vulns: list,
    start_time: float,
) -> None:
    duration     = time.time() - start_time
    deduped      = _deduplicate_vulns(vulns)
    threat_score = calculate_threat_score(deduped)

    await delete_scan_vulnerabilities(scan_id)
    for vuln in deduped:
        await save_vulnerability(scan_id, vuln)

    await update_scan_results(scan_id, deduped, duration, threat_score)
    await update_scan_status(scan_id, "cancelled")

    await _publish(
        r, scan_id,
        phase="Cancelled",
        progress=100,
        message=f"Scan cancelled. {len(deduped)} vulnerabilities found before cancellation.",
        done=True,
        vulns_found=len(deduped),
        vulnerabilities=deduped,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Real-time DB save helper
# ─────────────────────────────────────────────────────────────────────────────

async def _save_new_findings(scan_id: int, new_vulns: list) -> None:
    """
    Immediately persist newly discovered vulnerabilities to SQLite.
    Called right after each scanner finishes so findings appear in the
    frontend even before the scan completes.
    """
    for vuln in new_vulns:
        await save_vulnerability(scan_id, vuln)


async def _save_incremental(scan_id: int, deduped_vulns: list, saved_keys: dict) -> None:
    """
    Incrementally update SQLite database with new or modified findings.
    Avoids deleting and re-inserting all findings on every progress update.
    """
    current_keys = set()
    for vuln in deduped_vulns:
        vuln_type = vuln.get("vuln_type", "")
        url = vuln.get("url", "")
        key = (vuln_type.strip().lower(), url.strip().rstrip("/").lower())
        current_keys.add(key)

        existing = saved_keys.get(key)
        if existing is None:
            # New finding! Save it.
            await save_vulnerability(scan_id, vuln)
            saved_keys[key] = dict(vuln)
        else:
            # Check if evidence, risk level, or description has changed
            if (existing.get("evidence") != vuln.get("evidence") or 
                existing.get("risk_level") != vuln.get("risk_level") or 
                existing.get("description") != vuln.get("description")):
                # Changed! Delete the old one and insert updated one
                await delete_vulnerability_by_key(scan_id, vuln_type, url)
                await save_vulnerability(scan_id, vuln)
                saved_keys[key] = dict(vuln)

    # Clean up keys that are no longer in deduped
    for key in list(saved_keys.keys()):
        if key not in current_keys:
            vuln_type, url = saved_keys[key]["vuln_type"], saved_keys[key]["url"]
            await delete_vulnerability_by_key(scan_id, vuln_type, url)
            del saved_keys[key]


# ─────────────────────────────────────────────────────────────────────────────
# Adaptive AI semaphore helper
# ─────────────────────────────────────────────────────────────────────────────

async def _get_ai_semaphore() -> asyncio.Semaphore:
    """
    Query the vLLM server's health endpoint to decide how many concurrent
    AI vulnerability checks to run.

    Scale:
        vLLM healthy & responsive  → Semaphore(3)  [safe for RTX 4050 6 GB]
        vLLM unresponsive / error  → Semaphore(2)  [conservative fallback]

    We deliberately cap at 3 (not 4) because the baseline scanners are also
    running concurrently during the AI phase and share system resources.
    """
    import aiohttp
    vllm_url = os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1").rstrip("/v1").rstrip("/")
    health_url = f"{vllm_url}/health"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(health_url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                if resp.status == 200:
                    return asyncio.Semaphore(3)
    except Exception:
        pass  # vLLM unreachable — conservative fallback
    return asyncio.Semaphore(2)


# ─────────────────────────────────────────────────────────────────────────────
# Task 1 — Traditional scanner pipeline (v3 — concurrent baselines)
# ─────────────────────────────────────────────────────────────────────────────

@broker.task
async def run_scan_task(target_url: str, scan_id: int) -> dict:
    """
    Runs the full traditional scanner pipeline as a Taskiq task.

    v3 Changes:
      - All post-crawl scanners (SQLi, XSS, SSTI, Misconfig/Nmap, Advanced)
        run concurrently via asyncio.gather() in separate to_thread() calls.
      - Each concurrent scanner gets its own requests.Session to prevent
        shared-state race conditions across threads.
      - Findings are saved to SQLite immediately as each scanner finishes
        (not only at the end), so the frontend can display results live.
      - Progress events include vulns_found count for real-time UI updates.
    """
    import requests as _requests
    from scanner.crawler import Crawler
    from scanner.sqli_scanner import SQLiScanner
    from scanner.xss_scanner import XSSScanner
    from scanner.misconfig_scanner import MisconfigScanner
    from scanner.advanced_scanner import AdvancedScanner

    start_time   = time.time()
    vulns: list  = []
    cancel_event = asyncio.Event()
    stop_event   = threading.Event()
    saved_keys: dict = {}  # key -> dict of vulnerability details for delta tracking

    # Normalise URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    target_url = target_url.rstrip("/")

    r = aioredis.from_url(REDIS_URL, decode_responses=True)

    # Cancel watcher — listens for cancel signal and sets both events
    async def _watch_and_propagate():
        r2 = aioredis.from_url(REDIS_URL, decode_responses=True)
        pub2 = r2.pubsub()
        await pub2.subscribe(f"scan:cancel:{scan_id}")
        try:
            async for msg in pub2.listen():
                if msg["type"] == "message":
                    cancel_event.set()
                    stop_event.set()
                    break
        finally:
            await pub2.unsubscribe(f"scan:cancel:{scan_id}")
            await r2.aclose()

    cancel_watcher = asyncio.create_task(_watch_and_propagate())

    # Lock to guard concurrent mutations to `vulns` and Redis publishes
    findings_lock = asyncio.Lock()

    try:
        # ── Phase 1: Crawling ─────────────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        await _publish(r, scan_id, "Crawling", 8, f"Crawling {target_url}...", vulns_found=0)

        crawler    = Crawler(target_url)
        crawl_data = await asyncio.to_thread(crawler.crawl)

        pages            = crawl_data["pages"]
        forms            = crawl_data["forms"]
        urls_with_params = crawl_data["urls_with_params"]
        discovered_ports = crawl_data.get("discovered_ports", [])

        # Build alternate port targets so SQLi, XSS, and SSTI scanners test them
        parsed_target = urlparse(target_url)
        target_hostname = parsed_target.hostname or target_url
        
        for port in discovered_ports:
            # Construct http:// and https:// URLs for the non-standard port
            for scheme in ["http", "https"]:
                alt_url = f"{scheme}://{target_hostname}:{port}/"
                # Add to pages to ensure other generic checks might pick them up
                if not any(p["url"] == alt_url for p in pages):
                    pages.append({
                        "url": alt_url,
                        "status_code": 200,
                        "headers": {},
                    })
                # Add to urls_with_params if needed (e.g. as a basic base target) or fuzz targets

        await _publish(
            r, scan_id, "Crawling Complete", 18,
            f"Found {len(pages)} pages, {len(forms)} forms, "
            f"{len(urls_with_params)} parameterised URLs. Discovered non-standard ports: {discovered_ports}",
            vulns_found=0,
        )

        # ── Phase 2-6: Concurrent scanning ───────────────────────────────────
        # Each scanner gets its own Session to be thread-safe.
        # All scanners are launched simultaneously; we wait for all to finish.

        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        # Pre-emptive Nmap port scan to gather tech signatures for active fuzzers
        nmap_findings = []
        tech_signatures = []
        
        if not cancel_event.is_set():
            await _publish(r, scan_id, "Nmap Port Scanning", 20,
                           f"Running Nmap port scan on ports: {discovered_ports or 'default Fast Mode'}...",
                           vulns_found=len(_deduplicate_vulns(vulns)))
            
            from scanner.nmap_scanner import run_nmap_scan
            nmap_findings = await asyncio.to_thread(run_nmap_scan, target_url, ports=discovered_ports, stop_event=stop_event)
            
            # Parse Nmap findings/output/evidence for technology signatures
            # E.g. "Werkzeug", "Gunicorn", "Python", "Node", "Ruby", "Spring"
            known_signatures = ["Werkzeug", "Gunicorn", "Python", "Node", "Ruby", "Spring", "Flask", "Django", "Java", "Express"]
            for f in nmap_findings:
                evidence_text = f.get("evidence", "") + " " + f.get("description", "")
                for sig in known_signatures:
                    if sig.lower() in evidence_text.lower() and sig not in tech_signatures:
                        tech_signatures.append(sig)
            
            async with findings_lock:
                if not cancel_event.is_set():
                    if nmap_findings:
                        vulns.extend(nmap_findings)
                    deduped = _deduplicate_vulns(vulns)
                    await _save_incremental(scan_id, deduped, saved_keys)
                    await _publish(
                        r, scan_id, "Nmap Port Scanning", 22,
                        f"Nmap complete — {len(nmap_findings) if nmap_findings else 0} finding(s). Tech signatures: {tech_signatures}",
                        vulns_found=len(deduped),
                        vulnerabilities=deduped,
                    )

        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        await _publish(r, scan_id, "Security Testing", 25,
                       "Running SQLi, XSS, SSTI, Misconfig, and Advanced checks in parallel...",
                       vulns_found=len(_deduplicate_vulns(vulns)))

        async def _run_and_collect(scanner_fn, phase_name: str, phase_pct: int):
            """Run a scanner in a thread, then publish its findings count immediately.
            Saves deduplicated findings incrementally to SQLite so they appear in the UI live."""
            if cancel_event.is_set():
                return
            new_findings = await asyncio.to_thread(scanner_fn)
            async with findings_lock:
                if not cancel_event.is_set():
                    if new_findings:
                        vulns.extend(new_findings)
                    
                    deduped = _deduplicate_vulns(vulns)
                    
                    # Use delta-based incremental saving instead of delete-all/reinsert-all
                    await _save_incremental(scan_id, deduped, saved_keys)
                    
                    await _publish(
                        r, scan_id, phase_name, phase_pct,
                        f"{phase_name} complete — {len(new_findings) if new_findings else 0} finding(s)",
                        vulns_found=len(deduped),
                        vulnerabilities=deduped,
                    )

        def _make_session():
            s = _requests.Session()
            s.headers.update({"User-Agent": "Vultix/2.0 Security Scanner (Educational)"})
            return s

        def _sqli():
            scanner = SQLiScanner(session=_make_session())
            # Scan normal targets + alternate targets
            for url in urls_with_params: 
                scanner.scan_url_params(url)
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    # Create base url and scan
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    scanner.scan_url_params(base_url)
            for form in forms:           
                scanner.scan_form(form)
            return scanner.get_results()

        def _xss():
            scanner = XSSScanner(session=_make_session())
            for url in urls_with_params: 
                scanner.scan_url_params(url)
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    scanner.scan_url_params(base_url)
            for form in forms:           
                scanner.scan_form(form)
            return scanner.get_results()

        def _ssti():
            from scanner.ssti_scanner import SSTIScanner
            # Pass detected tech signatures to optimize/prioritize template injections
            scanner = SSTIScanner(session=_make_session(), tech_context=tech_signatures)
            for url in urls_with_params: 
                scanner.scan_url_params(url)
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    scanner.scan_url_params(base_url)
            for form in forms:           
                scanner.scan_form(form)
            return scanner.get_results()

        def _misconfig():
            scanner = MisconfigScanner(session=_make_session())
            # Scan headers for up to first 3 pages
            for page in pages[:3]:
                scanner.scan_headers(page)
            scanner.scan_sensitive_files(target_url)
            # Scan sensitive files on discovered alternate ports
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    scanner.scan_sensitive_files(base_url)
            scanner.check_https(target_url)
            return scanner.get_results()

        def _advanced():
            scanner = AdvancedScanner(session=_make_session())
            scanner.run_all(target_url, pages, forms, urls_with_params)
            return scanner.get_results()

        # Launch all 5 scanner groups concurrently (excluding nmap which ran sequentially first)
        await asyncio.gather(
            _run_and_collect(_sqli,     "SQL Injection Testing",        40),
            _run_and_collect(_xss,      "XSS Testing",                  55),
            _run_and_collect(_ssti,     "SSTI Testing",                 70),
            _run_and_collect(_misconfig,"Misconfig Analysis",           80),
            _run_and_collect(_advanced, "Advanced Security Checks",     88),
        )

        # ── Phase 7: Deduplicate + Save ───────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        vulns = _deduplicate_vulns(vulns)

        await _publish(r, scan_id, "Saving Results", 90,
                       f"Deduplication complete — {len(vulns)} unique findings",
                       vulns_found=len(vulns),
                       vulnerabilities=vulns)

        threat_score = calculate_threat_score(vulns)
        # Clear incremental findings first to avoid duplicates
        await delete_scan_vulnerabilities(scan_id)
        # Save all deduplicated findings to SQLite at once
        for vuln in vulns:
            await save_vulnerability(scan_id, vuln)
        duration     = time.time() - start_time
        await update_scan_results(scan_id, vulns, duration, threat_score)

        await _publish(
            r, scan_id, "Completed", 100,
            f"Scan complete! Found {len(vulns)} vulnerabilities "
            f"(Threat Score: {threat_score}/100) in {duration:.1f}s",
            done=True,
            vulns_found=len(vulns),
            vulnerabilities=vulns,
        )

        return {"scan_id": scan_id, "total": len(vulns), "threat_score": threat_score}

    except Exception as exc:
        await update_scan_status(scan_id, "error")
        await _publish(r, scan_id, "Error", 0,
                       f"Scan failed: {exc}", done=True)
        raise

    finally:
        cancel_watcher.cancel()
        await r.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# Task 2 — AI-powered scan pipeline (v3 — all optimizations)
# ─────────────────────────────────────────────────────────────────────────────

# Phase labels mirror AIScannerEngine._VULN_PHASES from the old scanner_engine.py
_AI_VULN_PHASES = [
    ("SQL Injection",                            8,  "AI: Planning SQL Injection attack..."),
    ("Cross-Site Scripting (XSS)",              14,  "AI: Testing for XSS vulnerabilities..."),
    ("Server-Side Template Injection (SSTI)",   20,  "AI: Testing for Server-Side Template Injection..."),
    ("Infrastructure & Port Scan (Nmap)",       26,  "AI: Scanning infrastructure and open ports..."),
    ("CSRF",                                    32,  "AI: Analysing CSRF token protections..."),
    ("Directory Traversal",                     38,  "AI: Testing directory traversal paths..."),
    ("Open Redirect",                           44,  "AI: Checking open redirect parameters..."),
    ("Clickjacking",                            50,  "AI: Checking clickjacking headers..."),
    ("Sensitive Data Exposure",                 55,  "AI: Scanning for sensitive data leaks..."),
    ("Weak Authentication",                     60,  "AI: Evaluating authentication strength..."),
    ("Server-Side Request Forgery (SSRF)",      65,  "AI: Probing for SSRF attack vectors..."),
    ("CORS Misconfiguration",                   70,  "AI: Testing cross-origin resource sharing policy..."),
    ("Insecure Direct Object Reference (IDOR)", 75,  "AI: Testing IDOR via ID parameter enumeration..."),
    ("Business Logic & API Endpoint Discovery", 81,  "AI: Discovering hidden API endpoints & logic flaws..."),
    ("HTTP Parameter Pollution (HPP)",          86,  "AI: Testing parameter pollution vectors..."),
    ("XML External Entity (XXE) Injection",     92,  "AI: Testing XXE injection via XML inputs..."),
]

# Per-vulnerability timeout in seconds (enforced in the worker)
_VULN_TIMEOUT = 320


@broker.task
async def run_ai_scan_task(target_url: str, scan_id: int) -> dict:
    """
    Runs the AI-powered scan pipeline as a Taskiq task.

    v3 Changes:
      - WAF pre-detection: probes the target for CF-Ray/WAF headers before
        launching any scanner; result is passed to AI agents so they apply
        evasion on Attempt 1 instead of waiting to get blocked.
      - Crawl runs once; crawl_data is passed to both baseline scanners and
        AI fallback loops to eliminate all redundant crawling.
      - Baseline scanners (SQLi, XSS, SSTI, Misconfig, Advanced) run
        concurrently via asyncio.gather() in separate threads.
      - Findings are saved to SQLite immediately as each scanner completes.
      - Adaptive semaphore: vLLM health endpoint is queried; concurrency is
        set to 3 if vLLM is healthy, falling back to 2 if unreachable.
      - Progress events include vulns_found count for live UI updates.
    """
    from scanner.ai_orchestrator import scan_vulnerability_with_ai, detect_waf

    start_time    = time.time()
    all_findings: list = []
    cancel_event  = asyncio.Event()
    stop_event    = threading.Event()
    saved_keys: dict = {}  # key -> dict of vulnerability details for delta tracking

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    target_url = target_url.rstrip("/")

    r = aioredis.from_url(REDIS_URL, decode_responses=True)

    async def _ai_watch_cancel():
        r2 = aioredis.from_url(REDIS_URL, decode_responses=True)
        pub2 = r2.pubsub()
        await pub2.subscribe(f"scan:cancel:{scan_id}")
        try:
            async for msg in pub2.listen():
                if msg["type"] == "message":
                    cancel_event.set()
                    stop_event.set()
                    break
        finally:
            await pub2.unsubscribe(f"scan:cancel:{scan_id}")
            await r2.aclose()

    cancel_watcher = asyncio.create_task(_ai_watch_cancel())

    # Lock for safe concurrent mutations to all_findings and Redis publishes
    findings_lock = asyncio.Lock()

    try:
        # ── Phase 0: WAF Detection + vLLM health check ────────────────────────
        await _publish(r, scan_id, "AI Agents Initialising", 2,
                       "Detecting WAF protections & checking vLLM server...",
                       vulns_found=0)

        # Run WAF detection and vLLM health check concurrently
        waf_info, sem = await asyncio.gather(
            detect_waf(target_url),
            _get_ai_semaphore(),
        )

        if waf_info.get("detected"):
            waf_name = waf_info.get("name", "Unknown WAF")
            await _publish(r, scan_id, "WAF Detected", 3,
                           f"⚠️ WAF detected ({waf_name}) — enabling evasion on all AI probes.",
                           vulns_found=0)

        # ── Phase 1: Crawl ────────────────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, all_findings, start_time)

        await _publish(r, scan_id, "Crawling", 4,
                       f"Crawling {target_url} (shared across all scanners)...",
                       vulns_found=0)

        import requests as _req
        from scanner.crawler import Crawler

        def _do_crawl():
            return Crawler(target_url).crawl()

        crawl_data = await asyncio.to_thread(_do_crawl)
        pages            = crawl_data["pages"]
        forms            = crawl_data["forms"]
        urls_with_params = crawl_data["urls_with_params"]
        discovered_ports = crawl_data.get("discovered_ports", [])

        # Build alternate port targets so SQLi, XSS, and SSTI scanners test them
        parsed_target = urlparse(target_url)
        target_hostname = parsed_target.hostname or target_url
        
        for port in discovered_ports:
            # Construct http:// and https:// URLs for the non-standard port
            for scheme in ["http", "https"]:
                alt_url = f"{scheme}://{target_hostname}:{port}/"
                # Add to pages to ensure other generic checks might pick them up
                if not any(p["url"] == alt_url for p in pages):
                    pages.append({
                        "url": alt_url,
                        "status_code": 200,
                        "headers": {},
                    })

        await _publish(r, scan_id, "Crawling Complete", 5,
                       f"Found {len(pages)} pages, {len(forms)} forms, "
                       f"{len(urls_with_params)} parameterised URLs. Discovered non-standard ports: {discovered_ports}",
                       vulns_found=0)

        # ── Phase 2: Concurrent Baseline Scan ────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, all_findings, start_time)

        # Pre-emptive Nmap port scan to gather tech signatures for active fuzzers
        nmap_findings = []
        tech_signatures = []
        
        if not cancel_event.is_set():
            await _publish(r, scan_id, "Nmap Port Scanning", 6,
                           f"Running Nmap port scan on ports: {discovered_ports or 'default Fast Mode'}...",
                           vulns_found=len(_deduplicate_vulns(all_findings)))
            
            from scanner.nmap_scanner import run_nmap_scan
            nmap_findings = await asyncio.to_thread(run_nmap_scan, target_url, ports=discovered_ports, stop_event=stop_event)
            
            # Parse Nmap findings/output/evidence for technology signatures
            known_signatures = ["Werkzeug", "Gunicorn", "Python", "Node", "Ruby", "Spring", "Flask", "Django", "Java", "Express"]
            for f in nmap_findings:
                evidence_text = f.get("evidence", "") + " " + f.get("description", "")
                for sig in known_signatures:
                    if sig.lower() in evidence_text.lower() and sig not in tech_signatures:
                        tech_signatures.append(sig)
            
            async with findings_lock:
                if not cancel_event.is_set():
                    if nmap_findings:
                        all_findings.extend(nmap_findings)
                    deduped = _deduplicate_vulns(all_findings)
                    await _save_incremental(scan_id, deduped, saved_keys)
                    await _publish(
                        r, scan_id, "Baseline Scan", 6,
                        f"Baseline: Nmap Complete — {len(nmap_findings) if nmap_findings else 0} finding(s) (total: {len(deduped)}). Tech signatures: {tech_signatures}",
                        vulns_found=len(deduped),
                        vulnerabilities=deduped,
                    )

        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, all_findings, start_time)

        await _publish(r, scan_id, "Baseline Scan", 7,
                       "Running traditional security checks in parallel (SQLi, XSS, SSTI)...",
                       vulns_found=len(_deduplicate_vulns(all_findings)))

        def _make_session():
            s = _req.Session()
            s.headers.update({"User-Agent": "Vultix/2.0 Security Scanner (Educational)"})
            return s

        async def _baseline_run_and_collect(scanner_fn, label: str):
            if cancel_event.is_set():
                return
            new_findings = await asyncio.to_thread(scanner_fn)
            async with findings_lock:
                if not cancel_event.is_set():
                    if new_findings:
                        all_findings.extend(new_findings)
                    
                    deduped = _deduplicate_vulns(all_findings)
                    
                    await _save_incremental(scan_id, deduped, saved_keys)
                        
                    await _publish(
                        r, scan_id, "Baseline Scan", 7,
                        f"Baseline: {label} — {len(new_findings) if new_findings else 0} finding(s) (total: {len(deduped)})",
                        vulns_found=len(deduped),
                        vulnerabilities=deduped,
                    )

        def _sqli():
            from scanner.sqli_scanner import SQLiScanner
            s = SQLiScanner(session=_make_session())
            for u in urls_with_params: s.scan_url_params(u)
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    s.scan_url_params(base_url)
            for f in forms:            s.scan_form(f)
            return s.get_results()

        def _xss():
            from scanner.xss_scanner import XSSScanner
            s = XSSScanner(session=_make_session())
            for u in urls_with_params: s.scan_url_params(u)
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    s.scan_url_params(base_url)
            for f in forms:            s.scan_form(f)
            return s.get_results()

        def _ssti():
            from scanner.ssti_scanner import SSTIScanner
            s = SSTIScanner(session=_make_session(), tech_context=tech_signatures)
            for u in urls_with_params: s.scan_url_params(u)
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    s.scan_url_params(base_url)
            for f in forms:            s.scan_form(f)
            return s.get_results()

        def _misconfig():
            from scanner.misconfig_scanner import MisconfigScanner
            ms = MisconfigScanner(session=_make_session())
            for page in pages[:3]:
                ms.scan_headers(page)
            ms.scan_sensitive_files(target_url)
            for port in discovered_ports:
                for scheme in ["http", "https"]:
                    base_url = f"{scheme}://{target_hostname}:{port}/"
                    ms.scan_sensitive_files(base_url)
            ms.check_https(target_url)
            return ms.get_results()

        def _advanced():
            from scanner.advanced_scanner import AdvancedScanner
            s = AdvancedScanner(session=_make_session())
            s.run_all(target_url, pages, forms, urls_with_params)
            return s.get_results()

        # Run all 5 baseline scanner groups concurrently
        await asyncio.gather(
            _baseline_run_and_collect(_sqli,     "SQL Injection"),
            _baseline_run_and_collect(_xss,      "XSS"),
            _baseline_run_and_collect(_ssti,     "SSTI"),
            _baseline_run_and_collect(_misconfig,"Misconfig"),
            _baseline_run_and_collect(_advanced, "Advanced Checks"),
        )

        await _publish(r, scan_id, "Baseline Complete", 8,
                       f"Baseline scan done — {len(all_findings)} findings so far",
                       vulns_found=len(all_findings))

        # ── Phase 3: AI Agent Loop ────────────────────────────────────────────
        # Fire all vulnerability types concurrently under the adaptive semaphore.
        # crawl_data and waf_info are passed to eliminate redundant re-crawling
        # inside fallback scanners.
        completed     = [0]
        total_phases  = len(_AI_VULN_PHASES)

        async def _run_one(vuln_type: str) -> None:
            """Run a single vulnerability scan under the semaphore."""
            async with sem:
                if cancel_event.is_set():
                    return

                async with findings_lock:
                    pct = min(92, 8 + completed[0] * (84 // total_phases))
                    deduped_init = _deduplicate_vulns(all_findings)
                    await _publish(
                        r, scan_id,
                        phase="AI Scan",
                        progress=pct,
                        message=f"AI: Testing — {vuln_type}…",
                        vulns_found=len(deduped_init),
                        vulnerabilities=deduped_init,
                    )

                try:
                    result = await asyncio.wait_for(
                        scan_vulnerability_with_ai(
                            target_url,
                            vuln_type,
                            cancel_event=cancel_event,
                            stop_event=stop_event,
                            crawl_data=crawl_data,
                            waf_info=waf_info,
                        ),
                        timeout=_VULN_TIMEOUT,
                    )
                    findings = result.get("findings", [])
                    async with findings_lock:
                        if findings:
                            all_findings.extend(findings)
                        
                        deduped = _deduplicate_vulns(all_findings)
                        
                        await _save_incremental(scan_id, deduped, saved_keys)
                            
                        completed[0] += 1
                        pct = min(92, 8 + completed[0] * (84 // total_phases))
                        found_str = f" — {len(findings)} finding(s)" if findings else " — nothing found"
                        await _publish(
                            r, scan_id,
                            phase="AI Scan",
                            progress=pct,
                            message=(
                                f"AI: Finished {vuln_type}{found_str} "
                                f"({completed[0]}/{total_phases} complete)"
                            ),
                            vulns_found=len(deduped),
                            vulnerabilities=deduped,
                        )

                except asyncio.TimeoutError:
                    async with findings_lock:
                        completed[0] += 1
                        pct = min(92, 8 + completed[0] * (84 // total_phases))
                        deduped = _deduplicate_vulns(all_findings)
                        await _publish(
                            r, scan_id,
                            phase="Skipping (Timeout)",
                            progress=pct,
                            message=(
                                f"AI timed out on {vuln_type} after "
                                f"{_VULN_TIMEOUT}s — skipping "
                                f"({completed[0]}/{total_phases} complete)"
                            ),
                            vulns_found=len(deduped),
                            vulnerabilities=deduped,
                        )

                except Exception as vuln_err:
                    err_msg = str(vuln_err)
                    if any(kw in err_msg.upper() for kw in ["WAF", "BLOCK", "403", "CLOUDFLARE"]):
                        friendly = (
                            f"{vuln_type}: target blocked the AI probe (WAF/firewall) — skipping."
                        )
                    else:
                        friendly = f"Error on {vuln_type}: {err_msg} — continuing…"
                    async with findings_lock:
                        completed[0] += 1
                        pct = min(92, 8 + completed[0] * (84 // total_phases))
                        deduped = _deduplicate_vulns(all_findings)
                        await _publish(
                            r, scan_id,
                            phase="Skipping",
                            progress=pct,
                            message=friendly,
                            vulns_found=len(deduped),
                            vulnerabilities=deduped,
                        )

        # Fire all AI checks concurrently under the adaptive semaphore
        await asyncio.gather(*[
            _run_one(vuln_type)
            for vuln_type, _, _ in _AI_VULN_PHASES
        ])

        # ── Save final deduplicated results ───────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, all_findings, start_time)

        all_findings = _deduplicate_vulns(all_findings)

        await _publish(r, scan_id, "Saving Results", 95,
                       f"Deduplication complete — {len(all_findings)} unique AI findings...",
                       vulns_found=len(all_findings),
                       vulnerabilities=all_findings)

        threat_score = calculate_threat_score(all_findings)
        # Delete the incremental (pre-dedup) rows from SQLite and re-insert
        # only the clean deduplicated findings so no duplicate rows persist.
        await delete_scan_vulnerabilities(scan_id)
        for vuln in all_findings:
            await save_vulnerability(scan_id, vuln)
        duration     = time.time() - start_time
        await update_scan_results(scan_id, all_findings, duration, threat_score)

        await _publish(
            r, scan_id, "Completed", 100,
            f"AI Scan complete! Found {len(all_findings)} vulnerabilities "
            f"(Threat Score: {threat_score}/100) in {duration:.1f}s",
            done=True,
            vulns_found=len(all_findings),
            vulnerabilities=all_findings,
        )

        return {
            "scan_id":      scan_id,
            "total":        len(all_findings),
            "threat_score": threat_score,
        }

    except Exception as exc:
        await update_scan_status(scan_id, "error")
        await _publish(r, scan_id, "Error", 0,
                       f"AI scan failed: {exc}", done=True)
        raise

    finally:
        cancel_watcher.cancel()
        await r.aclose()
