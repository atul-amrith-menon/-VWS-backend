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
        "phase":    str,   # human-readable phase name
        "progress": int,   # 0-100
        "message":  str,   # detail message shown on the frontend
        "done":     bool   # True only on the final event
    }
"""

import asyncio
import json
import os
import threading
import time
from typing import Optional

import redis.asyncio as aioredis

from broker import broker
from models.scan_db import (
    calculate_threat_score,
    get_scan,
    save_vulnerability,
    update_scan_results,
    update_scan_status,
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication helper
# ─────────────────────────────────────────────────────────────────────────────

def _deduplicate_vulns(vulns: list) -> list:
    """
    Collapse duplicate vulnerability findings into a single entry.

    Two findings are considered duplicates when they share the same
    `vuln_type` AND `url`.  When duplicates are found:
      - The first occurrence is kept as the base.
      - Each subsequent duplicate's `evidence` is appended to the base
        (separated by a visible delimiter) as long as the text is new.
      - The base `description` is updated to note multiple instances.

    The ordering is preserved: the first occurrence's risk_level and
    severity are kept, since the scanners already rank the worst case first.
    """
    seen: dict = {}   # key -> index in `result`
    result: list = []

    for vuln in vulns:
        key = (vuln.get("vuln_type", "").strip().lower(),
               vuln.get("url", "").strip().rstrip("/").lower())

        if key not in seen:
            seen[key] = len(result)
            result.append(dict(vuln))   # work on a copy
        else:
            base = result[seen[key]]
            extra_evidence = (vuln.get("evidence") or "").strip()
            if extra_evidence and extra_evidence not in (base.get("evidence") or ""):
                delimiter = "\n\n--- [Additional Instance] ---\n"
                base["evidence"] = (base.get("evidence") or "") + delimiter + extra_evidence
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
) -> None:
    """Publish a progress event to the Redis channel for this scan."""
    payload = json.dumps({
        "phase":    phase,
        "progress": progress,
        "message":  message,
        "done":     done,
    })
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
    threat_score = calculate_threat_score(vulns)

    for vuln in vulns:
        await save_vulnerability(scan_id, vuln)

    await update_scan_results(scan_id, vulns, duration, threat_score)
    await update_scan_status(scan_id, "cancelled")

    await _publish(
        r, scan_id,
        phase="Cancelled",
        progress=100,
        message=f"Scan cancelled. {len(vulns)} vulnerabilities found before cancellation.",
        done=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Task 1 — Traditional scanner pipeline
# ─────────────────────────────────────────────────────────────────────────────

@broker.task
async def run_scan_task(target_url: str, scan_id: int) -> dict:
    """
    Runs the full traditional scanner pipeline as a Taskiq task.

    Phases mirror the old ScannerEngine.run() but:
      - Each sync scanner call is wrapped in asyncio.to_thread()
      - Progress is published to Redis (not written to a local dict)
      - Cancellation is checked via an asyncio.Event (not a dict flag)
    """
    # Lazy imports — sub-scanners only needed inside the worker process
    import requests as _requests
    from scanner.crawler import Crawler
    from scanner.sqli_scanner import SQLiScanner
    from scanner.xss_scanner import XSSScanner
    from scanner.misconfig_scanner import MisconfigScanner
    from scanner.advanced_scanner import AdvancedScanner

    start_time   = time.time()
    vulns: list  = []
    cancel_event = asyncio.Event()
    # threading.Event shared with sync workers (e.g. nmap) so they can be
    # killed immediately when the user clicks Cancel, even mid-subprocess.
    stop_event   = threading.Event()

    # Normalise URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    target_url = target_url.rstrip("/")

    # Shared requests session (sync, used inside to_thread calls)
    session = _requests.Session()
    session.headers.update({
        "User-Agent": "Vultix/2.0 Security Scanner (Educational)",
    })

    r = aioredis.from_url(REDIS_URL, decode_responses=True)

    # Start the cancel-watcher in the background.
    # When a cancel arrives: set asyncio cancel_event (checked between phases)
    # AND set threading stop_event (kills blocking subprocesses like Nmap instantly).
    async def _watch_and_propagate():
        await _watch_cancel.__wrapped__(scan_id, cancel_event) if hasattr(_watch_cancel, '__wrapped__') else None
        r2 = aioredis.from_url(REDIS_URL, decode_responses=True)
        pub2 = r2.pubsub()
        await pub2.subscribe(f"scan:cancel:{scan_id}")
        try:
            async for msg in pub2.listen():
                if msg["type"] == "message":
                    cancel_event.set()
                    stop_event.set()   # <-- kills blocking subprocess immediately
                    break
        finally:
            await pub2.unsubscribe(f"scan:cancel:{scan_id}")
            await r2.aclose()

    cancel_watcher = asyncio.create_task(_watch_and_propagate())

    try:
        # ── Phase 1: Crawling ─────────────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        await _publish(r, scan_id, "Crawling", 8, f"Crawling {target_url}...")

        crawler   = Crawler(target_url)
        crawl_data = await asyncio.to_thread(crawler.crawl)

        pages            = crawl_data["pages"]
        forms            = crawl_data["forms"]
        urls_with_params = crawl_data["urls_with_params"]

        await _publish(
            r, scan_id, "Crawling Complete", 18,
            f"Found {len(pages)} pages, {len(forms)} forms, "
            f"{len(urls_with_params)} parameterised URLs",
        )

        # ── Phase 2: SQL Injection ────────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        await _publish(r, scan_id, "SQL Injection Testing", 25,
                       "Testing for SQL Injection vulnerabilities...")

        def _run_sqli():
            scanner = SQLiScanner(session=session)
            for url in urls_with_params:
                scanner.scan_url_params(url)
            for form in forms:
                scanner.scan_form(form)
            return scanner.get_results()

        vulns.extend(await asyncio.to_thread(_run_sqli))

        # ── Phase 3: XSS ──────────────────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        await _publish(r, scan_id, "XSS Testing", 38,
                       "Testing for Cross-Site Scripting vulnerabilities...")

        def _run_xss():
            scanner = XSSScanner(session=session)
            for url in urls_with_params:
                scanner.scan_url_params(url)
            for form in forms:
                scanner.scan_form(form)
            return scanner.get_results()

        vulns.extend(await asyncio.to_thread(_run_xss))

        # ── Phase 4: Misconfiguration ─────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        await _publish(r, scan_id, "Misconfig & Nmap Analysis", 50,
                       "Checking misconfigurations and scanning infrastructure (Nmap)...")

        def _run_misconfig():
            from scanner.nmap_scanner import run_nmap_scan

            scanner = MisconfigScanner(session=session)
            if pages:
                scanner.scan_headers(pages[0])
            scanner.scan_sensitive_files(target_url)
            scanner.check_https(target_url)

            results = scanner.get_results()
            # Pass stop_event so Nmap subprocess is killed the instant Cancel is clicked
            results.extend(run_nmap_scan(target_url, stop_event=stop_event))
            return results

        vulns.extend(await asyncio.to_thread(_run_misconfig))

        # ── Phase 5: Advanced checks ──────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        await _publish(r, scan_id, "Advanced Security Checks", 65,
                       "Running CSRF, clickjacking, directory traversal, open redirect checks...")

        def _run_advanced():
            scanner = AdvancedScanner(session=session)
            scanner.run_all(target_url, pages, forms, urls_with_params)
            return scanner.get_results()

        vulns.extend(await asyncio.to_thread(_run_advanced))

        # ── Phase 6: Deduplicate + Save results ──────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, vulns, start_time)

        vulns = _deduplicate_vulns(vulns)

        await _publish(r, scan_id, "Saving Results", 90,
                       f"Deduplication complete — saving {len(vulns)} unique findings...")

        threat_score = calculate_threat_score(vulns)
        for vuln in vulns:
            await save_vulnerability(scan_id, vuln)

        duration = time.time() - start_time
        await update_scan_results(scan_id, vulns, duration, threat_score)

        await _publish(
            r, scan_id, "Completed", 100,
            f"Scan complete! Found {len(vulns)} vulnerabilities "
            f"(Threat Score: {threat_score}/100) in {duration:.1f}s",
            done=True,
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
# Task 2 — AI-powered scan pipeline
# ─────────────────────────────────────────────────────────────────────────────

# Phase labels mirror AIScannerEngine._VULN_PHASES from the old scanner_engine.py
_AI_VULN_PHASES = [
    ("SQL Injection",                            8,  "AI: Planning SQL Injection attack..."),
    ("Cross-Site Scripting (XSS)",              14,  "AI: Testing for XSS vulnerabilities..."),
    ("Infrastructure & Port Scan (Nmap)",       21,  "AI: Scanning infrastructure and open ports..."),
    ("CSRF",                                    28,  "AI: Analysing CSRF token protections..."),
    ("Directory Traversal",                     35,  "AI: Testing directory traversal paths..."),
    ("Open Redirect",                           41,  "AI: Checking open redirect parameters..."),
    ("Clickjacking",                            47,  "AI: Checking clickjacking headers..."),
    ("Sensitive Data Exposure",                 53,  "AI: Scanning for sensitive data leaks..."),
    ("Weak Authentication",                     59,  "AI: Evaluating authentication strength..."),
    ("Server-Side Request Forgery (SSRF)",      65,  "AI: Probing for SSRF attack vectors..."),
    ("CORS Misconfiguration",                   71,  "AI: Testing cross-origin resource sharing policy..."),
    ("Insecure Direct Object Reference (IDOR)", 77,  "AI: Testing IDOR via ID parameter enumeration..."),
    ("Business Logic & API Endpoint Discovery", 82,  "AI: Discovering hidden API endpoints & logic flaws..."),
    ("HTTP Parameter Pollution (HPP)",          87,  "AI: Testing parameter pollution vectors..."),
    ("XML External Entity (XXE) Injection",     92,  "AI: Testing XXE injection via XML inputs..."),
]

# Per-vulnerability timeout in seconds (enforced in the worker)
_VULN_TIMEOUT = 320


@broker.task
async def run_ai_scan_task(target_url: str, scan_id: int) -> dict:
    """
    Runs the AI-powered scan pipeline as a Taskiq task.

    Uses the new async ai_orchestrator (Phase 6) which talks to vLLM
    via the openai package. Each vulnerability type is tested with a
    configurable timeout so a slow vLLM response can't stall the entire scan.

    Cancellation is checked between vulnerability types (same asyncio.Event
    pattern as run_scan_task).
    """
    from scanner.ai_orchestrator import scan_vulnerability_with_ai

    start_time   = time.time()
    all_findings: list = []
    cancel_event = asyncio.Event()
    stop_event   = threading.Event()  # kills blocking subprocesses (Nmap) instantly

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
                    stop_event.set()   # <-- kills Nmap subprocess instantly
                    break
        finally:
            await pub2.unsubscribe(f"scan:cancel:{scan_id}")
            await r2.aclose()

    cancel_watcher = asyncio.create_task(_ai_watch_cancel())

    try:
        # ── Initialise ────────────────────────────────────────────────────────
        await _publish(r, scan_id, "AI Agents Initialising", 2,
                       "Connecting to vLLM server and preparing baseline scanners...")

        # ── Baseline Scan (Traditional) ───────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, all_findings, start_time)

        await _publish(r, scan_id, "Baseline Scan", 5,
                       "Running traditional security checks (Crawling, SQLi, XSS, Nmap)...")

        def _run_baseline():
            import requests as _requests
            from scanner.crawler import Crawler
            from scanner.sqli_scanner import SQLiScanner
            from scanner.xss_scanner import XSSScanner
            from scanner.misconfig_scanner import MisconfigScanner
            from scanner.advanced_scanner import AdvancedScanner
            from scanner.nmap_scanner import run_nmap_scan

            session = _requests.Session()
            session.headers.update({"User-Agent": "Vultix/2.0 Security Scanner (Educational)"})
            trad_vulns = []

            # Crawl
            crawler = Crawler(target_url)
            crawl_data = crawler.crawl()

            # SQLi
            sqli = SQLiScanner(session=session)
            for u in crawl_data["urls_with_params"]: sqli.scan_url_params(u)
            for f in crawl_data["forms"]: sqli.scan_form(f)
            trad_vulns.extend(sqli.get_results())

            # XSS
            xss = XSSScanner(session=session)
            for u in crawl_data["urls_with_params"]: xss.scan_url_params(u)
            for f in crawl_data["forms"]: xss.scan_form(f)
            trad_vulns.extend(xss.get_results())

            # Misconfig & Nmap
            misc = MisconfigScanner(session=session)
            if crawl_data["pages"]: misc.scan_headers(crawl_data["pages"][0])
            misc.scan_sensitive_files(target_url)
            misc.check_https(target_url)
            trad_vulns.extend(misc.get_results())
            trad_vulns.extend(run_nmap_scan(target_url, stop_event=stop_event))

            # Advanced
            adv = AdvancedScanner(session=session)
            adv.run_all(target_url, crawl_data["pages"], crawl_data["forms"], crawl_data["urls_with_params"])
            trad_vulns.extend(adv.get_results())

            return trad_vulns

        baseline_findings = await asyncio.to_thread(_run_baseline)
        all_findings.extend(baseline_findings)

        # ── Per-vulnerability AI loop ─────────────────────────────────────────
        for vuln_type, progress_pct, phase_msg in _AI_VULN_PHASES:

            if cancel_event.is_set():
                return await _finish_cancelled(r, scan_id, all_findings, start_time)

            await _publish(
                r, scan_id,
                phase=phase_msg.split(":")[0],
                progress=progress_pct,
                message=phase_msg,
            )

            try:
                result = await asyncio.wait_for(
                    scan_vulnerability_with_ai(
                        target_url,
                        vuln_type,
                        cancel_event=cancel_event,
                        stop_event=stop_event,
                    ),
                    timeout=_VULN_TIMEOUT,
                )
                all_findings.extend(result.get("findings", []))

            except asyncio.TimeoutError:
                await _publish(
                    r, scan_id,
                    phase="Skipping (Timeout)",
                    progress=progress_pct,
                    message=(
                        f"AI timed out on {vuln_type} after "
                        f"{_VULN_TIMEOUT}s — skipping."
                    ),
                )

            except Exception as vuln_err:
                err_msg = str(vuln_err)
                if any(kw in err_msg.upper() for kw in ["WAF", "BLOCK", "403", "CLOUDFLARE"]):
                    friendly = f"{vuln_type}: target blocked the AI probe (WAF/firewall) — skipping."
                else:
                    friendly = f"Error on {vuln_type}: {err_msg} — continuing..."

                await _publish(
                    r, scan_id,
                    phase="Skipping",
                    progress=progress_pct,
                    message=friendly,
                )

        # ── Save results ──────────────────────────────────────────────────────
        if cancel_event.is_set():
            return await _finish_cancelled(r, scan_id, all_findings, start_time)

        all_findings = _deduplicate_vulns(all_findings)

        await _publish(r, scan_id, "Saving Results", 95,
                       f"Deduplication complete — saving {len(all_findings)} unique AI findings...")

        threat_score = calculate_threat_score(all_findings)
        for vuln in all_findings:
            await save_vulnerability(scan_id, vuln)

        duration = time.time() - start_time
        await update_scan_results(scan_id, all_findings, duration, threat_score)

        await _publish(
            r, scan_id, "Completed", 100,
            f"AI Scan complete! Found {len(all_findings)} vulnerabilities "
            f"(Threat Score: {threat_score}/100) in {duration:.1f}s",
            done=True,
        )

        return {
            "scan_id":     scan_id,
            "total":       len(all_findings),
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
