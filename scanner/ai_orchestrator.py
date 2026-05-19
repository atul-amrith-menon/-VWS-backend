# -*- coding: utf-8 -*-
"""
scanner/ai_orchestrator.py — Async AI Vulnerability Scanner Orchestrator
=========================================================================
Replaces the old Ollama-based synchronous orchestrator.

Changes from v1:
  • Removes `ollama` package entirely.
  • Uses `openai.AsyncOpenAI` pointed at a vLLM server (OpenAI-compatible API).
  • Cold-start elimination: one Base Model (e.g. Llama-3) stays hot in VRAM.
    LoRA adapters are injected per-call via the `model` parameter — no reload.
  • All LLM calls are `async def` (no ThreadPoolExecutor for AI calls).
  • Subprocess execution (`_run_python_code`) remains sync and is called via
    `asyncio.to_thread()` so it never blocks the event loop.
  • `scan_vulnerability_with_ai()` is now `async def` so tasks.py can
    `await` it directly inside `run_ai_scan_task`.

Environment variables:
    VLLM_BASE_URL      — vLLM server URL  (default: http://localhost:8000/v1)
    VLLM_API_KEY       — API key if vLLM is behind auth (default: "not-needed")
    ANALYST_ADAPTER    — LoRA adapter ID for Analyst role
    EXECUTOR_ADAPTER   — LoRA adapter ID for Executor role
    AI_CALL_TIMEOUT    — seconds per LLM call (default: 350)
"""

import asyncio
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from typing import Optional

from dotenv import load_dotenv
load_dotenv()   # must run before AsyncOpenAI reads VLLM_BASE_URL from os.getenv

from openai import AsyncOpenAI

# ── vLLM client (singleton) ───────────────────────────────────────────────────
# The base model is always loaded in VRAM on the vLLM server.
# Passing a LoRA adapter ID as `model` injects the adapter weights on-the-fly
# (~milliseconds), not a full model reload (~minutes). This eliminates cold starts.
_vllm_client = AsyncOpenAI(
    base_url=os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1"),
    api_key=os.getenv("VLLM_API_KEY", "not-needed"),
)

# ── LoRA adapter IDs (registered with the vLLM server at startup) ─────────────
ANALYST_ADAPTER  = os.getenv("ANALYST_ADAPTER",  "vultix-analyst-lora")
EXECUTOR_ADAPTER = os.getenv("EXECUTOR_ADAPTER", "vultix-executor-lora")

# ── Timeouts ──────────────────────────────────────────────────────────────────
AI_CALL_TIMEOUT = int(os.getenv("AI_CALL_TIMEOUT", "480"))  # seconds per LLM call (first call loads VRAM)

# ── Local fallback scanners (unchanged from v1) ───────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from scanner.sqli_scanner import SQLiScanner          # noqa: E402
from scanner.xss_scanner import XSSScanner            # noqa: E402
from scanner.advanced_scanner import AdvancedScanner  # noqa: E402
from scanner.nmap_scanner import run_nmap_scan        # noqa: E402
from scanner.crawler import Crawler                   # noqa: E402


# ════════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPTS  (identical to v1 — battle-tested in production)
# ════════════════════════════════════════════════════════════════════════════════

ANALYST_SYSTEM_PROMPT = textwrap.dedent("""
    You are the Lead Web Security Analyst in an automated vulnerability scanning pipeline.
    Your job is to orchestrate safe, non-destructive security tests against a given target URL.

    You operate in two modes depending on the message you receive:

    ── MODE 1: PLAN (first message per vulnerability) ──────────────────
    You will receive:
        Target: <URL>
        Vulnerability Type: <Type>

    You must:
    1. Reason about what attack vectors are relevant for this vulnerability on this URL.
    2. Produce a clear, specific instruction block for the Executor Agent.
       The instruction block must include:
         - The exact Python `requests` code pattern to use.
         - The specific payload(s) to inject (benign only).
         - Which URL parameter, form field, or header to target.
         - What to look for in the HTTP response to confirm the vulnerability.

    ── MODE 2: REVIEW (after Executor runs the test) ───────────────────
    You will receive:
        Attempt: <N> of 2
        Executor Output:
        <raw output from the test script>

    You must:
    1. Carefully analyze the raw HTTP output (status codes, headers, body snippets).

    ── WAF / BOT-BLOCK DETECTION ──────────────────────────────────
    A request is likely BLOCKED if the output shows:
      - HTTP status 403 Forbidden or 406 Not Acceptable
      - Body contains: "Access Denied", "Blocked", "Forbidden", "Cloudflare",
        "captcha", "security check", "unusual traffic", "cf-ray"
      - Response body is unusually short (<200 chars)

    If Attempt 1 was BLOCKED, your RETRY instruction MUST include ONE evasion technique:
      a) URL-encode the payload  b) Double URL-encode  c) HTML entity encoding
      d) Add browser-like headers  e) Fragment the payload  f) Switch GET↔POST

    2. Make a definitive decision — choose EXACTLY ONE of:

       a) CONFIRMED: <Vulnerability Type>
          Then provide: Description, Evidence, Remediation.

       b) RETRY: <short reason + evasion technique>
          Only use on Attempt 1. Provide revised Executor instructions.

       c) FALLBACK_TRIGGERED: <Vulnerability Type>
          Use when Attempt 2 was also blocked or inconclusive.

    ── HARD RULES ───────────────────────────────────────────────────────
    - Maximum 2 attempts. After Attempt 2, output CONFIRMED or FALLBACK_TRIGGERED.
    - Only confirm if evidence is definitive (SQL error, reflected payload, redirect).
    - A 403 alone is NOT confirmation. Never hallucinate results.
""").strip()


EXECUTOR_SYSTEM_PROMPT = textwrap.dedent("""
    You are the Security Testing Executor Agent in an automated vulnerability scanning pipeline.
    Your job is to write clean, self-contained Python scripts that test a target URL for
    a specific security vulnerability, based on exact instructions from the Lead Analyst.

    ── YOUR OUTPUT FORMAT ───────────────────────────────────────────
    Output ONLY a single Python code block. Nothing else. The code must:
    1. Import only standard library modules and `requests`.
    2. Be completely self-contained — runs with `python script.py` with no arguments.
    3. Have the target URL hardcoded.
    4. Print: full URL tested, HTTP status code, key response headers,
       first 800 chars of response body, any specific pattern found.
    5. Use try/except for network errors.
    6. Disable SSL verification with `verify=False`.
    7. Use a 15-second timeout on all requests.

    ── MANDATORY HEADERS (always include) ───────────────────────────
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })

    ── WAF EVASION (apply when instructed) ─────────────────────────
      - "URL-encode payload":   urllib.parse.quote(payload)
      - "Double URL-encode":    urllib.parse.quote(urllib.parse.quote(payload))
      - "Switch to POST":       send payload as POST body
      - "Fragment payload":     split string with concatenation

    ── CONSTRAINTS ─────────────────────────────────────────────────
    - Use ONLY benign payloads (no DROP TABLE, no shell spawning).
    - Output ONLY the Python code block — no prose, no markdown explanation.
""").strip()


# ════════════════════════════════════════════════════════════════════════════════
# ASYNC LLM HELPER
# ════════════════════════════════════════════════════════════════════════════════

async def _chat_async(adapter_id: str, system: str, messages: list) -> str:
    """
    Send a chat completion request to the vLLM server, injecting the specified
    LoRA adapter via the `model` parameter.

    The base model stays hot in VRAM permanently.
    Switching adapters costs ~milliseconds, not minutes.

    Raises asyncio.TimeoutError if the server doesn't respond within AI_CALL_TIMEOUT.
    """
    response = await asyncio.wait_for(
        _vllm_client.chat.completions.create(
            model=adapter_id,
            messages=[{"role": "system", "content": system}, *messages],
            temperature=0.1,
            max_tokens=2048,
        ),
        timeout=AI_CALL_TIMEOUT,
    )
    return response.choices[0].message.content.strip()


# ════════════════════════════════════════════════════════════════════════════════
# SYNC HELPERS  (called via asyncio.to_thread — never block the event loop)
# ════════════════════════════════════════════════════════════════════════════════

def _extract_python_code(text: str) -> Optional[str]:
    """Extract a Python code block from a markdown-fenced response."""
    match = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    if "import requests" in text or "import urllib" in text:
        return text.strip()
    return None


def _run_python_code(code: str, timeout: int = 25) -> str:
    """
    Write generated code to a temp file and run it in a subprocess.
    Returns combined stdout + stderr. Safe to call from asyncio.to_thread().
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.stderr.strip():
            output += "\n[STDERR]\n" + result.stderr
        return output.strip() or "[No output from script]"
    except subprocess.TimeoutExpired:
        return "[EXECUTOR_ERROR: Script timed out after 25 seconds]"
    except Exception as exc:
        return f"[EXECUTOR_ERROR: {exc}]"
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _parse_analyst_decision(response: str) -> str:
    """Return 'CONFIRMED', 'RETRY', or 'FALLBACK_TRIGGERED'."""
    upper = response.upper()
    if "CONFIRMED:" in upper:
        return "CONFIRMED"
    if "RETRY:" in upper:
        return "RETRY"
    return "FALLBACK_TRIGGERED"


# ════════════════════════════════════════════════════════════════════════════════
# OUTPUT CLEANER  — strips internal chain-of-thought from AI reports
# ════════════════════════════════════════════════════════════════════════════════

def _clean_ai_description(raw: str, vuln_type: str) -> tuple[str, str]:
    """
    Parse the Analyst's CONFIRMED output into a clean (description, solution) pair.

    The Analyst mixes planning text, Python code, markdown, and decision keywords
    into its report. This function strips all of that and extracts only the human-
    readable summary and remediation steps.

    Returns:
        (description, solution) — both plain-text strings suitable for the frontend.
    """
    # Remove fenced code blocks (```python ... ``` or ``` ... ```)
    text = re.sub(r"```[\s\S]*?```", "", raw)

    # Remove leading decision keywords and metadata lines
    text = re.sub(
        r"^(CONFIRMED:|RETRY:|FALLBACK_TRIGGERED:|###|\*\*|Attempt:\s*\d|Executor Output:)[^\n]*",
        "",
        text,
        flags=re.MULTILINE | re.IGNORECASE,
    )

    # Remove markdown headers (## Heading, ### Heading)
    text = re.sub(r"^#{1,4}\s+", "", text, flags=re.MULTILINE)

    # Remove bold markers (**text**)
    text = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", text)

    # Remove lines that look like Python/code (import, requests., print(, =, etc.)
    text = re.sub(
        r"^\s*(import\s|from\s|session\s*=|requests\.|response\s*=|print\(|url\s*=|data\s*=|payload\s*=).*$",
        "",
        text,
        flags=re.MULTILINE,
    )

    # Collapse excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    # ── Extract a Description and Remediation section if present ──
    desc_match = re.search(
        r"(description|summary|finding|vulnerability)[:\s]+([^\n]{20,})",
        text, re.IGNORECASE
    )
    remed_match = re.search(
        r"(remediation|recommendation|solution|fix|mitigation)[:\s]+([\s\S]{20,})",
        text, re.IGNORECASE
    )

    if desc_match:
        description = desc_match.group(2).strip()
    else:
        # Use first substantive paragraph as description
        paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 40]
        description = paragraphs[0] if paragraphs else f"{vuln_type} vulnerability detected."

    if remed_match:
        solution = remed_match.group(2).strip().split("\n")[0].strip()
    else:
        solution = "Review the identified vulnerability and apply appropriate security controls."

    # Final safety — if description is still too long or has code, truncate cleanly
    if len(description) > 600:
        description = description[:600].rsplit(".", 1)[0] + "."

    return description, solution


# ════════════════════════════════════════════════════════════════════════════════
# LOCAL FALLBACK DISPATCHER
# ════════════════════════════════════════════════════════════════════════════════

# Vuln types with no local scanner equivalent — return empty on fallback
_AI_ONLY_TYPES = [
    "ssrf", "server-side request forgery",
    "cors", "idor", "insecure direct object",
    "business logic", "api endpoint",
    "http parameter pollution", "hpp",
    "xxe", "xml external entity",
]


def _run_local_fallback(target_url: str, vuln_type: str, session, stop_event=None) -> list:
    """
    Run the appropriate local scanner as a fallback when AI is inconclusive.
    Sync function — called via asyncio.to_thread() in the scan loop below.
    Returns a list of vulnerability dicts in the standard format.
    """
    vuln_lower = vuln_type.lower()

    if any(kw in vuln_lower for kw in _AI_ONLY_TYPES):
        return []  # No local scanner for AI-only types

    crawler    = Crawler(target_url)
    crawl_data = crawler.crawl()
    pages            = crawl_data.get("pages", [])
    forms            = crawl_data.get("forms", [])
    urls_with_params = crawl_data.get("urls_with_params", [])

    if "sql" in vuln_lower:
        s = SQLiScanner(session=session)
        for u in urls_with_params: s.scan_url_params(u)
        for f in forms:            s.scan_form(f)
        return s.get_results()

    if "xss" in vuln_lower or "cross-site scripting" in vuln_lower:
        s = XSSScanner(session=session)
        for u in urls_with_params: s.scan_url_params(u)
        for f in forms:            s.scan_form(f)
        return s.get_results()

    if "nmap" in vuln_lower or "infrastructure" in vuln_lower or "port scan" in vuln_lower:
        # Run Nmap directly — pass stop_event so it can be killed on cancel
        return run_nmap_scan(target_url, stop_event=stop_event)

    if any(k in vuln_lower for k in ["csrf", "redirect", "traversal",
                                      "clickjack", "weak auth", "sensitive data"]):
        s = AdvancedScanner(session=session)
        s.run_all(target_url, pages, forms, urls_with_params)
        return s.get_results()

    return []  # Unknown type — safe default


# ════════════════════════════════════════════════════════════════════════════════
# CORE ASYNC SCAN LOOP
# ════════════════════════════════════════════════════════════════════════════════

async def scan_vulnerability_with_ai(
    target_url: str,
    vuln_type: str,
    max_attempts: int = 2,
    cancel_event: Optional[asyncio.Event] = None,
    stop_event=None,   # threading.Event — kills blocking subprocesses immediately
) -> dict:
    """
    Async AI-powered scan loop for a single vulnerability type.

    Workflow:
      1. Analyst (ANALYST_ADAPTER LoRA) plans the attack.
      2. Executor (EXECUTOR_ADAPTER LoRA) writes the test script.
      3. Script runs in a subprocess via asyncio.to_thread() — non-blocking.
      4. Analyst reviews the output and decides: CONFIRMED / RETRY / FALLBACK.
      5. After max_attempts, triggers the local fallback scanner if available.

    Returns:
        {
            "vuln_type":  str,
            "method":     "ai" | "fallback",
            "success":    bool,
            "findings":   list[dict],
            "ai_report":  str | None,
            "log":        list[str],
        }
    """
    import requests as _requests

    log    = []
    result = {
        "vuln_type": vuln_type,
        "method":    "ai",
        "success":   False,
        "findings":  [],
        "ai_report": None,
        "log":       log,
    }

    # Shared session for fallback scanners
    session = _requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
    })

    # ── Step 1: Analyst plans ─────────────────────────────────────────────────
    if cancel_event and cancel_event.is_set():
        return result

    plan_prompt = f"Target: {target_url}\nVulnerability Type: {vuln_type}"
    log.append(f"[Analyst] Planning: {vuln_type} on {target_url}")

    try:
        analyst_messages = [{"role": "user", "content": plan_prompt}]
        analyst_plan = await _chat_async(
            ANALYST_ADAPTER, ANALYST_SYSTEM_PROMPT, analyst_messages
        )
        log.append(f"[Analyst] Plan received ({len(analyst_plan)} chars)")
    except Exception as exc:
        log.append(f"[ERROR] Analyst failed: {exc}")
        result["method"]   = "fallback"
        if not (cancel_event and cancel_event.is_set()):
            result["findings"] = await asyncio.to_thread(
                _run_local_fallback, target_url, vuln_type, session, stop_event
            )
        return result

    # ── Step 2 & 3: Attempt loop ──────────────────────────────────────────────
    conversation = list(analyst_messages) + [{"role": "assistant", "content": analyst_plan}]

    for attempt in range(1, max_attempts + 1):
        log.append(f"[Executor] Attempt {attempt}/{max_attempts}")

        # Executor writes test script (EXECUTOR_ADAPTER)
        if cancel_event and cancel_event.is_set():
            return result

        try:
            executor_response = await _chat_async(
                EXECUTOR_ADAPTER,
                EXECUTOR_SYSTEM_PROMPT,
                [{"role": "user", "content": analyst_plan}],
            )
        except Exception as exc:
            log.append(f"[ERROR] Executor failed: {exc}")
            break

        code = _extract_python_code(executor_response)
        if not code:
            execution_output = "[EXECUTOR_ERROR: No valid Python code extracted]"
            log.append("[Executor] No code extracted")
        else:
            log.append(f"[Executor] Running script ({len(code)} chars)...")
            execution_output = await asyncio.to_thread(_run_python_code, code)
            log.append(f"[Executor] Output: {execution_output[:200]}...")

        # Check cancel before Analyst review
        if cancel_event and cancel_event.is_set():
            return result

        # Analyst reviews output (ANALYST_ADAPTER)
        review_prompt = (
            f"Attempt: {attempt} of {max_attempts}\n"
            f"Executor Output:\n{execution_output}"
        )
        conversation.append({"role": "user", "content": review_prompt})

        try:
            analyst_review = await _chat_async(
                ANALYST_ADAPTER, ANALYST_SYSTEM_PROMPT, conversation
            )
        except Exception as exc:
            log.append(f"[ERROR] Analyst review failed: {exc}")
            break

        conversation.append({"role": "assistant", "content": analyst_review})
        decision = _parse_analyst_decision(analyst_review)
        log.append(f"[Analyst] Decision: {decision}")

        if decision == "CONFIRMED":
            description, solution = _clean_ai_description(analyst_review, vuln_type)
            # Determine risk level from analyst review text
            review_upper = analyst_review.upper()
            if any(w in review_upper for w in ["CRITICAL", "HIGH", "SEVERE"]):
                risk = "High"
            elif "MEDIUM" in review_upper or "MODERATE" in review_upper:
                risk = "Medium"
            else:
                risk = "High"   # AI confirmations are typically significant

            # Clean evidence — keep only the test result, not the script
            evidence_lines = [
                line for line in execution_output.splitlines()
                if not any(kw in line for kw in ["import ", "session.", "requests.", "print("])
            ]
            clean_evidence = "\n".join(evidence_lines[:15]).strip()[:600]

            result["success"]   = True
            result["method"]    = "ai"
            result["ai_report"] = analyst_review
            result["findings"].append({
                "vuln_type":   vuln_type,
                "risk_level":  risk,
                "url":         target_url,
                "description": description,
                "evidence":    clean_evidence or execution_output[:300],
                "solution":    solution,
            })
            return result

        elif decision == "RETRY" and attempt < max_attempts:
            analyst_plan = analyst_review  # Updated instructions for retry
            continue

        else:
            break  # FALLBACK_TRIGGERED or last attempt

    # ── AI inconclusive — run local fallback ──────────────────────────────────
    log.append(f"[FALLBACK] AI inconclusive for {vuln_type}")
    result["method"] = "fallback"
    if not (cancel_event and cancel_event.is_set()):
        result["findings"] = await asyncio.to_thread(
            _run_local_fallback, target_url, vuln_type, session, stop_event
        )
    return result


# ════════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════════

# Full list of vulnerability types tested by the AI scan pipeline.
# tasks.py iterates over this list and calls scan_vulnerability_with_ai() per type.
VULN_TYPES = [
    # Core types — local fallback scanners exist for these
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Infrastructure & Port Scan (Nmap)",
    "CSRF",
    "Directory Traversal",
    "Open Redirect",
    "Clickjacking",
    "Sensitive Data Exposure",
    "Weak Authentication",
    # Advanced AI-only types — no local fallback
    "Server-Side Request Forgery (SSRF)",
    "CORS Misconfiguration",
    "Insecure Direct Object Reference (IDOR)",
    "Business Logic & API Endpoint Discovery",
    "HTTP Parameter Pollution (HPP)",
    "XML External Entity (XXE) Injection",
]


async def run_ai_scan(target_url: str, vuln_types: Optional[list] = None) -> dict:
    """
    Run a full async AI-driven vulnerability scan on the target URL.
    Convenience wrapper used by the CLI and tests. In production the
    Taskiq worker (tasks.py) calls scan_vulnerability_with_ai() directly.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    types_to_test = vuln_types or VULN_TYPES
    all_findings: list  = []
    ai_findings: list   = []
    fb_findings: list   = []
    full_log: list      = []
    summary: dict       = {}

    for vuln_type in types_to_test:
        scan_result = await scan_vulnerability_with_ai(target_url, vuln_type)
        full_log.extend(scan_result["log"])
        summary[vuln_type] = {
            "method":  scan_result["method"],
            "success": scan_result["success"],
            "count":   len(scan_result["findings"]),
        }
        for finding in scan_result["findings"]:
            all_findings.append(finding)
            if scan_result["method"] == "ai":
                ai_findings.append(finding)
            else:
                fb_findings.append(finding)

    return {
        "target":             target_url,
        "all_findings":       all_findings,
        "ai_findings":        ai_findings,
        "fallback_findings":  fb_findings,
        "scan_log":           full_log,
        "summary":            summary,
    }


# ════════════════════════════════════════════════════════════════════════════════
# CLI — quick test
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    async def _main():
        target  = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
        results = await run_ai_scan(target)
        print(json.dumps(results["summary"], indent=2))
        print(f"\nTotal vulnerabilities: {len(results['all_findings'])}")

    asyncio.run(_main())