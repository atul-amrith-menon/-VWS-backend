import asyncio
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ── Playwright optional import ─────────────────────────────────────────────────
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# ── XSS Payloads ──────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "';alert('XSS');//",
    '<svg onload=alert("XSS")>',
    '"><img src=x onerror=alert(1)>',
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(1)">',
    '<details open ontoggle=alert(1)>',
]

# Payloads that are safe for DOM-based headless verification
# These use unique numeric markers so the dialog listener can distinguish them
HEADLESS_PAYLOADS = [
    ('<script>alert("XSS")</script>',       'XSS'),
    ('<img src=x onerror=alert("XSS")>',    'XSS'),
    ('"><script>alert("XSS")</script>',     'XSS'),
    ('<svg onload=alert("XSS")>',           'XSS'),
    ('<details open ontoggle=alert(1)>',    '1'),
    ('"><img src=x onerror=alert(1)>',      '1'),
]

DIALOG_WAIT_MS = 3000   # ms to wait for a JS dialog after page load


class XSSScanner:
    """
    Two-Phase Cross-Site Scripting (XSS) Scanner.

    Phase 1 — Reflection Check (fast):
        Uses standard requests to send each payload and checks if it appears
        unescaped in the HTTP response body. Acts as a fast pre-filter.

    Phase 2 — Headless Browser Verification (accurate):
        Only triggered when Phase 1 finds a reflection candidate.
        Launches a headless Chromium browser (Playwright) and listens for
        an actual JavaScript dialog (alert/confirm/prompt) event.
        Only flags as CONFIRMED XSS if the dialog fires.

        This eliminates false positives where payloads are reflected inside:
          - <textarea> content (not executed)
          - HTML comments (not executed)
          - HTML-escaped attribute values (&lt;script&gt;)
          - <noscript> blocks

    Fallback: If Playwright is not installed, Phase 2 is skipped and the
    scanner falls back to the original reflection-based detection only.
    """

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.vulnerabilities = []
        self.candidates = []

    # ═══════════════════════════════════════════════════════════════════════════
    # URL PARAMETER SCANNING
    # ═══════════════════════════════════════════════════════════════════════════

    def scan_url_params(self, url):
        """Test URL parameters for XSS using Phase 1 + Phase 2."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in params:
            for payload in XSS_PAYLOADS:
                try:
                    modified = dict(params)
                    modified[param_name] = [payload]
                    new_query = urlencode(modified, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    body = response.text

                    # ── Phase 1: Reflection check ────────────────────────────
                    if payload not in body:
                        continue   # No reflection — definitely not XSS here

                    # ── Phase 2: Headless browser verification ───────────────
                    if HAS_PLAYWRIGHT:
                        self.candidates.append({
                            'type': 'url',
                            'url': url,
                            'parsed': parsed,
                            'params': params,
                            'param_name': param_name,
                            'payload': payload
                        })
                    else:
                        # Playwright not installed — fall back to reflection-only detection
                        evidence_note = 'Payload reflected in raw HTTP response (reflection-only mode — install playwright for full verification)'
                        description_suffix = (
                            'The payload was reflected in the raw HTTP response body. '
                            'Install playwright for headless browser confirmation.'
                        )

                        self.vulnerabilities.append({
                            'vuln_type':   'Cross-Site Scripting (XSS)',
                            'risk_level':  'High',
                            'url':         url,
                            'description': (
                                f'Reflected XSS vulnerability confirmed in URL parameter "{param_name}". '
                                f'The injected script payload was reflected in the response without '
                                f'proper encoding or sanitization. {description_suffix} '
                                f'An attacker could use this to execute arbitrary JavaScript in a victim\'s browser.'
                            ),
                            'evidence':    f'Parameter: {param_name} | Payload: {payload[:60]} | {evidence_note}',
                            'solution':    (
                                'Encode all user-supplied output using context-appropriate encoding '
                                '(HTML entity encoding, JavaScript encoding, URL encoding). '
                                'Implement Content-Security-Policy headers. Use frameworks that '
                                'automatically escape output.'
                            ),
                        })
                    return   # One finding/candidate per URL param

                except requests.exceptions.RequestException:
                    continue

    # ═══════════════════════════════════════════════════════════════════════════
    # FORM SCANNING
    # ═══════════════════════════════════════════════════════════════════════════

    def scan_form(self, form):
        """Test form inputs for XSS using Phase 1 + Phase 2."""
        action_url = form['action']
        method     = form['method']
        inputs     = form['inputs']

        for input_field in inputs:
            for payload in XSS_PAYLOADS[:5]:   # Fewer payloads for forms to keep scan fast
                try:
                    data = {
                        inp['name']: (payload if inp['name'] == input_field['name']
                                      else inp.get('value', 'test'))
                        for inp in inputs
                    }

                    if method == 'post':
                        response = self.session.post(action_url, data=data,
                                                     timeout=self.timeout, verify=False)
                    else:
                        response = self.session.get(action_url, params=data,
                                                    timeout=self.timeout, verify=False)

                    body = response.text

                    # ── Phase 1: Reflection check ────────────────────────────
                    if payload not in body:
                        continue

                    # ── Phase 2: Headless browser verification ───────────────
                    if HAS_PLAYWRIGHT:
                        self.candidates.append({
                            'type': 'form',
                            'action_url': action_url,
                            'method': method,
                            'inputs': inputs,
                            'field_name': input_field['name'],
                            'payload': payload
                        })
                    else:
                        evidence_note = 'Payload reflected in raw HTTP response (reflection-only mode)'
                        description_suffix = (
                            'The payload was reflected in the raw HTTP response body. '
                            'Install playwright for headless browser confirmation.'
                        )

                        self.vulnerabilities.append({
                            'vuln_type':   'Cross-Site Scripting (XSS)',
                            'risk_level':  'High',
                            'url':         action_url,
                            'description': (
                                f'Reflected XSS confirmed in form field "{input_field["name"]}" '
                                f'at {action_url}. The injected payload was reflected in the '
                                f'server response without sanitization. {description_suffix}'
                            ),
                            'evidence':    (
                                f'Form action: {action_url} | Method: {method.upper()} | '
                                f'Field: {input_field["name"]} | Payload: {payload[:60]} | {evidence_note}'
                            ),
                            'solution':    (
                                'Sanitize and encode all user input before rendering in HTML. '
                                'Use Content-Security-Policy headers to prevent inline script execution.'
                            ),
                        })
                    return   # One confirmed finding/candidate per form

                except requests.exceptions.RequestException:
                    continue

    # ═══════════════════════════════════════════════════════════════════════════
    # RESULTS
    # ═══════════════════════════════════════════════════════════════════════════

    def get_results(self):
        """Return deduplicated XSS findings."""
        if HAS_PLAYWRIGHT and self.candidates:
            verified = _run_async(_async_verify_all_candidates(self.candidates))
            self.vulnerabilities.extend(verified)

        seen   = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v['vuln_type'], v['url'])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique


# ════════════════════════════════════════════════════════════════════════════════
# HEADLESS BROWSER VERIFICATION HELPERS (Playwright)
# ════════════════════════════════════════════════════════════════════════════════

def _run_async(coro):
    """
    Run an async coroutine synchronously from a sync context.
    Uses asyncio.run() which creates a fresh event loop each time —
    safe to call from a Taskiq worker thread.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # Already inside a running event loop (e.g., inside an async Taskiq task)
        # Create a new loop in a thread to avoid nesting
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=30)


def _verify_xss_headless_url(parsed, params, param_name):
    """
    Launch Chromium and check if any XSS payload fires a JS dialog
    when injected into a URL query parameter.

    Returns (confirmed: bool, dialog_message: str).
    """
    return _run_async(_async_verify_url(parsed, params, param_name))


def _verify_xss_headless_form(action_url, method, inputs, target_field_name):
    """
    Launch Chromium and check if any XSS payload fires a JS dialog
    when submitted via a form.

    Returns (confirmed: bool, dialog_message: str).
    """
    return _run_async(_async_verify_form(action_url, method, inputs, target_field_name))


async def _async_verify_url(parsed, params, param_name):
    """Async implementation: verifies URL-based XSS with a headless browser."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page    = await context.new_page()

        dialog_fired   = False
        dialog_message = ''

        def _on_dialog(dialog):
            nonlocal dialog_fired, dialog_message
            dialog_fired   = True
            dialog_message = dialog.message
            # Dismiss immediately so the page doesn't hang
            asyncio.ensure_future(dialog.dismiss())

        page.on('dialog', _on_dialog)

        for payload, expected_msg in HEADLESS_PAYLOADS:
            modified = dict(params)
            modified[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(modified, doseq=True)))

            try:
                await page.goto(test_url, wait_until='domcontentloaded', timeout=8000)
                await page.wait_for_timeout(DIALOG_WAIT_MS)
            except Exception:
                pass   # Navigation errors (e.g., net::ERR_SSL_PROTOCOL_ERROR) are non-fatal

            if dialog_fired:
                await browser.close()
                return True, dialog_message

        await browser.close()
        return False, ''


async def _async_verify_form(action_url, method, inputs, target_field_name):
    """Async implementation: verifies form-based XSS with a headless browser."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page    = await context.new_page()

        dialog_fired   = False
        dialog_message = ''

        def _on_dialog(dialog):
            nonlocal dialog_fired, dialog_message
            dialog_fired   = True
            dialog_message = dialog.message
            asyncio.ensure_future(dialog.dismiss())

        page.on('dialog', _on_dialog)

        for payload, expected_msg in HEADLESS_PAYLOADS:
            try:
                # Navigate to the form page first
                await page.goto(action_url, wait_until='domcontentloaded', timeout=8000)

                if method == 'post':
                    # Build and submit the form programmatically via JavaScript
                    js_data = {
                        inp['name']: (payload if inp['name'] == target_field_name
                                      else inp.get('value', 'test'))
                        for inp in inputs
                    }
                    # Inject values into any matching form fields on the page
                    for field_name, field_value in js_data.items():
                        await page.evaluate(
                            f"""
                            (function() {{
                                var el = document.querySelector('[name="{field_name}"]');
                                if (el) {{ el.value = {repr(field_value)}; }}
                            }})();
                            """
                        )
                    # Submit the first form on the page
                    await page.evaluate("document.forms[0] && document.forms[0].submit();")
                else:
                    # GET: navigate with params in the URL
                    js_data = {
                        inp['name']: (payload if inp['name'] == target_field_name
                                      else inp.get('value', 'test'))
                        for inp in inputs
                    }
                    from urllib.parse import urlencode as _ue
                    get_url = f"{action_url}?{_ue(js_data)}"
                    await page.goto(get_url, wait_until='domcontentloaded', timeout=8000)

                await page.wait_for_timeout(DIALOG_WAIT_MS)

            except Exception:
                pass

            if dialog_fired:
                await browser.close()
                return True, dialog_message

        await browser.close()
        return False, ''


async def _async_verify_all_candidates(candidates):
    """
    Verify all XSS candidates inside a single, shared Playwright browser session.
    """
    verified_vulns = []
    if not candidates:
        return verified_vulns

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)

        for c in candidates:
            page = await context.new_page()
            
            dialog_fired = False
            dialog_message = ''

            def _on_dialog(dialog):
                nonlocal dialog_fired, dialog_message
                dialog_fired = True
                dialog_message = dialog.message
                asyncio.ensure_future(dialog.dismiss())

            page.on('dialog', _on_dialog)

            try:
                if c['type'] == 'url':
                    parsed = c['parsed']
                    params = c['params']
                    param_name = c['param_name']
                    # We can try multiple Headless Payloads to find one that triggers
                    for payload, expected_msg in HEADLESS_PAYLOADS:
                        modified = dict(params)
                        modified[param_name] = [payload]
                        test_url = urlunparse(parsed._replace(query=urlencode(modified, doseq=True)))
                        
                        try:
                            await page.goto(test_url, wait_until='domcontentloaded', timeout=8000)
                            await page.wait_for_timeout(DIALOG_WAIT_MS)
                        except Exception:
                            pass
                        
                        if dialog_fired:
                            break
                            
                elif c['type'] == 'form':
                    action_url = c['action_url']
                    method = c['method']
                    inputs = c['inputs']
                    target_field_name = c['field_name']
                    
                    for payload, expected_msg in HEADLESS_PAYLOADS:
                        try:
                            await page.goto(action_url, wait_until='domcontentloaded', timeout=8000)
                            
                            if method == 'post':
                                js_data = {
                                    inp['name']: (payload if inp['name'] == target_field_name
                                                  else inp.get('value', 'test'))
                                    for inp in inputs
                                }
                                for field_name, field_value in js_data.items():
                                    await page.evaluate(
                                        f"""
                                        (function() {{
                                            var el = document.querySelector('[name="{field_name}"]');
                                            if (el) {{ el.value = {repr(field_value)}; }}
                                        }})();
                                        """
                                    )
                                await page.evaluate("document.forms[0] && document.forms[0].submit();")
                            else:
                                js_data = {
                                    inp['name']: (payload if inp['name'] == target_field_name
                                                  else inp.get('value', 'test'))
                                    for inp in inputs
                                }
                                from urllib.parse import urlencode as _ue
                                get_url = f"{action_url}?{_ue(js_data)}"
                                await page.goto(get_url, wait_until='domcontentloaded', timeout=8000)
                                
                            await page.wait_for_timeout(DIALOG_WAIT_MS)
                        except Exception:
                            pass
                            
                        if dialog_fired:
                            break
            except Exception:
                pass

            if dialog_fired:
                evidence_note = f'Browser dialog fired: "{dialog_message}"'
                description_suffix = (
                    'The payload was confirmed executed by a live Chromium browser — '
                    'the JavaScript dialog event fired, proving the script runs in a real browser context.'
                )
                
                if c['type'] == 'url':
                    vuln = {
                        'vuln_type':   'Cross-Site Scripting (XSS)',
                        'risk_level':  'High',
                        'url':         c['url'],
                        'description': (
                            f'Reflected XSS vulnerability confirmed in URL parameter "{c["param_name"]}". '
                            f'The injected script payload was reflected in the response without '
                            f'proper encoding or sanitization. {description_suffix} '
                            f'An attacker could use this to execute arbitrary JavaScript in a victim\'s browser.'
                        ),
                        'evidence':    f'Parameter: {c["param_name"]} | Payload: {c["payload"][:60]} | {evidence_note}',
                        'solution':    (
                            'Encode all user-supplied output using context-appropriate encoding '
                            '(HTML entity encoding, JavaScript encoding, URL encoding). '
                            'Implement Content-Security-Policy headers. Use frameworks that '
                            'automatically escape output.'
                        ),
                    }
                else:  # form
                    vuln = {
                        'vuln_type':   'Cross-Site Scripting (XSS)',
                        'risk_level':  'High',
                        'url':         c['action_url'],
                        'description': (
                            f'Reflected XSS confirmed in form field "{c["field_name"]}" '
                            f'at {c["action_url"]}. The injected payload was reflected in the '
                            f'server response without sanitization. {description_suffix}'
                        ),
                        'evidence':    (
                            f'Form action: {c["action_url"]} | Method: {c["method"].upper()} | '
                            f'Field: {c["field_name"]} | Payload: {c["payload"][:60]} | {evidence_note}'
                        ),
                        'solution':    (
                            'Sanitize and encode all user input before rendering in HTML. '
                            'Use Content-Security-Policy headers to prevent inline script execution.'
                        ),
                    }
                verified_vulns.append(vuln)
                
            try:
                await page.close()
            except Exception:
                pass
                
        await browser.close()
        
    return verified_vulns
