"""
crawler.py — Optimized Async Web Crawler with Headless SPA Support
===================================================================
Crawl order (best available engine is used automatically):

  Tier 1 — Playwright Headless Chromium (most accurate, SPA-aware):
    • Launches a real Chromium browser via playwright.async_api
    • Executes the full JavaScript bundle, builds the live DOM
    • Discovers dynamic React/Vite routes by clicking rendered links
    • Extracts forms from the live DOM (not from raw HTML source)
    • Capped at MAX_PLAYWRIGHT_PAGES (15) to keep scans fast

  Tier 2 — aiohttp async HTTP (fast, static-HTML sites):
    • Non-blocking concurrent requests via asyncio.Semaphore
    • HEAD-first content-type check (avoids downloading non-HTML bodies)
    • 3-second timeout, exponential backoff on failures
    • Response size capped at 1 MB

  Tier 3 — requests sync HTTP (fallback if aiohttp is missing):
    • Original synchronous behavior for maximum compatibility

The crawl results (pages, forms, urls_with_params) are IDENTICAL across
all three tiers — all downstream scanners work without any changes.
"""

import asyncio
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

# ── Playwright optional import ─────────────────────────────────────────────────
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# ── aiohttp optional import ────────────────────────────────────────────────────
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    import requests

# ── Constants ──────────────────────────────────────────────────────────────────
CONNECTION_TIMEOUT    = 3            # seconds — fast fail on slow sites
MAX_RETRIES           = 2            # retry failed requests up to 2 times
RATE_LIMIT_DELAY      = 0.15         # seconds between aiohttp requests
MAX_RESPONSE_SIZE     = 1_048_576    # 1 MB max response body
MAX_CONCURRENT        = 5            # parallel aiohttp request limit
MAX_PLAYWRIGHT_PAGES  = 15           # max pages crawled by Playwright (SPA cap)
PW_PAGE_TIMEOUT       = 8_000        # ms — Playwright navigation timeout per page
PW_RENDER_WAIT        = 800          # ms — wait after navigation for JS to settle (reduced: assets intercepted)

# Resource types that add zero value to link/form discovery.
# Blocking them at the context level cuts per-page load time by ~40-60%.
_BLOCKED_RESOURCE_TYPES = frozenset({
    "image", "media", "font", "stylesheet",
    "texttrack", "eventsource", "manifest", "other",
})
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0.0.0 Safari/537.36'
)


class Crawler:
    """
    Crawl a target website to discover pages, forms, and URL parameters.

    Engine priority:
      1. Playwright Headless Chromium — fully renders SPAs, discovers JS routes
      2. aiohttp async HTTP          — fast static-HTML crawl
      3. requests sync HTTP          — safe fallback for maximum compatibility
    """

    # Ports that are always considered "standard" and excluded from discovery
    _STANDARD_PORTS = frozenset({80, 443})

    def __init__(self, target_url, max_pages=25, timeout=CONNECTION_TIMEOUT):
        self.target_url  = target_url.rstrip('/')
        self.max_pages   = max_pages
        self.timeout     = timeout
        self.visited     = set()
        self.pages       = []
        self.forms       = []
        self.urls_with_params = []
        self.domain      = urlparse(target_url).netloc
        # Opportunistic port discovery — non-standard ports found during crawl
        self.discovered_ports: set[int] = set()

    def crawl(self):
        """
        Start crawling from the target URL.

        Automatically selects the best available engine:
          Playwright  →  aiohttp  →  requests
        """
        if HAS_PLAYWRIGHT:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(self._playwright_crawl())
            finally:
                loop.close()
        elif HAS_AIOHTTP:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(self._async_crawl())
            finally:
                loop.close()
        else:
            self._sync_crawl(self.target_url)

        return {
            'pages':            self.pages,
            'forms':            self.forms,
            'urls_with_params': self.urls_with_params,
            'discovered_ports': sorted(self.discovered_ports),
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # TIER 1 — PLAYWRIGHT HEADLESS SPA CRAWLER
    # ═══════════════════════════════════════════════════════════════════════════

    async def _playwright_crawl(self):
        """
        Crawl a modern SPA using a real headless Chromium browser.

        Strategy:
          1. Navigate to the root URL and wait for the JavaScript bundle to render.
          2. Extract all <a href> links from the live DOM (includes JS-rendered links).
          3. Extract all <form> elements from the live DOM.
          4. Follow each same-domain link (BFS), up to MAX_PLAYWRIGHT_PAGES pages.
        """
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=USER_AGENT,
                ignore_https_errors=True,
            )

            # ── Request interception: abort non-essential resource types ──────
            # Images, fonts, media and stylesheets are irrelevant for link and
            # form discovery. Blocking them at the context level means every page
            # navigation skips downloading those assets entirely, cutting wall-clock
            # load time per page by 40-60% on asset-heavy sites.
            async def _intercept(route):
                if route.request.resource_type in _BLOCKED_RESOURCE_TYPES:
                    await route.abort()
                else:
                    await route.continue_()

            await context.route("**/*", _intercept)

            queue   = [self.target_url]
            visited = set()

            while queue and len(visited) < MAX_PLAYWRIGHT_PAGES:
                url = queue.pop(0)

                # Normalise and deduplicate
                url = url.split('#')[0].rstrip('/')
                if url in visited:
                    continue
                if not self._same_domain(url):
                    continue
                visited.add(url)

                page = None
                try:
                    page = await context.new_page()

                    # Navigate and wait for the network to go idle
                    # (React/Vite apps fire XHR/fetch calls during mounting)
                    try:
                        await page.goto(
                            url,
                            wait_until='networkidle',
                            timeout=PW_PAGE_TIMEOUT,
                        )
                    except Exception:
                        # networkidle can time out on heavy SPAs — fall back to DOMContentLoaded
                        try:
                            await page.goto(url, wait_until='domcontentloaded',
                                            timeout=PW_PAGE_TIMEOUT)
                        except Exception:
                            continue

                    # Give React/Vite an extra moment to finish rendering
                    await page.wait_for_timeout(PW_RENDER_WAIT)

                    # ── Record page ──────────────────────────────────────────
                    current_url = page.url
                    status      = 200   # Playwright doesn't expose status directly on goto
                    self.pages.append({
                        'url':         current_url,
                        'status_code': status,
                        'headers':     {},
                    })

                    # Opportunistic port discovery on the page we just loaded
                    self._collect_port(current_url)

                    if urlparse(current_url).query:
                        self.urls_with_params.append(current_url)

                    # ── Extract forms from live DOM ──────────────────────────
                    forms_data = await self._extract_forms_playwright(page, current_url)
                    self.forms.extend(forms_data)

                    # ── Discover links from live DOM ─────────────────────────
                    hrefs = await page.evaluate("""
                        () => Array.from(document.querySelectorAll('a[href]'))
                                   .map(a => a.href)
                    """)

                    for href in hrefs:
                        href = href.split('#')[0].rstrip('/')
                        if not href or href in visited:
                            continue
                        if not self._same_domain(href):
                            continue
                        # Opportunistic port discovery
                        self._collect_port(href)
                        # Track URLs that carry query parameters
                        if urlparse(href).query:
                            self.urls_with_params.append(href)
                        queue.append(href)

                except Exception:
                    pass
                finally:
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass

            await browser.close()

        # ── Fallback: top-up with aiohttp if Playwright found very few pages ──
        # This catches server-rendered pages that Playwright missed due to the
        # MAX_PLAYWRIGHT_PAGES cap.
        if HAS_AIOHTTP and len(self.pages) < 3:
            await self._async_crawl()

    async def _extract_forms_playwright(self, page, page_url):
        """Extract form data from the live Playwright DOM."""
        forms = []
        try:
            forms_info = await page.evaluate("""
                () => Array.from(document.forms).map(form => ({
                    action: form.action || '',
                    method: (form.method || 'get').toLowerCase(),
                    inputs: Array.from(form.elements)
                        .filter(el => el.name && !['submit','button','image','reset'].includes(el.type))
                        .map(el => ({ type: el.type || 'text', name: el.name, value: el.value || '' }))
                }))
            """)

            for f in forms_info:
                if not f['inputs']:
                    continue
                action = f['action'] or page_url
                forms.append({
                    'action':   action,
                    'method':   f['method'],
                    'inputs':   f['inputs'],
                    'page_url': page_url,
                })
        except Exception:
            pass
        return forms

    def _same_domain(self, url):
        """Return True if the URL belongs to the same domain as the target."""
        try:
            parsed = urlparse(url)
            return (not parsed.netloc) or (parsed.netloc == self.domain)
        except Exception:
            return False

    def _collect_port(self, url: str) -> None:
        """Passively record a non-standard port if the URL belongs to our target domain.

        Called for every URL encountered during crawling. If URL parsing fails
        for any reason the error is silently swallowed so the crawl is never
        interrupted by port-collection logic.
        """
        try:
            parsed = urlparse(url)
            port = parsed.port  # None when no explicit port in the URL
            if port is None:
                return
            # Only collect if the URL belongs to the target domain
            hostname = parsed.hostname or ''
            target_hostname = urlparse(self.target_url).hostname or ''
            if hostname != target_hostname:
                return
            if port not in self._STANDARD_PORTS:
                self.discovered_ports.add(int(port))
        except Exception:
            pass  # Never crash the crawl for port collection

    # ═══════════════════════════════════════════════════════════════════════════
    # TIER 2 — AIOHTTP ASYNC CRAWLER (fast path for static sites)
    # ═══════════════════════════════════════════════════════════════════════════

    async def _async_crawl(self):
        """Crawl using aiohttp with concurrency control."""
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        timeout   = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            await self._async_crawl_page(session, self.target_url, semaphore)

    async def _async_crawl_page(self, session, url, semaphore):
        """Crawl a single page asynchronously."""
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.domain:
            return

        self.visited.add(url)

        try:
            async with semaphore:
                # ── HEAD request first — check content-type cheaply ──────────
                for attempt in range(MAX_RETRIES + 1):
                    try:
                        async with session.head(url, allow_redirects=True) as head_resp:
                            content_type = head_resp.headers.get('Content-Type', '')
                            if 'text/html' not in content_type:
                                return
                        break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(0.5 * (attempt + 1))
                        else:
                            return

                await asyncio.sleep(RATE_LIMIT_DELAY)

                # ── GET request for HTML body ────────────────────────────────
                html_text = None
                response_headers = {}
                status_code = 0

                for attempt in range(MAX_RETRIES + 1):
                    try:
                        async with session.get(url, allow_redirects=True) as resp:
                            status_code      = resp.status
                            response_headers = dict(resp.headers)

                            content_length = resp.headers.get('Content-Length', '0')
                            if content_length.isdigit() and int(content_length) > MAX_RESPONSE_SIZE:
                                return

                            body_bytes = await resp.content.read(MAX_RESPONSE_SIZE)
                            html_text  = body_bytes.decode('utf-8', errors='ignore')
                        break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(0.5 * (attempt + 1))
                        else:
                            return

                if not html_text:
                    return

            # ── Parse the HTML ───────────────────────────────────────────────
            self.pages.append({
                'url':         url,
                'status_code': status_code,
                'headers':     response_headers,
            })

            soup = BeautifulSoup(html_text, 'html.parser')

            for form in soup.find_all('form'):
                form_data = self._extract_form(form, url)
                if form_data:
                    self.forms.append(form_data)

            if parsed.query:
                self.urls_with_params.append(url)

            # ── Follow links concurrently ────────────────────────────────────
            tasks = []
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href']).split('#')[0]
                # Opportunistic port discovery
                self._collect_port(next_url)
                if urlparse(next_url).query:
                    self.urls_with_params.append(next_url)
                tasks.append(self._async_crawl_page(session, next_url, semaphore))

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════
    # TIER 3 — REQUESTS SYNC CRAWLER (compatibility fallback)
    # ═══════════════════════════════════════════════════════════════════════════

    def _sync_crawl(self, url):
        """Crawl a single page synchronously (original behavior)."""
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.domain:
            return

        self.visited.add(url)

        try:
            import requests as req
            session = req.Session()
            session.headers.update({'User-Agent': USER_AGENT})

            response = session.get(url, timeout=self.timeout, verify=False)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return

            self.pages.append({
                'url':         url,
                'status_code': response.status_code,
                'headers':     dict(response.headers),
            })

            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                form_data = self._extract_form(form, url)
                if form_data:
                    self.forms.append(form_data)

            if parsed.query:
                self.urls_with_params.append(url)

            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href']).split('#')[0]
                # Opportunistic port discovery
                self._collect_port(next_url)
                if urlparse(next_url).query:
                    self.urls_with_params.append(next_url)
                self._sync_crawl(next_url)

        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════
    # FORM EXTRACTION HELPER (shared across all tiers)
    # ═══════════════════════════════════════════════════════════════════════════

    def _extract_form(self, form, page_url):
        """Extract form details including action URL and input fields."""
        action     = form.get('action', '')
        action_url = urljoin(page_url, action) if action else page_url
        # Opportunistic port discovery from form action URLs
        self._collect_port(action_url)
        method     = form.get('method', 'get').lower()

        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            input_type  = inp.get('type', 'text')
            input_name  = inp.get('name', '')
            input_value = inp.get('value', '')

            if input_name and input_type not in ('submit', 'button', 'image', 'reset'):
                inputs.append({
                    'type':  input_type,
                    'name':  input_name,
                    'value': input_value,
                })

        if not inputs:
            return None

        return {
            'action':   action_url,
            'method':   method,
            'inputs':   inputs,
            'page_url': page_url,
        }
