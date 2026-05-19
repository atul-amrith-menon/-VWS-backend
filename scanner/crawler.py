"""
crawler.py — Optimized Async Web Crawler
=========================================
Performance improvements over the original:
  1. Uses aiohttp for non-blocking HTTP requests (was: blocking requests.get)
  2. HEAD requests first to check content-type before downloading body
  3. 3-second connection timeout (was: 10s)
  4. Concurrent crawling with asyncio.Semaphore (max 5 parallel requests)
  5. Built-in retry logic (max 2 retries with backoff)
  6. Response size limit (1 MB max) to prevent memory issues
  7. Rate limiting delay (0.15s) to avoid IP blocks
  8. Falls back to synchronous requests if aiohttp is not available

The crawl results (pages, forms, urls_with_params) stay exactly the same
so all downstream scanners work without any changes.
"""

import asyncio
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Try to import aiohttp; fall back to requests if not installed
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    import requests

# ── Constants ────────────────────────────────────────────────────
CONNECTION_TIMEOUT = 3           # seconds — fast fail on slow sites
MAX_RETRIES = 2                  # retry failed requests up to 2 times
RATE_LIMIT_DELAY = 0.15          # seconds between requests
MAX_RESPONSE_SIZE = 1_048_576    # 1 MB max response body
MAX_CONCURRENT = 5               # parallel request limit
USER_AGENT = 'Vultix/1.0 Security Scanner (Educational)'


class Crawler:
    """Crawl a target website to discover pages, forms, and parameters.

    Uses async HTTP when aiohttp is available, otherwise falls back
    to synchronous requests for compatibility.
    """

    def __init__(self, target_url, max_pages=25, timeout=CONNECTION_TIMEOUT):
        self.target_url = target_url.rstrip('/')
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.pages = []
        self.forms = []
        self.urls_with_params = []
        self.domain = urlparse(target_url).netloc

    def crawl(self):
        """Start crawling from the target URL.

        Automatically picks async or sync mode based on
        whether aiohttp is installed.
        """
        if HAS_AIOHTTP:
            # Run the async crawler in a new event loop
            # (safe to call from a thread — each scan thread gets its own loop)
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(self._async_crawl())
            finally:
                loop.close()
        else:
            # Fallback: synchronous crawling (original behavior)
            self._sync_crawl(self.target_url)

        return {
            'pages': self.pages,
            'forms': self.forms,
            'urls_with_params': self.urls_with_params
        }

    # ═══════════════════════════════════════════════════════════════
    # ASYNC CRAWLING (aiohttp) — the fast path
    # ═══════════════════════════════════════════════════════════════

    async def _async_crawl(self):
        """Crawl using aiohttp with concurrency control."""
        # Semaphore limits how many requests run at the same time
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        # aiohttp timeout — 3 seconds total, keeps things fast
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=False)  # Skip SSL verification
        ) as session:
            # Start with the target URL
            await self._async_crawl_page(session, self.target_url, semaphore)

    async def _async_crawl_page(self, session, url, semaphore):
        """Crawl a single page asynchronously."""
        # Stop conditions
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        # Only crawl same domain
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.domain:
            return

        self.visited.add(url)

        try:
            async with semaphore:
                # ── Step 1: HEAD request first (fast, no body download) ──
                # This checks content-type without downloading the full page
                for attempt in range(MAX_RETRIES + 1):
                    try:
                        async with session.head(url, allow_redirects=True) as head_resp:
                            content_type = head_resp.headers.get('Content-Type', '')
                            # Skip non-HTML content (images, videos, PDFs, etc.)
                            if 'text/html' not in content_type:
                                return
                        break  # HEAD succeeded
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(0.5 * (attempt + 1))  # Backoff
                        else:
                            return  # All retries failed

                # ── Rate limiting ──
                await asyncio.sleep(RATE_LIMIT_DELAY)

                # ── Step 2: GET request for HTML body ──
                html_text = None
                response_headers = {}
                status_code = 0

                for attempt in range(MAX_RETRIES + 1):
                    try:
                        async with session.get(url, allow_redirects=True) as resp:
                            status_code = resp.status
                            response_headers = dict(resp.headers)

                            # Limit response size to prevent memory issues
                            content_length = resp.headers.get('Content-Length', '0')
                            if content_length.isdigit() and int(content_length) > MAX_RESPONSE_SIZE:
                                return  # Skip very large responses

                            # Read body with size limit
                            body_bytes = await resp.content.read(MAX_RESPONSE_SIZE)
                            html_text = body_bytes.decode('utf-8', errors='ignore')
                        break  # GET succeeded
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(0.5 * (attempt + 1))
                        else:
                            return

                if not html_text:
                    return

            # ── Step 3: Parse the HTML ──
            self.pages.append({
                'url': url,
                'status_code': status_code,
                'headers': response_headers
            })

            soup = BeautifulSoup(html_text, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                form_data = self._extract_form(form, url)
                if form_data:
                    self.forms.append(form_data)

            # Check if URL has parameters
            if parsed.query:
                self.urls_with_params.append(url)

            # ── Step 4: Follow links in parallel ──
            tasks = []
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                next_url = next_url.split('#')[0]  # Remove fragments

                # Check for params in discovered URLs
                if urlparse(next_url).query:
                    self.urls_with_params.append(next_url)

                # Queue the next page for crawling
                tasks.append(self._async_crawl_page(session, next_url, semaphore))

            # Run link-following tasks concurrently
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        except Exception:
            pass  # Skip any unexpected errors, keep crawling

    # ═══════════════════════════════════════════════════════════════
    # SYNC CRAWLING (requests) — fallback if aiohttp not installed
    # ═══════════════════════════════════════════════════════════════

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
                'url': url,
                'status_code': response.status_code,
                'headers': dict(response.headers)
            })

            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                form_data = self._extract_form(form, url)
                if form_data:
                    self.forms.append(form_data)

            if parsed.query:
                self.urls_with_params.append(url)

            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                next_url = next_url.split('#')[0]

                if urlparse(next_url).query:
                    self.urls_with_params.append(next_url)

                self._sync_crawl(next_url)

        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    # Form Extraction (unchanged — same logic as before)
    # ═══════════════════════════════════════════════════════════════

    def _extract_form(self, form, page_url):
        """Extract form details including action and inputs."""
        action = form.get('action', '')
        action_url = urljoin(page_url, action) if action else page_url
        method = form.get('method', 'get').lower()

        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            input_type = inp.get('type', 'text')
            input_name = inp.get('name', '')
            input_value = inp.get('value', '')

            if input_name and input_type not in ('submit', 'button', 'image', 'reset'):
                inputs.append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })

        if not inputs:
            return None

        return {
            'action': action_url,
            'method': method,
            'inputs': inputs,
            'page_url': page_url
        }
