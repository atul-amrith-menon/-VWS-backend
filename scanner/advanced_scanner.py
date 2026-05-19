import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import re


# Directory traversal payloads
DIR_TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '....//....//....//etc/passwd',
    '../../../etc/shadow',
    '..%2f..%2f..%2fetc%2fpasswd',
    '..%5c..%5c..%5cwindows%5cwin.ini',
]

DIR_TRAVERSAL_SIGNATURES = [
    'root:x:0:0',
    'root:*:0:0',
    '[extensions]',
    'for 16-bit app support',
    'daemon:x:',
    '/bin/bash',
    '/bin/sh',
]

# Open redirect payloads
REDIRECT_PARAMS = ['url', 'redirect', 'next', 'return', 'returnurl', 'return_url',
                   'redir', 'redirect_to', 'goto', 'destination', 'out', 'view',
                   'target', 'link', 'continue', 'forward']

REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '/\\evil.com',
    'https:evil.com',
]

# Sensitive data exposure patterns
SENSITIVE_DATA_PATTERNS = [
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+', 'Password found in page source'),
    (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?\w{16,}', 'API key found in source'),
    (r'(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']?\w{16,}', 'Secret key exposed'),
    (r'(?i)(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?\w{16,}', 'Access token exposed'),
    (r'(?i)(?:aws[_-]?access|aws[_-]?secret)\s*[:=]\s*\S+', 'AWS credentials exposed'),
    (r'(?i)(?:private[_-]?key)\s*[:=]\s*\S+', 'Private key reference found'),
    (r'(?i)(?:jdbc:|mysql://|postgres://|mongodb://)\S+', 'Database connection string exposed'),
    (r'(?i)BEGIN\s(?:RSA\s)?PRIVATE\sKEY', 'Private key found in page source'),
]

# Weak authentication indicators
WEAK_AUTH_INDICATORS = [
    ('/login', ['input[type="password"]'], 'Login form found'),
    ('/admin', ['input[type="password"]'], 'Admin login found'),
    ('/signup', ['input[type="password"]'], 'Signup form found'),
    ('/register', ['input[type="password"]'], 'Registration form found'),
]


class AdvancedScanner:
    """Detect CSRF, Directory Traversal, Open Redirect, Weak Auth,
       Sensitive Data Exposure, and Clickjacking vulnerabilities."""

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.vulnerabilities = []

    # ================================================================
    # 1. CSRF Detection
    # ================================================================
    def scan_csrf(self, forms):
        """Check forms for missing CSRF tokens."""
        csrf_token_names = [
            'csrf', 'csrftoken', 'csrf_token', '_csrf', 'xsrf',
            'xsrf_token', '_token', 'authenticity_token', '__requestverificationtoken',
            'csrfmiddlewaretoken', 'anti-csrf-token', 'antiforgery'
        ]

        for form in forms:
            action_url = form.get('action', '')
            method = form.get('method', 'get').lower()

            # CSRF is mainly relevant for POST forms that change state
            if method != 'post':
                continue

            inputs = form.get('inputs', [])
            input_names = [inp.get('name', '').lower() for inp in inputs]

            has_csrf = any(
                any(token in name for token in csrf_token_names)
                for name in input_names
            )

            if not has_csrf:
                self.vulnerabilities.append({
                    'vuln_type': 'CSRF',
                    'risk_level': 'Medium',
                    'url': action_url,
                    'description': (
                        f'The POST form at {action_url} does not contain a CSRF token. '
                        f'An attacker could craft a malicious page that submits this form '
                        f'on behalf of an authenticated user without their knowledge.'
                    ),
                    'evidence': (
                        f'Form method: POST | Action: {action_url} | '
                        f'Fields: {", ".join(input_names[:5])} | No CSRF token found'
                    ),
                    'solution': (
                        'Add a unique, unpredictable CSRF token to every state-changing form. '
                        'Validate the token server-side on each request. '
                        'Use the SameSite cookie attribute as an additional defense.'
                    )
                })

    # ================================================================
    # 2. Directory Traversal
    # ================================================================
    def scan_directory_traversal(self, urls_with_params):
        """Test URL parameters for directory/path traversal."""
        for url in urls_with_params:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in params:
                # Only test params that look like they could reference files
                param_lower = param_name.lower()
                file_like = any(kw in param_lower for kw in
                                ['file', 'path', 'page', 'doc', 'dir', 'folder',
                                 'template', 'include', 'load', 'read', 'view',
                                 'cat', 'name', 'src', 'img'])
                if not file_like:
                    continue

                for payload in DIR_TRAVERSAL_PAYLOADS:
                    try:
                        modified = dict(params)
                        modified[param_name] = [payload]
                        new_query = urlencode(modified, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))

                        resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                        body = resp.text.lower()

                        for sig in DIR_TRAVERSAL_SIGNATURES:
                            if sig.lower() in body:
                                self.vulnerabilities.append({
                                    'vuln_type': 'Directory Traversal',
                                    'risk_level': 'High',
                                    'url': url,
                                    'description': (
                                        f'Directory traversal vulnerability found in parameter '
                                        f'"{param_name}". An attacker can read arbitrary files '
                                        f'from the server by manipulating the path.'
                                    ),
                                    'evidence': (
                                        f'Parameter: {param_name} | Payload: {payload} | '
                                        f'Signature matched: "{sig}"'
                                    ),
                                    'solution': (
                                        'Validate and sanitize file path inputs. Use a whitelist '
                                        'of allowed files. Never pass user input directly to file '
                                        'system operations. Use chroot or sandboxing.'
                                    )
                                })
                                return
                    except requests.exceptions.RequestException:
                        continue

    # ================================================================
    # 3. Open Redirect
    # ================================================================
    def scan_open_redirect(self, urls_with_params):
        """Test URL parameters for open redirect vulnerabilities."""
        for url in urls_with_params:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in params:
                if param_name.lower() not in REDIRECT_PARAMS:
                    continue

                for payload in REDIRECT_PAYLOADS:
                    try:
                        modified = dict(params)
                        modified[param_name] = [payload]
                        new_query = urlencode(modified, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))

                        resp = self.session.get(test_url, timeout=self.timeout,
                                                verify=False, allow_redirects=False)

                        location = resp.headers.get('Location', '')
                        if resp.status_code in (301, 302, 303, 307, 308):
                            if 'evil.com' in location:
                                self.vulnerabilities.append({
                                    'vuln_type': 'Open Redirect',
                                    'risk_level': 'Medium',
                                    'url': url,
                                    'description': (
                                        f'Open redirect vulnerability in parameter "{param_name}". '
                                        f'An attacker can redirect users to a malicious website, '
                                        f'enabling phishing attacks and credential theft.'
                                    ),
                                    'evidence': (
                                        f'Parameter: {param_name} | Payload: {payload} | '
                                        f'Redirect Location: {location[:100]}'
                                    ),
                                    'solution': (
                                        'Validate redirect URLs against a whitelist of allowed '
                                        'destinations. Never redirect to user-supplied URLs directly. '
                                        'Use relative paths instead of absolute URLs.'
                                    )
                                })
                                return
                    except requests.exceptions.RequestException:
                        continue

    # ================================================================
    # 4. Clickjacking Detection
    # ================================================================
    def scan_clickjacking(self, pages):
        """Check if the site is vulnerable to clickjacking."""
        if not pages:
            return

        page = pages[0]
        headers = page.get('headers', {})
        url = page['url']

        has_xfo = any(k.lower() == 'x-frame-options' for k in headers)
        has_csp_frame = False

        for k, v in headers.items():
            if k.lower() == 'content-security-policy' and v:
                if 'frame-ancestors' in v.lower():
                    has_csp_frame = True

        if not has_xfo and not has_csp_frame:
            self.vulnerabilities.append({
                'vuln_type': 'Clickjacking',
                'risk_level': 'Medium',
                'url': url,
                'description': (
                    'The site does not set X-Frame-Options or CSP frame-ancestors, '
                    'making it vulnerable to clickjacking. An attacker can embed this '
                    'site in a hidden iframe to trick users into performing unintended actions.'
                ),
                'evidence': (
                    'Neither X-Frame-Options header nor CSP frame-ancestors directive '
                    'is present in the response.'
                ),
                'solution': (
                    'Set the X-Frame-Options header to DENY or SAMEORIGIN. '
                    'Additionally, add a Content-Security-Policy header with '
                    '"frame-ancestors \'self\'" to restrict framing.'
                )
            })

    # ================================================================
    # 5. Weak Authentication Checks
    # ================================================================
    def scan_weak_auth(self, base_url, pages):
        """Check for weak authentication indicators."""
        # Check if login forms submit over HTTP
        for page in pages:
            url = page['url']
            if url.startswith('http://'):
                # Check if any forms submit credentials over HTTP
                pass  # Already covered by HTTPS check in misconfig

        # Check for autocomplete on password fields
        for page in pages:
            try:
                resp = self.session.get(page['url'], timeout=self.timeout, verify=False)
                body = resp.text.lower()

                # Check for password fields without autocomplete="off"
                if '<input' in body and 'type="password"' in body:
                    if 'autocomplete="off"' not in body and "autocomplete='off'" not in body:
                        self.vulnerabilities.append({
                            'vuln_type': 'Weak Authentication',
                            'risk_level': 'Low',
                            'url': page['url'],
                            'description': (
                                'Password field found without autocomplete="off". '
                                'Browsers may cache the password, increasing the risk '
                                'of credential theft from shared or compromised machines.'
                            ),
                            'evidence': 'Password input field found without autocomplete disabled.',
                            'solution': (
                                'Add autocomplete="off" to sensitive form fields. '
                                'Consider using autocomplete="new-password" for registration forms.'
                            )
                        })
                        break

                # Check for login form over HTTP
                if 'type="password"' in body and page['url'].startswith('http://'):
                    self.vulnerabilities.append({
                        'vuln_type': 'Weak Authentication',
                        'risk_level': 'High',
                        'url': page['url'],
                        'description': (
                            'Login form transmits credentials over unencrypted HTTP. '
                            'An attacker on the network can intercept usernames and passwords.'
                        ),
                        'evidence': f'Password field found on HTTP page: {page["url"]}',
                        'solution': (
                            'Serve all login pages over HTTPS. Redirect HTTP to HTTPS '
                            'and set the HSTS header.'
                        )
                    })
                    break

            except requests.exceptions.RequestException:
                continue

        # Check common default credential paths
        default_paths = [
            ('/admin', 'Admin panel'),
            ('/administrator', 'Administrator panel'),
            ('/login', 'Login page'),
        ]
        for path, desc in default_paths:
            try:
                test_url = urljoin(base_url, path)
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and ('password' in resp.text.lower() or
                                                 'login' in resp.text.lower()):
                    body_lower = resp.text.lower()
                    if 'type="password"' in body_lower:
                        # Check if there's a rate-limiting header or CAPTCHA
                        has_captcha = any(kw in body_lower for kw in
                                          ['captcha', 'recaptcha', 'g-recaptcha', 'hcaptcha'])
                        if not has_captcha:
                            self.vulnerabilities.append({
                                'vuln_type': 'Weak Authentication',
                                'risk_level': 'Medium',
                                'url': test_url,
                                'description': (
                                    f'{desc} found at {path} without CAPTCHA or visible '
                                    f'rate-limiting protection. This makes the form susceptible '
                                    f'to brute-force credential attacks.'
                                ),
                                'evidence': f'Login form at {test_url} has no CAPTCHA protection.',
                                'solution': (
                                    'Implement CAPTCHA, account lockout policies, and rate '
                                    'limiting on authentication endpoints. Consider multi-factor auth.'
                                )
                            })
            except requests.exceptions.RequestException:
                continue

    # ================================================================
    # 6. Sensitive Data Exposure
    # ================================================================
    def scan_sensitive_data(self, pages):
        """Scan page content for exposed sensitive data."""
        checked = set()

        for page in pages[:10]:
            url = page['url']
            if url in checked:
                continue
            checked.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                body = resp.text

                for pattern, desc in SENSITIVE_DATA_PATTERNS:
                    match = re.search(pattern, body)
                    if match:
                        matched_text = match.group(0)
                        # Mask the actual value for safety
                        safe_evidence = matched_text[:30] + '...' if len(matched_text) > 30 else matched_text

                        self.vulnerabilities.append({
                            'vuln_type': 'Sensitive Data Exposure',
                            'risk_level': 'High',
                            'url': url,
                            'description': (
                                f'{desc}. Sensitive information is visible in the page source, '
                                f'which could be exploited by attackers to gain unauthorized access.'
                            ),
                            'evidence': f'Pattern matched: {safe_evidence}',
                            'solution': (
                                'Remove sensitive data from client-side code. Store secrets '
                                'in environment variables or a secrets manager. Never commit '
                                'credentials to version control.'
                            )
                        })
                        break  # One finding per page

            except requests.exceptions.RequestException:
                continue

    # ================================================================
    # Run All Checks
    # ================================================================
    def run_all(self, base_url, pages, forms, urls_with_params):
        """Run all advanced security checks."""
        self.scan_csrf(forms)
        self.scan_directory_traversal(urls_with_params)
        self.scan_open_redirect(urls_with_params)
        self.scan_clickjacking(pages)
        self.scan_weak_auth(base_url, pages)
        self.scan_sensitive_data(pages)

    def get_results(self):
        """Return deduplicated results."""
        seen = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v['vuln_type'], v['url'], v['description'][:80])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
