import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re


# XSS test payloads
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "';alert('XSS');//",
    '<svg onload=alert("XSS")>',
    '"><img src=x onerror=alert(1)>',
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(1)">',
    '{{7*7}}',
    '<details open ontoggle=alert(1)>',
]

# Markers to check for reflection
XSS_MARKERS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    "alert('XSS')",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(1)">',
    'onerror=alert(1)',
    '<details open ontoggle=alert(1)>',
]


class XSSScanner:
    """Test for Cross-Site Scripting (XSS) vulnerabilities."""

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.vulnerabilities = []

    def scan_url_params(self, url):
        """Test URL parameters for reflected XSS."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        for param_name in params:
            for payload in XSS_PAYLOADS:
                try:
                    modified_params = dict(params)
                    modified_params[param_name] = [payload]
                    new_query = urlencode(modified_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    body = response.text

                    # Check if payload is reflected in response
                    if payload in body:
                        self.vulnerabilities.append({
                            'vuln_type': 'Cross-Site Scripting (XSS)',
                            'risk_level': 'High',
                            'url': url,
                            'description': (
                                f'Reflected XSS vulnerability found in URL parameter "{param_name}". '
                                f'The injected script payload was reflected in the response without '
                                f'proper encoding or sanitization. An attacker could use this to '
                                f'execute arbitrary JavaScript in a victim\'s browser.'
                            ),
                            'evidence': f'Parameter: {param_name} | Payload reflected: {payload[:60]}',
                            'solution': (
                                'Encode all user-supplied output using context-appropriate encoding '
                                '(HTML entity encoding, JavaScript encoding, URL encoding). '
                                'Implement Content-Security-Policy headers. Use frameworks that '
                                'automatically escape output.'
                            )
                        })
                        return  # One finding per param

                except requests.exceptions.RequestException:
                    continue

    def scan_form(self, form):
        """Test form inputs for XSS."""
        action_url = form['action']
        method = form['method']
        inputs = form['inputs']

        for input_field in inputs:
            for payload in XSS_PAYLOADS[:5]:  # Use fewer payloads for forms
                try:
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

                    body = response.text

                    if payload in body:
                        self.vulnerabilities.append({
                            'vuln_type': 'Cross-Site Scripting (XSS)',
                            'risk_level': 'High',
                            'url': action_url,
                            'description': (
                                f'Reflected XSS found in form field "{input_field["name"]}" '
                                f'at {action_url}. The injected payload was reflected in the '
                                f'server response without sanitization.'
                            ),
                            'evidence': (
                                f'Form action: {action_url} | Method: {method.upper()} | '
                                f'Field: {input_field["name"]} | Payload: {payload[:60]}'
                            ),
                            'solution': (
                                'Sanitize and encode all user input before rendering in HTML. '
                                'Use Content-Security-Policy headers to prevent inline script execution.'
                            )
                        })
                        return  # One finding per form

                except requests.exceptions.RequestException:
                    continue

    def get_results(self):
        """Return deduplicated results."""
        seen = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v['vuln_type'], v['url'])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
