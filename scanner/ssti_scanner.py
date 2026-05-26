import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ── SSTI Payloads ─────────────────────────────────────────────────────────────
# Each tuple: (payload_to_inject, expected_evaluated_output)
# These cover the most common template engines:
#   {{7*7}}      → Jinja2 (Python/Flask), Twig (PHP)
#   ${7*7}       → FreeMarker (Java), Thymeleaf (Java), Velocity (Java)
#   <%= 7*7 %>   → ERB (Ruby), EJS (Node.js)
#   *{7*7}*      → Spring Expression Language (Java/Spring Boot)
SSTI_PAYLOADS = [
    ("{{7*7}}",     "49"),
    ("${7*7}",      "49"),
    ("<%= 7*7 %>",  "49"),
    ("*{7*7}",      "49"),
]


class SSTIScanner:
    """
    Deterministic Server-Side Template Injection (SSTI) scanner.

    Detection logic:
        1. Inject a benign math expression (e.g. {{7*7}}) into URL parameters
           and form fields.
        2. Confirm SSTI if the evaluated result (e.g. '49') appears in the
           response body AND the raw payload itself does NOT appear verbatim.

    The second condition (raw payload absent) is the false-positive guard:
    a site that simply echoes back user input will reflect '{{7*7}}' as-is,
    while a vulnerable template engine will evaluate and return '49'.
    """

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.vulnerabilities = []

    # ================================================================
    # URL Parameter Scanning
    # ================================================================

    def scan_url_params(self, url: str) -> None:
        """Inject SSTI payloads into every URL query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in params:
            for payload, expected in SSTI_PAYLOADS:
                try:
                    modified = dict(params)
                    modified[param_name] = [payload]
                    new_query = urlencode(modified, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
                    body = response.text

                    # SSTI confirmed: evaluated output present, raw payload absent
                    if expected in body and payload not in body:
                        self.vulnerabilities.append(
                            self._build_finding(
                                url=url,
                                param=param_name,
                                payload=payload,
                                expected=expected,
                                context="URL parameter",
                            )
                        )
                        return  # One confirmed finding per URL is sufficient

                except requests.exceptions.RequestException:
                    continue

    # ================================================================
    # Form Field Scanning
    # ================================================================

    def scan_form(self, form: dict) -> None:
        """Inject SSTI payloads into each input field of a discovered form."""
        action_url = form.get("action", "")
        method     = form.get("method", "get").lower()
        inputs     = form.get("inputs", [])

        if not inputs:
            return

        for input_field in inputs:
            for payload, expected in SSTI_PAYLOADS:
                try:
                    # Build form data: inject payload only into the current field
                    data = {}
                    for inp in inputs:
                        if inp["name"] == input_field["name"]:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp.get("value", "test")

                    if method == "post":
                        response = self.session.post(
                            action_url, data=data,
                            timeout=self.timeout, verify=False
                        )
                    else:
                        response = self.session.get(
                            action_url, params=data,
                            timeout=self.timeout, verify=False
                        )

                    body = response.text

                    # SSTI confirmed: evaluated output present, raw payload absent
                    if expected in body and payload not in body:
                        self.vulnerabilities.append(
                            self._build_finding(
                                url=action_url,
                                param=input_field["name"],
                                payload=payload,
                                expected=expected,
                                context=f"form field (method={method.upper()})",
                            )
                        )
                        return  # One confirmed finding per form is sufficient

                except requests.exceptions.RequestException:
                    continue

    # ================================================================
    # Finding Builder
    # ================================================================

    @staticmethod
    def _build_finding(
        url: str,
        param: str,
        payload: str,
        expected: str,
        context: str,
    ) -> dict:
        return {
            "vuln_type":   "Server-Side Template Injection (SSTI)",
            "risk_level":  "High",
            "url":         url,
            "description": (
                f"Server-Side Template Injection (SSTI) vulnerability detected in the "
                f"{context} \"{param}\" at {url}. "
                f"The server evaluated the injected template expression and returned its "
                f"computed value, indicating that user-supplied input is being directly "
                f"compiled inside the template engine without sanitization. "
                f"This is a critical vulnerability that can escalate to full Remote Code "
                f"Execution (RCE), giving an attacker complete control over the server, "
                f"access to the filesystem, environment variables, and internal network."
            ),
            "evidence": (
                f"Context: {context} | "
                f"Parameter: \"{param}\" | "
                f"Payload injected: {payload} | "
                f"Evaluated output found in response: \"{expected}\" | "
                f"Raw payload NOT reflected (confirms server-side evaluation, not echo)"
            ),
            "solution": (
                "Never concatenate or format user-supplied input directly into template "
                "strings. Always pass user data as a separate template context variable "
                "(e.g. render_template_string('<h1>{{ name }}</h1>', name=user_input)). "
                "Use a sandboxed Jinja2 environment (SandboxedEnvironment) if dynamic "
                "templates are a hard requirement. Validate and whitelist all inputs. "
                "Apply a Web Application Firewall (WAF) rule to block common template "
                "expression characters: {{ }}, ${ }, <%= %>, *{ }."
            ),
        }

    # ================================================================
    # Results
    # ================================================================

    def get_results(self) -> list:
        """Return deduplicated SSTI findings."""
        seen   = set()
        unique = []
        for v in self.vulnerabilities:
            key = (v["vuln_type"], v["url"], v.get("evidence", "")[:80])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
