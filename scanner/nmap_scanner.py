# -*- coding: utf-8 -*-
"""
scanner/nmap_scanner.py — Optimized Nmap Infrastructure Scanner
===============================================================
Replaces MisconfigScanner for infrastructure-level security checks.

Uses the following optimized flags for fast execution (<10 seconds):
    -F      : Fast mode — top 100 ports only (not all 65,535)
    -T4     : Aggressive timing — faster without being reckless
    -Pn     : Skip host discovery ping — assume host is up
    -sV     : Probe open ports to determine service/version info
    --script=http-security-headers
            : NSE script to check for missing HTTP security headers

Public API:
    run_nmap_scan(target_url) -> list[dict]
        Returns a list of vulnerability dicts in the standard Vultix format.

Requirements:
    - Nmap must be installed on the host machine:
        Windows: https://nmap.org/download.html
        Linux:   sudo apt-get install nmap
    - No Python packages required (uses subprocess, no python-nmap needed).
"""

import re
import shutil
import subprocess
import sys
from urllib.parse import urlparse


# Nmap timeout has been removed to allow complete scanning without a timeout ceiling.


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_host(target_url: str) -> str:
    """Strip scheme and path — Nmap only needs the bare hostname or IP."""
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    return host


def _get_nmap_path() -> str | None:
    """Return the path to the Nmap executable, checking default Windows paths if needed."""
    path = shutil.which("nmap")
    if path:
        return path
    
    # Fallback for Windows if it wasn't added to PATH or terminal wasn't restarted
    win_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    import os
    if os.path.exists(win_path):
        return win_path
        
    return None

def _nmap_available() -> bool:
    """Return True if the nmap binary can be found."""
    return _get_nmap_path() is not None


def _build_finding(
    vuln_type: str,
    risk_level: str,
    url: str,
    description: str,
    evidence: str,
    solution: str,
) -> dict:
    """Build a standard Vultix vulnerability dictionary."""
    return {
        "vuln_type":   vuln_type,
        "risk_level":  risk_level,
        "url":         url,
        "description": description,
        "evidence":    evidence,
        "solution":    solution,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Nmap output parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_open_ports(nmap_output: str, target_url: str) -> list[dict]:
    """
    Detect dangerous open ports from Nmap output.
    Flags: database ports, admin panels, legacy/unencrypted services.
    """
    findings = []

    DANGEROUS_PORTS = {
        "21":   ("FTP (Unencrypted File Transfer)", "High",
                 "FTP transmits credentials in plain text. Disable FTP and use SFTP (port 22) instead."),
        "23":   ("Telnet (Unencrypted Remote Shell)", "High",
                 "Telnet is completely unencrypted. Replace with SSH (port 22) immediately."),
        "3306": ("MySQL Database Port Exposed", "High",
                 "MySQL is accessible from the public internet. Restrict port 3306 to internal IPs only via firewall rules."),
        "5432": ("PostgreSQL Database Port Exposed", "High",
                 "PostgreSQL is accessible from the public internet. Restrict port 5432 to internal IPs only."),
        "27017":("MongoDB Port Exposed", "High",
                 "MongoDB is accessible from the public internet. Restrict port 27017 to internal IPs only."),
        "6379": ("Redis Port Exposed", "High",
                 "Redis is accessible from the public internet with no authentication by default. Restrict immediately."),
        "8080": ("Alternative HTTP Port Open", "Medium",
                 "An alternative HTTP port is open. Ensure no debug servers or staging environments are exposed."),
        "8443": ("Alternative HTTPS Port Open", "Low",
                 "An alternative HTTPS port is open. Verify this is intentional."),
        "9200": ("Elasticsearch Port Exposed", "High",
                 "Elasticsearch has no authentication by default. Restrict port 9200 to internal access only."),
        "22":   ("SSH Port Open", "Low",
                 "SSH is publicly accessible. Ensure you are using key-based authentication and have disabled password login."),
    }

    # Match lines like:  22/tcp   open  ssh     OpenSSH 7.9p1
    port_pattern = re.compile(
        r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)?$", re.MULTILINE
    )

    for match in port_pattern.finditer(nmap_output):
        port    = match.group(1)
        service = match.group(2)
        version = match.group(3).strip()
        evidence = f"Port {port}/tcp is open. Service: {service} {version}".strip()

        if port in DANGEROUS_PORTS:
            label, risk, solution = DANGEROUS_PORTS[port]
            findings.append(_build_finding(
                vuln_type   = f"Exposed Service: {label}",
                risk_level  = risk,
                url         = target_url,
                description = (
                    f"Port {port}/tcp ({service}) is open and accessible from the internet. "
                    f"Service version detected: {version or 'unknown'}."
                ),
                evidence    = evidence,
                solution    = solution,
            ))

    return findings


def _parse_outdated_services(nmap_output: str, target_url: str) -> list[dict]:
    """Flag known outdated / vulnerable service versions detected by -sV."""
    findings = []

    VULNERABLE_VERSIONS = [
        # (regex pattern, description, risk, solution)
        (r"OpenSSH [1-6]\.",
         "Outdated OpenSSH Version Detected", "Medium",
         "Upgrade OpenSSH to the latest stable version (8.x or higher)."),
        (r"Apache/[12]\.",
         "Outdated Apache HTTP Server Detected", "Medium",
         "Upgrade Apache to version 2.4.x or higher. Older versions have known CVEs."),
        (r"nginx/0\.",
         "Outdated Nginx Detected", "Medium",
         "Upgrade Nginx to the latest stable version."),
        (r"PHP/[4567]\.",
         "End-of-Life PHP Version Detected", "High",
         "PHP versions below 8.0 are end-of-life and receive no security patches. Upgrade immediately."),
        (r"MySQL\s+5\.[0-6]\.",
         "Outdated MySQL Version Detected", "Medium",
         "Upgrade MySQL to version 8.0 or higher."),
        (r"vsftpd\s+2\.",
         "Outdated vsftpd Detected", "High",
         "vsftpd 2.3.4 had a critical backdoor. Upgrade vsftpd and consider disabling FTP entirely."),
    ]

    for pattern, desc, risk, solution in VULNERABLE_VERSIONS:
        match = re.search(pattern, nmap_output, re.IGNORECASE)
        if match:
            findings.append(_build_finding(
                vuln_type   = desc,
                risk_level  = risk,
                url         = target_url,
                description = (
                    f"Nmap identified a potentially vulnerable service version: "
                    f"`{match.group(0).strip()}`. This version may have known security vulnerabilities."
                ),
                evidence    = match.group(0).strip(),
                solution    = solution,
            ))

    return findings


def _parse_security_headers(nmap_output: str, target_url: str) -> list[dict]:
    """Parse the http-security-headers NSE script output for missing headers."""
    findings = []

    REQUIRED_HEADERS = {
        "X-Frame-Options": (
            "Missing X-Frame-Options Header", "Medium",
            "Add the header `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking.",
        ),
        "X-Content-Type-Options": (
            "Missing X-Content-Type-Options Header", "Low",
            "Add `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing attacks.",
        ),
        "Strict-Transport-Security": (
            "Missing HTTP Strict Transport Security (HSTS)", "High",
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to enforce HTTPS.",
        ),
        "Content-Security-Policy": (
            "Missing Content Security Policy (CSP)", "Medium",
            "Implement a Content-Security-Policy header to prevent XSS and data injection attacks.",
        ),
        "X-XSS-Protection": (
            "Missing X-XSS-Protection Header", "Low",
            "Add `X-XSS-Protection: 1; mode=block` as a legacy XSS defense layer.",
        ),
    }

    # The NSE script marks missing headers with "NOT" or "MISSING"
    script_section = re.search(
        r"http-security-headers:(.*?)(?=\n\S|\Z)", nmap_output, re.DOTALL
    )
    if not script_section:
        return findings

    script_text = script_section.group(1)

    for header, (label, risk, solution) in REQUIRED_HEADERS.items():
        # Nmap NSE script reports missing headers with a line that includes the header name
        # but lacks the actual value — we detect absence by checking the script output
        if header not in script_text:
            findings.append(_build_finding(
                vuln_type   = label,
                risk_level  = risk,
                url         = target_url,
                description = (
                    f"The HTTP response is missing the `{header}` security header. "
                    f"This was detected by Nmap's http-security-headers NSE script."
                ),
                evidence    = f"Header `{header}` not present in HTTP response.",
                solution    = solution,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_nmap_scan(target_url: str, ports: list[int] = None, stop_event=None) -> list[dict]:
    """
    Run a stealthy Nmap infrastructure scan against the target.

    Flags used:
        -p <ports> or -F : Scan specified ports (or top 100 ports if none provided)
        -T4     : Aggressive timing (extremely fast, prevents timeouts)
        -Pn     : Skip host ping check
        -sV     : Detect service and version information
        --script=http-security-headers : Check for missing HTTP security headers

    stop_event: optional threading.Event. When set, the Nmap subprocess is
                immediately killed so the scan aborts without hanging the worker.

    Returns a list of vulnerability dicts in the standard Vultix format.
    If Nmap is not installed, returns a single informational finding instead
    of crashing the scan.
    """
    if not _nmap_available():
        return [_build_finding(
            vuln_type   = "Nmap Not Installed",
            risk_level  = "Info",
            url         = target_url,
            description = (
                "Nmap is not installed on the server running this scanner. "
                "Infrastructure scanning was skipped. Install Nmap to enable this feature."
            ),
            evidence    = "shutil.which('nmap') returned None",
            solution    = (
                "Install Nmap: Windows → https://nmap.org/download.html | "
                "Linux → sudo apt-get install nmap"
            ),
        )]

    host = _extract_host(target_url)

    nmap_exe = _get_nmap_path() or "nmap"
    
    # Build port argument dynamically if ports are provided
    port_arg = "-F"
    if ports:
        # Include standard ports 80 and 443 along with the discovered ones
        full_ports = set(ports)
        full_ports.add(80)
        full_ports.add(443)
        # Format as sorted comma-separated string
        port_list_str = ",".join(str(p) for p in sorted(full_ports))
        port_arg_list = ["-p", port_list_str]
    else:
        port_arg_list = ["-F"]

    cmd = [
        nmap_exe,
    ]
    cmd.extend(port_arg_list)
    cmd.extend([
        "-T4",                             # Aggressive timing (extremely fast, prevents timeouts)
        "-Pn",                             # Skip host discovery
        "-sV",                             # Service/version detection
        "--script=http-security-headers",  # NSE header check
        "--script-args", "http.timeout=3s",# Timeout slow HTTP requests inside NSE scripts
        "--max-retries", "1",              # Stop retrying lost packets on firewalled hosts
        "--max-scan-delay", "20ms",        # Prevent WAF rate-limiting from slowing Nmap to a crawl
        "--host-timeout", "45s",           # Standard limit: tell Nmap to stop scanning this host if it takes > 45s
        host,
    ])

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Poll until done, stop_event is triggered, or we hit a hard execution ceiling
        import time as _time
        start_poll = _time.time()
        max_scan_time = 50.0  # 50-second ceiling (slightly above the 45s Nmap host-timeout)
        
        while proc.poll() is None:
            # Check cancel signal
            if stop_event is not None and stop_event.is_set():
                proc.kill()
                return []   # Cancelled — return empty, caller handles cleanup
                
            # Check hard timeout limit
            if _time.time() - start_poll > max_scan_time:
                proc.kill()
                break
                
            _time.sleep(0.5)  # Poll every 500ms

        nmap_output = proc.stdout.read()
        if proc.returncode != 0 and not nmap_output:
            nmap_output = proc.stderr.read()

    except FileNotFoundError:
        return [_build_finding(
            vuln_type   = "Nmap Not Found",
            risk_level  = "Info",
            url         = target_url,
            description = "Nmap binary not found. Infrastructure scanning skipped.",
            evidence    = "FileNotFoundError when executing nmap",
            solution    = "Install Nmap and ensure it is on the system PATH.",
        )]
    except Exception as exc:
        return [_build_finding(
            vuln_type   = "Nmap Execution Error",
            risk_level  = "Info",
            url         = target_url,
            description = f"An unexpected error occurred while running Nmap: {exc}",
            evidence    = str(exc),
            solution    = "Check that Nmap is correctly installed and the system has network access.",
        )]

    findings: list[dict] = []
    findings.extend(_parse_open_ports(nmap_output, target_url))
    findings.extend(_parse_outdated_services(nmap_output, target_url))
    findings.extend(_parse_security_headers(nmap_output, target_url))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CLI — quick test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    results = run_nmap_scan(target)
    print(json.dumps(results, indent=2))
    print(f"\nTotal findings: {len(results)}")
