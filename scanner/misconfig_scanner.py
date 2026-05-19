import requests
from urllib.parse import urljoin


# Security headers to check
SECURITY_HEADERS = {
    'X-Frame-Options': {
        'description': 'Missing X-Frame-Options header. The site may be vulnerable to clickjacking attacks.',
        'risk': 'Medium',
        'solution': 'Set the X-Frame-Options header to DENY or SAMEORIGIN.'
    },
    'Content-Security-Policy': {
        'description': 'Missing Content-Security-Policy header. No CSP policy is set, allowing potential XSS attacks.',
        'risk': 'Medium',
        'solution': 'Implement a Content-Security-Policy header to restrict resource loading sources.'
    },
    'Strict-Transport-Security': {
        'description': 'Missing Strict-Transport-Security (HSTS) header. The site does not enforce HTTPS connections.',
        'risk': 'Medium',
        'solution': 'Add Strict-Transport-Security header with a max-age of at least 31536000 seconds.'
    },
    'X-Content-Type-Options': {
        'description': 'Missing X-Content-Type-Options header. The browser may MIME-sniff the response.',
        'risk': 'Low',
        'solution': 'Set X-Content-Type-Options to "nosniff".'
    },
    'X-XSS-Protection': {
        'description': 'Missing X-XSS-Protection header. Browser-level XSS filtering is not enforced.',
        'risk': 'Low',
        'solution': 'Set X-XSS-Protection to "1; mode=block".'
    },
    'Referrer-Policy': {
        'description': 'Missing Referrer-Policy header. Sensitive URL information may leak via the Referer header.',
        'risk': 'Low',
        'solution': 'Set Referrer-Policy to "strict-origin-when-cross-origin" or "no-referrer".'
    },
    'Permissions-Policy': {
        'description': 'Missing Permissions-Policy header. Browser features are not restricted.',
        'risk': 'Low',
        'solution': 'Implement Permissions-Policy to restrict access to browser APIs and features.'
    },
}

# Sensitive files/paths to check
SENSITIVE_PATHS = [
    # Configuration & credentials
    ('/.env',                'Environment file (.env) exposed — may contain DB passwords, API keys, secrets', 'High'),
    ('/.env.local',          'Local environment file exposed', 'High'),
    ('/.env.production',     'Production environment file exposed', 'High'),
    ('/.git/config',         'Git repository configuration file exposed', 'High'),
    ('/.git/HEAD',           'Git repository HEAD file exposed — source code may be downloadable', 'High'),
    ('/.gitignore',          'Git ignore file exposed — reveals project structure', 'Low'),
    ('/config.php',          'PHP configuration file potentially exposed', 'High'),
    ('/config.yml',          'YAML configuration file exposed', 'High'),
    ('/config.json',         'JSON configuration file exposed', 'High'),
    ('/web.config',          'IIS web.config file accessible', 'High'),
    ('/.htaccess',           'Apache .htaccess file accessible', 'Medium'),
    ('/wp-config.php',       'WordPress config file exposed — contains DB credentials', 'High'),
    # Admin panels
    ('/phpmyadmin/',         'phpMyAdmin database admin interface exposed', 'High'),
    ('/phpmyadmin/index.php','phpMyAdmin database admin interface exposed', 'High'),
    ('/wp-admin/',           'WordPress admin panel accessible', 'Medium'),
    ('/admin/',              'Admin panel potentially accessible', 'Medium'),
    ('/administrator/',      'Administrator panel potentially accessible', 'Medium'),
    ('/manage/',             'Management panel accessible', 'Medium'),
    ('/dashboard/',          'Dashboard accessible without authentication check', 'Low'),
    # Debug / info pages
    ('/phpinfo.php',         'PHP info page exposed — reveals server configuration', 'Medium'),
    ('/info.php',            'PHP info page exposed', 'Medium'),
    ('/server-status',       'Apache server-status page exposed', 'Medium'),
    ('/server-info',         'Apache server-info page exposed', 'Medium'),
    ('/debug/',              'Debug endpoint accessible', 'Medium'),
    ('/test/',               'Test directory accessible', 'Low'),
    ('/test.php',            'Test PHP file accessible', 'Low'),
    # Backup & archive files
    ('/backup/',             'Backup directory potentially accessible', 'High'),
    ('/backup.zip',          'Backup zip archive exposed', 'High'),
    ('/backup.tar.gz',       'Backup tar archive exposed', 'High'),
    ('/db.sql',              'SQL database dump exposed', 'High'),
    ('/dump.sql',            'SQL dump file exposed', 'High'),
    ('/database.sql',        'Database SQL file exposed', 'High'),
    # Log files
    ('/error.log',           'Error log file exposed', 'Medium'),
    ('/access.log',          'Access log file exposed', 'Medium'),
    ('/debug.log',           'Debug log file exposed', 'Medium'),
    # Miscellaneous
    ('/.DS_Store',           'macOS DS_Store metadata file exposed', 'Low'),
    ('/crossdomain.xml',     'Flash cross-domain policy file found', 'Low'),
    ('/robots.txt',          'Robots.txt file found (informational)', 'Info'),
    ('/sitemap.xml',         'Sitemap.xml file found (informational)', 'Info'),
]

# Server headers that reveal version info
SERVER_VERSION_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']


class MisconfigScanner:
    """Check for security misconfigurations."""

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.vulnerabilities = []

    def scan_headers(self, page):
        """Check for missing security headers."""
        headers = page.get('headers', {})
        url = page['url']

        # Check for missing security headers
        for header_name, info in SECURITY_HEADERS.items():
            header_found = False
            for key in headers:
                if key.lower() == header_name.lower():
                    header_found = True
                    break

            if not header_found:
                self.vulnerabilities.append({
                    'vuln_type': 'Security Misconfiguration',
                    'risk_level': info['risk'],
                    'url': url,
                    'description': info['description'],
                    'evidence': f'Header "{header_name}" is not present in the response.',
                    'solution': info['solution']
                })

        # Check for server version disclosure
        for header_name in SERVER_VERSION_HEADERS:
            for key, value in headers.items():
                if key.lower() == header_name.lower() and value:
                    self.vulnerabilities.append({
                        'vuln_type': 'Security Misconfiguration',
                        'risk_level': 'Low',
                        'url': url,
                        'description': (
                            f'Server version information disclosed via "{header_name}" header. '
                            f'This information helps attackers identify known vulnerabilities.'
                        ),
                        'evidence': f'{header_name}: {value}',
                        'solution': (
                            f'Remove or suppress the "{header_name}" header to prevent '
                            f'information disclosure.'
                        )
                    })

    def scan_sensitive_files(self, base_url):
        """Check for exposed sensitive files and directories."""
        for path, description, risk in SENSITIVE_PATHS:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=self.timeout,
                                           verify=False, allow_redirects=False)

                # Only flag if we get a 200 response with some content
                if response.status_code == 200 and len(response.text) > 0:
                    if risk == 'Info':
                        self.vulnerabilities.append({
                            'vuln_type': 'Sensitive File Exposure',
                            'risk_level': risk,
                            'url': test_url,
                            'description': description,
                            'evidence': f'HTTP {response.status_code} returned for {path}',
                            'solution': (
                                'Review the file contents and restrict access if it '
                                'contains sensitive or internal information.'
                            )
                        })
                    else:
                        self.vulnerabilities.append({
                            'vuln_type': 'Sensitive File Exposure',
                            'risk_level': risk,
                            'url': test_url,
                            'description': (
                                f'{description}. This file or directory is publicly '
                                f'accessible and may expose sensitive server information.'
                            ),
                            'evidence': (
                                f'HTTP {response.status_code} returned for {path} '
                                f'({len(response.text)} bytes)'
                            ),
                            'solution': (
                                'Restrict access to this path via server configuration '
                                '(e.g., deny in .htaccess or nginx config), or remove '
                                'the file from the web root entirely.'
                            )
                        })

            except requests.exceptions.RequestException:
                continue

    def check_https(self, url):
        """Check if the site uses HTTPS."""
        if url.startswith('http://'):
            self.vulnerabilities.append({
                'vuln_type': 'Security Misconfiguration',
                'risk_level': 'Medium',
                'url': url,
                'description': (
                    'The target website is served over HTTP (unencrypted). '
                    'All data transmitted between the client and server can be '
                    'intercepted by a network attacker (man-in-the-middle).'
                ),
                'evidence': 'URL scheme is HTTP, not HTTPS.',
                'solution': (
                    'Enable HTTPS with a valid TLS/SSL certificate. Redirect all '
                    'HTTP traffic to HTTPS and set the Strict-Transport-Security header.'
                )
            })

    def get_results(self):
        """Return deduplicated results."""
        seen = set()
        unique = []
        for v in self.vulnerabilities:
            desc_snippet = v['description'][:80] if v['description'] else ''
            key = (v['vuln_type'], v['url'], desc_snippet)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
