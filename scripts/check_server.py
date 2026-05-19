import urllib.request

# Check login page
r = urllib.request.urlopen('http://127.0.0.1:5050/login')
html = r.read().decode()
print('Login page status:', r.status)
print('Has login form:', 'form' in html.lower())

# Register a test user
import urllib.parse, json
data = urllib.parse.urlencode({
    'username': 'admin',
    'email': 'admin@vultix.com',
    'password': 'Admin@1234',
    'confirm_password': 'Admin@1234'
}).encode()

req = urllib.request.Request(
    'http://127.0.0.1:5050/register',
    data=data,
    method='POST',
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)
try:
    resp = urllib.request.urlopen(req, timeout=5)
    print('Register status:', resp.status)
    body = resp.read().decode()
    print('Registered OK, on page:', body[:200])
except Exception as e:
    print('Register response:', str(e)[:300])
