import requests

try:
    response = requests.post(
        "http://127.0.0.1:5050/api/auth/register",
        json={
            "username": "TestUser",
            "email": "atulamrithmenon@gmail.com",
            "password": "password123",
            "confirm_password": "password123"
        }
    )
    print("Status Code:", response.status_code)
    print("Response:", response.text)
except Exception as e:
    print("Failed to connect:", e)
