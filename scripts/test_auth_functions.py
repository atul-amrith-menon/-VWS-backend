import asyncio
from models.auth_db import create_user, validate_user

async def test_auth():
    print("Testing create_user...")
    success, user_id_or_err = await create_user("testuser", "test@example.com", "password123")
    print(f"create_user result: {success}, {user_id_or_err}")

    if success:
        print("Testing validate_user...")
        user = await validate_user("testuser", "password123")
        print(f"validate_user result: {user}")

if __name__ == "__main__":
    asyncio.run(test_auth())
