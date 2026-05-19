import asyncio
from models.auth_db import create_user

async def main():
    try:
        success, result = await create_user("TestUser2", "test2@example.com", "password123")
        print(f"Success: {success}, Result: {result}")
    except Exception as e:
        print(f"DB Error: {e}")

asyncio.run(main())
