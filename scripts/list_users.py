import sys
import os
import asyncio

# Add project root to python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlmodel import select
from models.auth_db import AsyncSessionLocal, User

async def list_users():
    async with AsyncSessionLocal() as session:
        try:
            statement = select(User)
            result = await session.execute(statement)
            users = result.scalars().all()
            
            if not users:
                print("No users found in the MySQL database. You need to register one!")
            else:
                print("--- Registered Users (MySQL) ---")
                for u in users:
                    print(f"ID: {u.id} | Username: {u.username} | Email: {u.email}")
            
        except Exception as e:
            print(f"Error reading MySQL database: {e}")

if __name__ == "__main__":
    asyncio.run(list_users())
