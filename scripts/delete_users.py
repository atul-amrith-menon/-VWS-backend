import sys
import os
import asyncio

# Add project root to python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlmodel import select
from sqlalchemy import delete
from models.auth_db import AsyncSessionLocal, User, RefreshToken

async def clear_users():
    async with AsyncSessionLocal() as session:
        try:
            # Delete all refresh tokens first (or MySQL does it via FK checks)
            await session.execute(delete(RefreshToken))
            # Delete all users
            await session.execute(delete(User))
            await session.commit()
            
            print("Successfully deleted all MySQL user accounts and active login sessions!")
            
        except Exception as e:
            print(f"Error clearing MySQL database: {e}")

if __name__ == "__main__":
    asyncio.run(clear_users())
