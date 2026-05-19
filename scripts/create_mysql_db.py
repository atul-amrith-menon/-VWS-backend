import asyncio
import aiomysql

async def create_db():
    try:
        print("Connecting to MySQL with password '2006'...")
        conn = await aiomysql.connect(
            host='localhost',
            port=3306,
            user='root',
            password='2006',
            autocommit=True
        )
        async with conn.cursor() as cursor:
            await cursor.execute("CREATE DATABASE IF NOT EXISTS vultix CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            print("✅ Database 'vultix' successfully created!")
        conn.close()
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(create_db())
