import asyncio
import aiomysql

async def check_users():
    conn = await aiomysql.connect(
        host='localhost',
        port=3306,
        user='root',
        password='2006',
        db='vultix'
    )
    async with conn.cursor() as cursor:
        await cursor.execute("SELECT COUNT(*) FROM users;")
        result = await cursor.fetchone()
        print(f"Total users in MySQL database: {result[0]}")
    conn.close()

if __name__ == "__main__":
    asyncio.run(check_users())
