import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'vultix.db')
if not os.path.exists(db_path):
    print("Database not found.")
else:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users")
        users = cursor.fetchall()
        
        if not users:
            print("No users found in the database. You need to register one!")
        else:
            print("--- Registered Users ---")
            for u in users:
                print(f"ID: {u[0]} | Username: {u[1]} | Email: {u[2]}")
        
    except Exception as e:
        print(f"Error reading database: {e}")
