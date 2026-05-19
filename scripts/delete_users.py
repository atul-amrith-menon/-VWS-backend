import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'vultix.db')
if not os.path.exists(db_path):
    print("Database not found.")
else:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable foreign keys so CASCADE works
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Delete all users (which will also delete their refresh tokens via CASCADE)
        cursor.execute("DELETE FROM users")
        conn.commit()
        
        print("Successfully deleted all user accounts and active login sessions!")
        
    except Exception as e:
        print(f"Error clearing database: {e}")
    finally:
        conn.close()
