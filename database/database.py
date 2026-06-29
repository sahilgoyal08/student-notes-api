import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def setup_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)
    
    # 2. ADD THIS: Create notes table linked to the user
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id SERIAL PRIMARY KEY,
        heading TEXT NOT NULL,
        content TEXT NOT NULL,
        owner_username TEXT NOT NULL REFERENCES users(username)
    )
    """)
    
    conn.commit()
    conn.close()