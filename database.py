import sqlite3

conn = sqlite3.connect("phishing.db")
cursor = conn.cursor()

# USERS TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT UNIQUE,
    password TEXT
)
""")

# SCANS TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email_text TEXT,
    prediction TEXT,
    risk_score INTEGER,
    reasons TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS admins(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
""")

conn.commit()
conn.close()

print("Database created successfully")