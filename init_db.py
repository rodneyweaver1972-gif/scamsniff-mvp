import sqlite3

conn = sqlite3.connect("scans.db")
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    score INTEGER,
    label TEXT,
    reasons TEXT,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()
