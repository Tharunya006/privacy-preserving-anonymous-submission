import sqlite3

DATABASE = "database/app.db"

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

# Insert test user
cursor.execute("""
    INSERT OR IGNORE INTO users (username, password, role)
    VALUES (?, ?, ?)
""", ("admin", "test123", "receiver"))

# Insert test submission
cursor.execute("""
    INSERT OR IGNORE INTO submissions
    (submission_token, title, content, status)
    VALUES (?, ?, ?, ?)
""", (
    "TEST-TOKEN-001",
    "Test Anonymous Report",
    "This is a test submission for Phase 1.",
    "Submitted"
))

connection.commit()
connection.close()

print("Test user and submission inserted successfully!")