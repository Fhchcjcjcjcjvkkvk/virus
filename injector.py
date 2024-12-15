import sqlite3

# Create a connection to SQLite database
conn = sqlite3.connect('ducky.db')
cursor = conn.cursor()

# Create table 'duckys' if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS duckys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

# Insert a test user into the 'duckys' table (for testing purposes)
cursor.execute('''
    INSERT INTO duckys (username, password)
    VALUES ('testuser', 'password123')
''')

# Commit the transaction and close the connection
conn.commit()
conn.close()

print("Database and table created successfully.")
