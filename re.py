from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Create a simple SQLite database
def init_db():
    conn = sqlite3.connect('database.db')  # Use a file-based database for Replit
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    cursor.execute(\"INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123')\")
    conn.commit()
    return conn

db_connection = init_db()

# Vulnerable login page route
@app.route('/', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # WARNING: This query is vulnerable to SQL injection
        query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"

        cursor = db_connection.cursor()
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            message = \"Login successful! Welcome, {}.\".format(user[0])
        else:
            message = \"Login failed! Invalid credentials.\"

    # HTML template with a login form
    html = \"\"\"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Page</title>
    </head>
    <body>
        <h1>Login</h1>
        <form method=\"POST\">
            <label for=\"username\">Username:</label>
            <input type=\"text\" id=\"username\" name=\"username\"><br>

            <label for=\"password\">Password:</label>
            <input type=\"password\" id=\"password\" name=\"password\"><br>

            <button type=\"submit\">Login</button>
        </form>
        <p>{{ message }}</p>
    </body>
    </html>
    \"\"\"

    return render_template_string(html, message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)  # Required for Replit
