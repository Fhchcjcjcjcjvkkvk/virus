from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Initialize a simple SQLite database
def init_db():
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123')")
    conn.commit()
    conn.close()

# Vulnerable SQL query (for educational purposes only)
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Vulnerable query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        conn = sqlite3.connect("example.db")
        cursor = conn.cursor()

        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            if user:
                return "<h1>Login successful!</h1>"
            else:
                return "<h1>Invalid credentials.</h1>"
        except Exception as e:
            conn.close()
            return f"<h1>Error: {str(e)}</h1>"

    # Simple HTML form
    html = """
    <!doctype html>
    <title>Login</title>
    <h1>Login</h1>
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    """
    return render_template_string(html)

if __name__ == "__main__":
    init_db()  # Initialize the database with a default user
    # Ensure the app runs on Zas-specific host and port environment variables
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=True)
