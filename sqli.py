from flask import Flask, request
import sqlite3

app = Flask(__name__)

# Function to simulate a connection to the database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Route for displaying the login page
@app.route('/')
def login():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 50px; }
            .login-container { width: 300px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }
            input { width: 100%; padding: 10px; margin: 10px 0; }
            button { width: 100%; padding: 10px; background-color: #4CAF50; color: white; border: none; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>Login</h2>
            <form action="/login" method="POST">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    '''

# Route to handle login form submission
@app.route('/login', methods=['POST'])
def check_login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerable SQL query (SQL Injection vulnerability here)
    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = conn.execute(query).fetchone()

    if user:
        return f"Welcome, {username}!"
    else:
        return "Login failed. Invalid username or password."

if __name__ == '__main__':
    app.run(debug=True)
