from flask import Flask, render_template_string, request

app = Flask(__name__)

# HTML content for the login page
login_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <h2>Login Page</h2>
    <form action="/login" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Simulate login logic (e.g., checking credentials)
        if username == "admin" and password == "password":
            return "Login successful!"
        return "Invalid credentials!"
    return render_template_string(login_html)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)  # Start the app without SSL
