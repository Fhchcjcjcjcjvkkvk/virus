from flask import Flask, request, redirect, url_for, render_template_string

app = Flask(__name__)

# Hardcoded user credentials for educational purposes
USER_CREDENTIALS = {
    'username': 'admin',
    'password': 'password123'
}

# HTML login page combined with Python using render_template_string
login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
</head>
<body>
    <h1>Login</h1>
    <form action="/" method="POST">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" required><br><br>
        
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>
        
        <button type="submit">Login</button>
    </form>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve the username and password entered by the user
        username = request.form['username']
        password = request.form['password']

        # Check if the username and password match the hardcoded credentials
        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            return redirect(url_for('welcome'))
        else:
            return "Invalid credentials. Please try again.", 403

    # Show the login page
    return render_template_string(login_html)

@app.route('/welcome')
def welcome():
    return "Welcome to the system!"

if __name__ == '__main__':
    # On Replit, ensure the host is set to '0.0.0.0' and the port is set to 3000.
    app.run(host='0.0.0.0', port=3000, debug=True)
