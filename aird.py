from flask import Flask, request, render_template_string

app = Flask(__name__)

# HTML template as a string
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Page</title>
</head>
<body>
    <h1>Register</h1>
    <form action="/submit" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required><br><br>
        
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        
        <button type="submit">Register</button>
    </form>
</body>
</html>
"""

# Route for the home page
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

# Route to handle form submission
@app.route('/submit', methods=['POST'])
def submit():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    # Process registration data (e.g., save to a database)
    # Display a success message
    return f"""
    <h1>Registration Successful!</h1>
    <p>Username: {username}</p>
    <p>Email: {email}</p>
    """

if __name__ == '__main__':
    app.run(debug=True)
