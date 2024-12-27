from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# HTML content
login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 300px;
        }
        .login-container h2 {
            text-align: center;
        }
        .input-field {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .login-button {
            width: 100%;
            padding: 10px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .login-button:hover {
            background-color: #45a049;
        }
        .error-message {
            color: red;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        {% if error %}
        <p class="error-message">{{ error }}</p>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" class="input-field" placeholder="Username" required><br>
            <input type="password" name="password" class="input-field" placeholder="Password" required><br>
            <button type="submit" class="login-button">Login</button>
        </form>
    </div>
</body>
</html>
'''

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password1"

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the credentials are correct
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            return redirect(url_for('welcome'))
        else:
            error = "Invalid credentials. Please try again."
    
    return render_template_string(login_html, error=error)

@app.route('/welcome')
def welcome():
    return "Welcome to the admin page!"

if __name__ == '__main__':
    app.run(debug=True)
