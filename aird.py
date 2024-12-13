from flask import Flask, render_template, request

app = Flask(__name__)

# Route for the home page
@app.route('/')
def home():
    return render_template('register.html')

# Route to handle form submission
@app.route('/submit', methods=['POST'])
def submit():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    # Here you can process the registration data, e.g., save to a database
    # For simplicity, we'll just display it on the screen
    return f"<h1>Registration Successful!</h1><p>Username: {username}</p><p>Email: {email}</p>"

if __name__ == '__main__':
    app.run(debug=True)
