from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Simulate login logic (e.g., checking credentials)
        if username == "admin" and password == "password":
            return "Login successful!"
        return "Invalid credentials!"
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)  # Start the app without SSL
