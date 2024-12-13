from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>Welcome to the XSS Test Page</h1>
    <form method="POST" action="/submit">
        <label for="input">Enter something:</label><br>
        <input type="text" id="input" name="input"><br>
        <button type="submit">Submit</button>
    </form>
    '''

@app.route('/submit', methods=['POST'])
def submit():
    user_input = request.form.get('input', '')
    # Vulnerable rendering: Directly displaying user input without sanitization
    response = f"""
    <h1>Submitted Data</h1>
    <p>You entered: {user_input}</p>
    <a href="/">Go back</a>
    """
    return render_template_string(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
