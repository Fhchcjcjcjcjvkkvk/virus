const express = require('express');
const app = express();
const bodyParser = require('body-parser');

// Middleware to parse JSON and URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Admin credentials
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'password1';

// Serve the HTML content
app.get('/', (req, res) => {
    res.send(`
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
                <p id="error" class="error-message" style="display: none;">Invalid credentials. Please try again.</p>
                <form id="loginForm">
                    <input type="text" id="username" class="input-field" placeholder="Username" required><br>
                    <input type="password" id="password" class="input-field" placeholder="Password" required><br>
                    <button type="submit" class="login-button">Login</button>
                </form>
            </div>
            <script>
                document.getElementById('loginForm').addEventListener('submit', async (event) => {
                    event.preventDefault(); // Prevent form from reloading the page
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;

                    // Send login request to the server
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password }),
                    });

                    if (response.ok) {
                        window.location.href = '/welcome'; // Redirect to welcome page
                    } else {
                        document.getElementById('error').style.display = 'block';
                    }
                });
            </script>
        </body>
        </html>
    `);
});

// Handle login requests
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check credentials
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        return res.status(200).send('Success');
    }
    res.status(401).send('Unauthorized');
});

// Serve the welcome page
app.get('/welcome', (req, res) => {
    res.send('<h1>Welcome to the admin page!</h1>');
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
