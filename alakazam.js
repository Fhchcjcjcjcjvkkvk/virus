const express = require('express');
const bodyParser = require('body-parser');
const app = express();

// Middleware to parse URL-encoded form data
app.use(bodyParser.urlencoded({ extended: true }));

// Hardcoded username and password
const validUser = 'alakazam';
const validPassword = 'password1';

// Render the login page
app.get('/', (req, res) => {
    res.send(`
        <html>
            <head>
                <title>Login Page</title>
            </head>
            <body>
                <h1>Login</h1>
                <form action="/login" method="POST">
                    <label for="username">Username:</label><br>
                    <input type="text" id="username" name="username"><br><br>
                    <label for="password">Password:</label><br>
                    <input type="password" id="password" name="password"><br><br>
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
    `);
});

// Handle login requests
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === validUser && password === validPassword) {
        res.redirect('/success');
    } else {
        res.send('Invalid username or password.');
    }
});

// Success page
app.get('/success', (req, res) => {
    res.send('Login successful! Welcome, alakazam.');
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
