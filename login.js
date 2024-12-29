const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const localIP = '10.0.1.33';

// Hardcoded credentials
const validUsername = 'admin';
const validPassword = 'password123';

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve the login form
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Login Page</title>
      </head>
      <body>
        <h1>Login</h1>
        <form method="POST" action="/login">
          <label for="username">Username:</label>
          <input type="text" id="username" name="username" required><br><br>
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" required><br><br>
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `);
});

// Handle login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === validUsername && password === validPassword) {
    res.send('<h1>Login successful!</h1>');
  } else {
    res.send('<h1>Login failed. Invalid credentials.</h1>');
  }
});

// Start the server
app.listen(port, localIP, () => {
  console.log(`Server running at http://${localIP}:${port}/`);
});
