const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;

// Middleware to parse request body
app.use(bodyParser.urlencoded({ extended: true }));

// Serve the login page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login Page</title>
    </head>
    <body>
      <h1>Login</h1>
      <form action="/login" method="post">
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

  // Check credentials
  if (username === 'admin' && password === 'password1') {
    res.send('<h1>Login successful!</h1>');
  } else {
    res.send('<h1>Invalid credentials. Please try again.</h1>');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
