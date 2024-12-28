const express = require('express');
const bodyParser = require('body-parser');

const app = express();

// Middleware to parse URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Set up a simple route to display the login form
app.get('/', (req, res) => {
  res.send(`
    <html>
      <body>
        <h2>Login</h2>
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

// Handle login POST request
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Check if the username and password match the credentials
  if (username === 'admin' && password === 'password1') {
    res.send('<h2>Login successful!</h2>');
  } else {
    res.send('<h2>Invalid username or password.</h2>');
  }
});

// Start the server to listen on IP 10.0.1.33
const port = 3000;
const localIp = '10.0.1.33';

app.listen(port, localIp, () => {
  console.log(`Server is running at http://${localIp}:${port}`);
});
