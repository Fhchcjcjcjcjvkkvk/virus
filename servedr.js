// server.js
const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

app.use(express.static('public')); // pro servírování statických souborů (HTML, JS, CSS)
app.use(express.urlencoded({ extended: true })); // pro zpracování formulářových dat

// Základní stránka
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Zpracování přihlášení
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'password1') {
    res.send('<h1>Úspěšně přihlášeno!</h1>');
  } else {
    res.send('<h1>Chybné uživatelské jméno nebo heslo</h1>');
  }
});

app.listen(port, () => {
  console.log(`Server běží na http://localhost:${port}`);
});
