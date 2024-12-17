const express = require('express');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Nastavení statického souboru (HTML, CSS, JS)
app.use(express.static('public'));

// Zpracování připojení klientů
io.on('connection', (socket) => {
  console.log('New user connected');

  // Posílání zpráv ostatním uživatelům
  socket.on('chat message', (msg) => {
    io.emit('chat message', msg); // Poslat zprávu všem připojeným uživatelům
  });

  // Událost odpojení
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// Změna na naslouchání na všech síťových rozhraních (0.0.0.0)
const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
});
