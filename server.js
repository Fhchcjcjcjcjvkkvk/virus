// Server-side code (server.js)
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const os = require('os');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

io.on('connection', (socket) => {
  console.log('A user connected');
  
  // Broadcast a message when a user joins
  socket.broadcast.emit('message', 'A new user has joined the chat.');

  // Handle incoming chat messages from clients
  socket.on('chatMessage', (msg) => {
    console.log('Received message:', msg);  // Log the received message on the server
    io.emit('message', msg);  // Broadcast the message to all users
  });

  // Handle user disconnecting
  socket.on('disconnect', () => {
    console.log('A user disconnected');
    io.emit('message', 'A user has left the chat.');
  });
});

const ifaces = os.networkInterfaces();
let localIp = '';
for (const iface in ifaces) {
  ifaces[iface].forEach((details) => {
    if (details.family === 'IPv4' && !details.internal) {
      localIp = details.address;
    }
  });
}

const PORT = 3000;
const HOST = localIp;

server.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}`);
});
