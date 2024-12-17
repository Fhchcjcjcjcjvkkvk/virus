// Import the required modules
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');

// Initialize the app and create the server
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Create a route for the homepage
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Set up a connection listener for sockets
io.on('connection', (socket) => {
  console.log('A user connected');
  
  // Broadcast a message to all users when a new user joins
  socket.broadcast.emit('message', 'A new user has joined the chat.');

  // Listen for incoming messages and broadcast them to all users
  socket.on('chatMessage', (msg) => {
    io.emit('message', msg);
  });

  // Handle user disconnecting
  socket.on('disconnect', () => {
    console.log('A user disconnected');
    io.emit('message', 'A user has left the chat.');
  });
});

// Get your local IP address (useful for local network access)
const os = require('os');
const ifaces = os.networkInterfaces();
let localIp = '';

for (const iface in ifaces) {
  ifaces[iface].forEach((details) => {
    if (details.family === 'IPv4' && !details.internal) {
      localIp = details.address;
    }
  });
}

const PORT = 3000; // You can change the port number if needed
const HOST = localIp; // Local IP address

// Start the server on your local IP and port
server.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}`);
});
