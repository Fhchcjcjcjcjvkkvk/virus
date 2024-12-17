const http = require('http');
const fs = require('fs');
const chokidar = require('chokidar');

// Get local IP address
const localIp = require('os').networkInterfaces().en0[1].address;  // Adjust based on your OS (en0 is typically used for macOS)

let lastMessage = '';

// Watch the specified directory for changes
const watcher = chokidar.watch('./watched-folder', { persistent: true });

watcher.on('change', (path) => {
  lastMessage = `File saved: ${path}`;
  console.log(lastMessage);
});

// Create an HTTP server
const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(lastMessage || 'No file changes yet.');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
});

// Start server on local IP address at port 3000
server.listen(3000, localIp, () => {
  console.log(`Server running at http://${localIp}:3000`);
});
