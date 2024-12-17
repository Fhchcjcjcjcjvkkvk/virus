const express = require('express');
const chokidar = require('chokidar');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Get your local IP address (for Windows)
const getLocalIpAddress = () => {
  const networkInterfaces = os.networkInterfaces();
  for (const iface in networkInterfaces) {
    for (const ifaceInfo of networkInterfaces[iface]) {
      if (ifaceInfo.family === 'IPv4' && !ifaceInfo.internal) {
        return ifaceInfo.address;
      }
    }
  }
  return 'localhost'; // Fallback to localhost if no external IP found
};

const localIp = getLocalIpAddress();

// Create an Express app
const app = express();

// Specify the port (you can choose any free port)
const port = 3000;

// Set up static file serving (optional)
app.use(express.static('public'));

// Basic route to test the server
app.get('/', (req, res) => {
  res.send('Server is running on your local IP address!');
});

// Start the server on your local IP address
app.listen(port, localIp, () => {
  console.log(`Server running at http://${localIp}:${port}`);
  console.log(`Or use your local IP address: http://<Your_Local_IP>:${port}`);
});

// Watch for file changes in a specific directory
const watchDir = './watched-folder'; // Directory to watch for file changes
if (!fs.existsSync(watchDir)) {
  fs.mkdirSync(watchDir); // Create the folder if it doesn't exist
}

const watcher = chokidar.watch(watchDir, {
  persistent: true,
});

// Log a message whenever a file is saved (added or modified)
watcher.on('change', (filePath) => {
  console.log(`File changed: ${filePath}`);
  sendMessage('A file was saved!');
});

// Function to simulate sending a message when a file is saved
function sendMessage(message) {
  console.log(`Message: ${message}`);
}

// For testing, let's create an empty file in the watched folder after 5 seconds
setTimeout(() => {
  fs.writeFileSync(path.join(watchDir, 'test.txt'), 'Hello, world!');
}, 5000);
