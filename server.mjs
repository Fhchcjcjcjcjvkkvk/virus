const express = require('express');
const bodyParser = require('body-parser');
const chalk = require('chalk');

// Create an express app
const app = express();

// Middleware to parse the POST request body
app.use(bodyParser.urlencoded({ extended: true }));

// Define the POST route to receive login data
app.post('/', (req, res) => {
    const { username, password } = req.body;

    // Log the credentials using chalk to print them in green
    console.log(chalk.green(`Username: ${username}`));
    console.log(chalk.green(`Password: ${password}`));

    // Send a response back to the client
    res.send('Credentials received successfully');
});

// Start the server on IP 10.0.1.33 and port 3000
const host = '10.0.1.33';
const port = 3000;
app.listen(port, host, () => {
    console.log(`Server is running on http://${host}:${port}`);
});
