const express = require('express');
const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.post('/', (req, res) => {
    console.log('Received POST data:', req.body);
    res.send('ERORR!');
});

app.listen(port, () => {
    console.log(`Server running at http://10.0.1.33:${port}`);
});
