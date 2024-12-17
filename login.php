<?php
// Připojení k databázi
$servername = "localhost";
$username = "root";  // Změňte podle vaší konfigurace
$password = "";      // Změňte podle vaší konfigurace
$dbname = "testdb";  // Název databáze

$conn = new mysqli($servername, $username, $password, $dbname);

// Zkontrolujte připojení
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Zpracování formuláře
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // SQL dotaz je zranitelný vůči SQL injection, protože uživatelský vstup není escapován
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        echo "Login successful!";
    } else {
        echo "Invalid username or password!";
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST" action="login.php">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>

        <input type="submit" value="Login">
    </form>
</body>
</html>
