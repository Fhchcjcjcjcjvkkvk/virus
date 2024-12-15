<?php
// Připojení k databázi
$host = 'localhost';
$username = 'root';
$password = '';
$dbname = 'evil';  // Název databáze 'evil'

$conn = new mysqli($host, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Spojení selhalo: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST['username'];  // Uživatelské jméno z formuláře
    $pass = $_POST['password'];  // Heslo z formuláře

    // Zranitelný SQL dotaz bez ošetření vstupů
    $sql = "SELECT * FROM bots WHERE username = '$user' AND password = '$pass'";

    // Výsledek dotazu
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        echo "Přihlášení úspěšné!";
    } else {
        echo "Neplatné uživatelské jméno nebo heslo!";
    }
}

$conn->close();
?>

<!-- HTML formulář pro přihlášení -->
<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <h2>Přihlášení</h2>
    <form method="POST" action="login.php">
        <label for="username">Uživatelské jméno:</label>
        <input type="text" name="username" id="username" required><br><br>
        <label for="password">Heslo:</label>
        <input type="password" name="password" id="password" required><br><br>
        <input type="submit" value="Přihlásit">
    </form>
</body>
</html>
