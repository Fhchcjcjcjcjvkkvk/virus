<?php
// Připojení k databázi
$servername = "localhost";
$username = "root";  // Nahraďte skutečným uživatelským jménem
$password = "";  // Nahraďte skutečným heslem
$dbname = "testdb";  // Nahraďte skutečným názvem databáze

// Vytvoření připojení
$conn = new mysqli($servername, $username, $password, $dbname);

// Zkontrolujte připojení
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Zpracování přihlášení, pokud byl odeslán formulář
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Získání uživatelského vstupu z formuláře
    $username_input = $_POST['username'];
    $password_input = $_POST['password'];
    
    // Zranitelný SQL dotaz (uživatelský vstup není nikdy ošetřen)
    // Poznámka: Tento dotaz umožňuje SQL injection
    $sql = "SELECT * FROM users WHERE username='$username_input' AND password='$password_input'";

    // Provedení dotazu
    $result = $conn->query($sql);

    // Kontrola výsledku
    if ($result->num_rows > 0) {
        // Uživatelský účet nalezen, přihlášení úspěšné
        echo "Vítejte, " . $username_input . "!";
    } else {
        // Špatné přihlašovací údaje
        echo "Neplatné uživatelské jméno nebo heslo.";
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
</head>
<body>

<h2>Přihlášení</h2>
<form method="POST" action="">
    Uživatelské jméno: <input type="text" name="username" required><br><br>
    Heslo: <input type="password" name="password" required><br><br>
    <input type="submit" value="Přihlásit se">
</form>

</body>
</html>
