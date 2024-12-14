<?php
// Tento PHP skript bude posílat příkazy na Python server pro vykonání příkazů.

if (isset($_REQUEST['cmd'])) {
    $cmd = $_REQUEST['cmd']; // Přečte příkaz z URL
    $url = 'http://10.0.1.12:5000'; // Python server běží na localhostu a portu 5000

    // Odesílání POST požadavku na Python server
    $data = array('cmd' => $cmd);
    $options = array(
        'http' => array(
            'method'  => 'POST',
            'header'  => 'Content-type: application/x-www-form-urlencoded',
            'content' => http_build_query($data)
        )
    );
    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    echo $result; // Výstup z Python serveru
}
?>
