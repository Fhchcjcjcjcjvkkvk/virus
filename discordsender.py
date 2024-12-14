from flask import Flask, render_template_string, request
import subprocess
import os
import time

# Definice barev pro banner
yellow = "\033[33m"
red = "\033[31m"
reset = "\033[0m"

app = Flask(__name__)

# HTML šablona s bannerem a formulářem
html_template = '''
<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Command Prompt - Controller</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            font-size: 16px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            padding: 10px 15px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover {
            background-color: #0056b3;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            background-color: #e9e9e9;
            border-radius: 4px;
            font-family: monospace;
        }
        .banner {
            text-align: center;
            font-family: monospace;
            font-size: 20px;
            color: #FF6347; /* Barva banneru */
            margin-bottom: 20px;
        }
    </style>
</head>
<body>

<div class="container">
    <div class="banner">
        <p>_____<br>
        __H__<br>
        ["<br>
        [)]<br>
        [)] <span style="color:red">|V.</span></p>
    </div>
    <h2>Command Prompt Controller</h2>
    <form method="POST">
        <label for="cmd">Zadejte příkaz:</label>
        <input type="text" id="cmd" name="cmd" placeholder="Například: ls -l">
        <button type="submit">Spustit příkaz</button>
    </form>

    {% if result %}
    <div class="result">
        <h3>Výsledek příkazu:</h3>
        <pre>{{ result }}</pre>
    </div>
    {% endif %}
</div>

</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        cmd = request.form['cmd']
        
        # Zpracování příkazů
        if cmd == "data_dump":
            result = data_dump()
        elif cmd.startswith("delete "):
            result = delete_file(cmd)
        elif cmd.startswith("gedit "):
            result = gedit_file(cmd)
        else:
            try:
                # Vykonání libovolného shell příkazu
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                result = result.decode('utf-8')  # Převod na textový výstup
            except subprocess.CalledProcessError as e:
                result = f"Chyba při vykonávání příkazu: {e.output.decode('utf-8')}"
    
    return render_template_string(html_template, result=result)

# Příkaz pro zálohování souborů (data_dump)
def data_dump():
    try:
        if not os.path.exists("backup"):
            os.makedirs("backup")
        # Archivace složky 'data' do zálohovacího souboru
        tar_file = "backup/backup_" + str(int(time.time())) + ".tar.gz"
        subprocess.check_call(['tar', '-czf', tar_file, 'data'])

        # Zkontroluje, zda byl soubor vytvořen
        if os.path.exists(tar_file):
            return f"Záloha byla úspěšně vytvořena: {tar_file}"
        else:
            return "Chyba při vytváření zálohy", 500
    except Exception as e:
        return f"Chyba při zálohování: {str(e)}", 500

# Příkaz pro mazání souboru
def delete_file(cmd):
    # Extrahuje název souboru z příkazu
    file_to_delete = cmd[7:].strip()  # Odstraní "delete " a ořízne mezery
    if os.path.exists(file_to_delete):
        os.remove(file_to_delete)
        return f"Soubor {file_to_delete} byl úspěšně smazán."
    else:
        return f"Soubor {file_to_delete} nenalezen."

# Příkaz pro zobrazení souboru (gedit)
def gedit_file(cmd):
    # Extrahuje název souboru z příkazu
    file_to_edit = cmd[6:].strip()  # Odstraní "gedit " a ořízne mezery
    if os.path.exists(file_to_edit):
        with open(file_to_edit, 'r') as f:
            return f.read()
    else:
        return f"Soubor {file_to_edit} nenalezen."

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
