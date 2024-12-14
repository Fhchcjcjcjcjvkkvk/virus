from flask import Flask, request, render_template_string
import xml.etree.ElementTree as ET  # Pozor: standardní knihovna, zranitelná vůči XXE

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    # Jednoduchá HTML šablona
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>XXE Test Web</title>
    </head>
    <body>
        <h1>XXE Vulnerability Test</h1>
        <p>Zadejte XML kód a sledujte výsledek:</p>
        <form method="POST" action="/">
            <label for="xml">Váš XML kód:</label><br>
            <textarea id="xml" name="xml" rows="10" cols="50"></textarea><br><br>
            <button type="submit">Odeslat</button>
        </form>
        {% if result %}
            <h2>Výsledek:</h2>
            <pre>{{ result }}</pre>
        {% endif %}
    </body>
    </html>
    """

    result = None

    if request.method == "POST":
        xml_data = request.form.get("xml", "")
        try:
            # Pokus o parsování zadaného XML
            root = ET.fromstring(xml_data)
            result = ET.tostring(root, encoding="unicode")
        except Exception as e:
            result = f"Chyba při parsování XML: {e}"

    return render_template_string(html_template, result=result)

if __name__ == "__main__":
    app.run(debug=True)
