from flask import Flask, request, render_template_string
from lxml import etree  # LXML podporuje externí entity (zranitelný parser)

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    template = """
    <!DOCTYPE html>
    <html>
    <head><title>XXE DoS Test</title></head>
    <body>
        <h1>Test XXE DoS</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="50"></textarea><br>
            <button type="submit">Submit</button>
        </form>
        {% if result %}
            <h2>Result:</h2>
            <pre>{{ result }}</pre>
        {% endif %}
    </body>
    </html>
    """
    result = None

    if request.method == "POST":
        xml_data = request.form.get("xml")
        try:
            parser = etree.XMLParser(load_dtd=True, resolve_entities=True)  # Zranitelná konfigurace
            root = etree.fromstring(xml_data, parser)
            result = etree.tostring(root, pretty_print=True).decode()
        except Exception as e:
            result = f"Error: {e}"

    return render_template_string(template, result=result)

if __name__ == "__main__":
    app.run(debug=True)
