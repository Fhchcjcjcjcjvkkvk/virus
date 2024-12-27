from PyPDF2 import PdfWriter

# Define the output PDF file path
output_pdf_path = "protected_document.pdf"  # This will save in the current directory

# Create a PdfWriter object
pdf_writer = PdfWriter()

# Add a blank page to the PDF
pdf_writer.add_blank_page(width=72, height=72)  # A basic blank page

# Encrypt the PDF with a password
password = "password1"
pdf_writer.encrypt(password)

# Save the password-protected PDF
with open(output_pdf_path, "wb") as output_pdf:
    pdf_writer.write(output_pdf)

print(f"Password-protected PDF created successfully at: {output_pdf_path}")
