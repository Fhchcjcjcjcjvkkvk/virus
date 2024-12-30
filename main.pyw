import tkinter as tk

# Create the root window
root = tk.Tk()
root.title("Decryptor")

# Set window size and background color
root.geometry("600x400")
root.configure(bg='red')

# Create the label with the ransom note message
note_label = tk.Label(root, text="YOUR FILES HAVE BEEN ENCRYPTED!\nTo decrypt find the magic key!", 
                      font=("Helvetica", 20, "bold"), fg="white", bg="red", padx=20, pady=20)
note_label.pack(expand=True)

# Create the "!" label at the bottom
exclamation_label = tk.Label(root, text="!", font=("Helvetica", 100, "bold"), fg="white", bg="red")
exclamation_label.pack(side="bottom", pady=20)

# Run the application
root.mainloop()
