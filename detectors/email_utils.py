import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app


def send_email(to_address, subject, html_body):
    gmail_address = current_app.config.get("GMAIL_ADDRESS")
    gmail_password = current_app.config.get("GMAIL_APP_PASSWORD")

    if not gmail_address or not gmail_password:
        raise ValueError("Gmail credentials are not configured.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = gmail_address
    msg["To"] = to_address
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(gmail_address, gmail_password)
        server.sendmail(gmail_address, to_address, msg.as_string())
