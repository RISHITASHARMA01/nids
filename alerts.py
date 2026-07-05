#!/usr/bin/env python3
import smtplib, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
load_dotenv()

class EmailAlerter:
    def __init__(self):
        self.sender   = os.getenv("EMAIL_SENDER", "")
        self.password = os.getenv("EMAIL_PASSWORD", "")
        self.receiver = os.getenv("EMAIL_RECEIVER", "")
        self.enabled  = all([self.sender, self.password, self.receiver,
                             self.password != "your_16_digit_app_password_here"])
        if not self.enabled:
            print("  [!] Email alerts disabled - configure .env to enable")

    def send(self, subject: str, body: str):
        if not self.enabled: return
        try:
            msg = MIMEMultipart()
            msg["From"]    = self.sender
            msg["To"]      = self.receiver
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.sender, self.password)
                server.send_message(msg)
            print(f"  [EMAIL] Alert sent to {self.receiver}")
        except Exception as e:
            print(f"  [!] Email failed: {e}")
