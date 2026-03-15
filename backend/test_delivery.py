import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

from app.services.credential_service import send_email_notification, send_whatsapp_notification, build_email_html, build_whatsapp_message

email_html = build_email_html(
    username="test",
    temp_password="password",
    token_link="http://test.com",
    admin_name="admin",
    admin_message="Hello",
    expires_hours=24
)

wa_msg = build_whatsapp_message(
    username="test",
    temp_password="password",
    token_link="http://test.com",
    admin_name="admin",
    admin_message="Hello",
    expires_hours=24
)

print("EMAIL HTML LENGTH:", len(email_html))
print("TESTING EMAIL...")
try:
    status = send_email_notification(["honeynet.verify@gmail.com"], "Test", email_html, "Plain")
    print("EMAIL STATUS:", status)
except Exception as e:
    print("EMAIL ERROR:", e)

print("TESTING WHATSAPP...")
try:
    status = send_whatsapp_notification("+917461077318", wa_msg)
    print("WHATSAPP STATUS:", status)
except Exception as e:
    print("WHATSAPP ERROR:", e)
