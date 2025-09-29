from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from django.conf import settings

def send_otp_email(email, otp):
    message = Mail(
        from_email=settings.DEFAULT_FROM_EMAIL,   # ✅ better: take from settings
        to_emails=email,
        subject='Your OTP Code',
        plain_text_content=f'Your OTP is: {otp}'
    )
    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)  # ✅ keep key in settings/env
        response = sg.send(message)
        print(f"[EMAIL] OTP sent to {email} | Status: {response.status_code}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {str(e)}")
        return False
