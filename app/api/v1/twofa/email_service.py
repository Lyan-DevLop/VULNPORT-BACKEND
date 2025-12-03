import smtplib
from email.mime.text import MIMEText

SMTP_USER = "tu_email@gmail.com"
SMTP_PASS = "contraseña_de_app"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587


def send_email_code(email_to: str, code: str):
    body = f"""
    Tu código de verificación para VULNPORTS es:

    🔐 {code}

    Este código expira en 10 minutos.
    """

    msg = MIMEText(body)
    msg["Subject"] = "Código de verificación - VULNPORTS"
    msg["From"] = SMTP_USER
    msg["To"] = email_to

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, email_to, msg.as_string())

    return True
