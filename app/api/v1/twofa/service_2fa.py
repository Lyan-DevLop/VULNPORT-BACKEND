import random
from datetime import datetime, timedelta
import pyotp

from .email_service import send_email_code


# ==========================
# EMAIL 2FA
# ==========================
def generate_email_2fa_code():
    return str(random.randint(100000, 999999))


def send_email_2fa_code(user, db):
    code = generate_email_2fa_code()
    user.email_2fa_code = code
    user.email_2fa_expiration = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    send_email_code(user.email, code)
    return True


def verify_email_code(user, code):
    if not user.email_2fa_code:
        return False

    if user.email_2fa_expiration < datetime.utcnow():
        return False

    return user.email_2fa_code == code


# ==========================
# TOTP – APP MÓVIL (Authy, Google Authenticator)
# ==========================
def verify_totp_code(user, code):
    if not user.totp_secret:
        return False

    totp = pyotp.TOTP(user.totp_secret)

    try:
        return totp.verify(code)
    except Exception:
        return False
