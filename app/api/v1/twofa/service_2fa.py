import random
from datetime import datetime, timedelta
import pyotp

from .email_service import send_email_code


# ============================================================
# 🔹 GENERAR CÓDIGO 2FA POR EMAIL
# ============================================================
def generate_email_2fa_code() -> str:
    """
    Genera un código de 6 dígitos SIN perder ceros a la izquierda.
    """
    return f"{random.randint(0, 999999):06d}"


def send_email_2fa_code(user, db):
    """
    Genera y almacena el código en BD con expiración.
    Envía correo HTML corporativo.
    """
    code = generate_email_2fa_code()

    user.email_2fa_code = code
    user.email_2fa_expiration = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    # Enviar correo
    send_email_code(user.email, code, user.username)

    return True


# ============================================================
# 🔹 VALIDACIÓN CÓDIGO EMAIL
# ============================================================
def verify_email_code(user, code: str) -> bool:
    """
    Valida código enviado por correo.
    """
    if not code or not user.email_2fa_code:
        return False

    if not user.email_2fa_expiration or user.email_2fa_expiration < datetime.utcnow():
        return False

    try:
        return user.email_2fa_code.strip() == str(code).strip()
    except:
        return False


# ============================================================
# 🔹 VALIDACIÓN CÓDIGO TOTP (AUTHY / GOOGLE AUTHENTICATOR)
# ============================================================
def verify_totp_code(user, code: str) -> bool:
    """
    Verifica códigos TOTP con tolerancia de ventana.
    valid_window=1 permite 1 paso de 30s de margen.
    """
    if not code or not user.totp_secret:
        return False

    # Validar que el código es numérico de 6 dígitos
    code = str(code).strip()
    if not code.isdigit() or len(code) not in (6, 7):
        return False

    try:
        totp = pyotp.TOTP(user.totp_secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


