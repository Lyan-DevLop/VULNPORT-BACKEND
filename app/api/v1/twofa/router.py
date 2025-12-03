from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from io import BytesIO
import qrcode
import pyotp

from app.database import get_db
from app.api.deps import get_current_user
from .service_2fa import (
    send_email_2fa_code,
    verify_email_code,
    verify_totp_code,
)
from .limiter import check_attempts, register_failed_attempt, reset_attempts
from app.models.users import User

router = APIRouter(prefix="/twofa", tags=["2FA"])


# ======================================================
# 🔍 ESTADO ACTUAL DE 2FA
# ======================================================
@router.get("/status")
def twofa_status(
    current_user: User = Depends(get_current_user)
):
    return {
        "is_enabled": current_user.is_2fa_enabled,
        "has_totp": current_user.totp_secret is not None,
        "email": current_user.email
    }


# ======================================================
# 🔐 GENERAR SECRETO TOTP
# ======================================================
@router.post("/generate-secret")
def generate_secret(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Si ya existe un secreto y 2FA está activo, evitar regeneración
    if current_user.totp_secret and current_user.is_2fa_enabled:
        raise HTTPException(400, "2FA activo. Primero debes desactivar antes de regenerar el secreto.")

    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    db.commit()

    return {"secret": secret}


# ======================================================
# 🔳 GENERAR QR PARA AUTHENTICATOR (PARA FRONT)
# ======================================================
@router.get("/qr")
def get_qr(secret: str):
    uri = pyotp.TOTP(secret).provisioning_uri(
        name="VULNPORTS",
        issuer_name="VULNPORTS"
    )

    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, "PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")



# ======================================================
# ✉️ ENVIAR CÓDIGO POR EMAIL
# ======================================================
@router.post("/email/send")
def twofa_email_send(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    send_email_2fa_code(current_user, db)
    return {"message": "Código enviado al correo."}


# ======================================================
# 📝 VALIDAR 2FA DURANTE SETUP (ACTIVA 2FA)
# ======================================================
@router.post("/verify")
def verify_twofa(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    method = payload.get("method")
    code = payload.get("code")

    if not method or not code:
        raise HTTPException(400, "Debe enviar método y código.")

    check_attempts(current_user)

    valid = (
        verify_email_code(current_user, code)
        if method == "email" else
        verify_totp_code(current_user, code)
    )

    if not valid:
        register_failed_attempt(current_user, db)
        raise HTTPException(401, "Código incorrecto.")

    reset_attempts(current_user, db)

    current_user.is_2fa_enabled = True
    db.commit()

    return {"message": "2FA activado correctamente."}


# ======================================================
# ❌ DESACTIVAR 2FA
# ======================================================
@router.post("/disable")
def disable_twofa(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    code = payload.get("code")

    if not current_user.is_2fa_enabled:
        raise HTTPException(400, "El 2FA no está activado.")

    if not code:
        raise HTTPException(400, "Debe enviar código de verificación.")

    valid = (
        verify_email_code(current_user, code)
        or verify_totp_code(current_user, code)
    )

    if not valid:
        raise HTTPException(401, "Código inválido.")

    current_user.is_2fa_enabled = False
    db.commit()

    return {"message": "2FA desactivado correctamente."}


# ======================================================
# 🔄 REGENERAR SECRETO
# ======================================================
@router.post("/regenerate-secret")
def regenerate_secret(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    code = payload.get("code")

    if not current_user.is_2fa_enabled:
        raise HTTPException(400, "Debes tener 2FA habilitado para regenerar el secreto.")

    if not code:
        raise HTTPException(400, "Debe enviar código de verificación.")

    valid = (
        verify_email_code(current_user, code)
        or verify_totp_code(current_user, code)
    )

    if not valid:
        raise HTTPException(401, "Código incorrecto.")

    new_secret = pyotp.random_base32()
    current_user.totp_secret = new_secret
    db.commit()

    return {"message": "Secreto regenerado.", "secret": new_secret}


# ======================================================
# 👁 VALIDACIÓN EN TIEMPO REAL (para el frontend)
# ======================================================
@router.post("/check")
def check_2fa_code(payload: dict, db: Session = Depends(get_db)):
    user_id = payload.get("user_id")
    method = payload.get("method")
    code = payload.get("code")

    if not user_id or not method or not code:
        raise HTTPException(400, "Datos incompletos")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    # Validación SIN activar 2FA ni generar tokens
    if method == "totp":
        valid = verify_totp_code(user, code)
    elif method == "email":
        valid = verify_email_code(user, code)
    else:
        raise HTTPException(400, "Método inválido")

    return {"valid": valid}


