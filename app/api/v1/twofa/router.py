from io import BytesIO
from typing import Optional

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.users import User

from .limiter import check_attempts, register_failed_attempt, reset_attempts
from .service_2fa import (
    send_email_2fa_code,
    verify_email_code,
    verify_totp_code,
)

router = APIRouter(prefix="/twofa", tags=["2FA"])

# ESTADO ACTUAL DE 2FA
@router.get("/status")
def twofa_status(current_user: User = Depends(get_current_user)):
    return {
        "is_enabled": current_user.is_2fa_enabled,
        "has_totp": current_user.totp_secret is not None,
        "email": current_user.email,
    }

# GENERAR SECRETO TOTP (para app Authenticator)
@router.post("/generate-secret")
def generate_secret(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.totp_secret and current_user.is_2fa_enabled:
        raise HTTPException(
            400,
            "2FA activo. Primero debes desactivar antes de regenerar el secreto."
        )

    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    db.commit()

    return {"secret": secret}

# GENERAR QR PARA AUTHENTICATOR
@router.get("/qr")
def get_qr(
    request: Request,
    secret: Optional[str] = None,
    db: Session = Depends(get_db)
):
    # Leer token desde query ?token=xxxx
    token = request.query_params.get("token")

    if not token:
        raise HTTPException(401, "Token requerido.")

    # Obtener usuario desde token manualmente
    try:
        current_user = get_current_user(token, db)
    except Exception:
        raise HTTPException(401, "Token inválido.")

    # Usar el secreto apropiado
    secret_to_use = secret or current_user.totp_secret
    if not secret_to_use:
        raise HTTPException(400, "No hay secreto TOTP registrado.")

    label = f"{current_user.username} ({current_user.email})"

    uri = pyotp.TOTP(secret_to_use).provisioning_uri(
        name=label,
        issuer_name="VULNPORTS"
    )

    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, "PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")

# ENVIAR CÓDIGO POR EMAIL (SETUP)
@router.post("/email/send")
def twofa_email_send(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ok = send_email_2fa_code(current_user, db)
    if not ok:
        raise HTTPException(500, "No se pudo enviar el correo 2FA.")
    return {"message": "Código enviado al correo."}

# ACTIVAR 2FA
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

    if method == "email":
        valid = verify_email_code(current_user, code)
    elif method == "totp":
        valid = verify_totp_code(current_user, code)
    else:
        raise HTTPException(400, "Método inválido.")

    if not valid:
        register_failed_attempt(current_user, db)
        raise HTTPException(401, "Código incorrecto.")

    reset_attempts(current_user, db)

    current_user.is_2fa_enabled = True
    db.commit()

    return {"message": "2FA activado correctamente."}


# DESACTIVAR 2FA
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
        raise HTTPException(400, "Debe enviar código.")

    valid = verify_email_code(current_user, code) or verify_totp_code(current_user, code)

    if not valid:
        raise HTTPException(401, "Código inválido.")

    current_user.is_2fa_enabled = False
    db.commit()

    return {"message": "2FA desactivado correctamente."}
