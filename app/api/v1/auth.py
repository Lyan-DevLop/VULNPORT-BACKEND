from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.security import create_access_token, verify_password, hash_password
from app.core.settings import get_settings
from app.database import get_db
from app.models.users import User
from app.api.deps import get_current_user

# 2FA servicios
from app.api.v1.twofa.service_2fa import (
    verify_email_code,
    verify_totp_code,
    send_email_2fa_code,
)
from app.api.v1.twofa.limiter import (
    check_attempts,
    register_failed_attempt,
    reset_attempts,
)

router = APIRouter(prefix="/auth", tags=["Auth"])

ACCESS_TOKEN_EXPIRE_MIN = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30
settings = get_settings()


# ===========================================================
# 🔐 LOGIN (FASE 1)
# ===========================================================
@router.post("/login")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(User.username == form.username).first()

    if not user:
        raise HTTPException(400, "Credenciales inválidas")

    if not verify_password(form.password, user.password_hash):
        raise HTTPException(400, "Credenciales inválidas")

    # 2FA activado → se requiere fase 2
    if user.is_2fa_enabled:
        return {
            "needs_2fa": True,
            "user_id": user.id,
            "methods": ["email", "totp"],
            "message": "Ingrese código de verificación"
        }

    # Login normal
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
    )

    refresh_token = create_access_token(
        data={"sub": str(user.id), "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": user.id
    }


# ===========================================================
# ✉️ ENVIAR CÓDIGO 2FA DURANTE EL LOGIN (usuario NO logueado)
# ===========================================================
@router.post("/login/email/send")
def send_login_email_code(payload: dict, db: Session = Depends(get_db)):
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(400, "Debe enviar user_id.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado.")

    # Validar intentos en email login
    check_attempts(user)

    # Generar y enviar código
    from app.api.v1.twofa.service_2fa import send_email_2fa_code
    send_email_2fa_code(user, db)

    return {"message": "Código enviado al correo del usuario."}



# ===========================================================
# 🔑 LOGIN 2FA (FASE 2)
# ===========================================================
@router.post("/login/2fa")
def login_2fa(payload: dict, db: Session = Depends(get_db)):

    user_id = payload.get("user_id")
    method = payload.get("method")
    code = payload.get("code")

    if not user_id or not method or not code:
        raise HTTPException(400, "Datos incompletos")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    # Intentos solo aplican para email (no para totp)
    if method == "email":
        check_attempts(user)

    # Validación
    if method == "email":
        valid = verify_email_code(user, code)
    elif method == "totp":
        valid = verify_totp_code(user, code)
    else:
        raise HTTPException(400, "Método inválido")

    if not valid:
        if method == "email":
            register_failed_attempt(user, db)
        raise HTTPException(400, "Código incorrecto")

    if method == "email":
        reset_attempts(user, db)

    # Generar tokens tras login exitoso
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
    )

    refresh_token = create_access_token(
        data={"sub": str(user.id), "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": user.id
    }


# ===========================================================
# 🔄 REFRESH TOKEN
# ===========================================================
@router.post("/refresh")
def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(
            refresh_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        if payload.get("type") != "refresh":
            raise HTTPException(401, "Token inválido")

        user_id = int(payload.get("sub"))

    except Exception:
        raise HTTPException(401, "Token inválido o expirado")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(401, "Usuario no encontrado")

    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# ===========================================================
# 🔒 CAMBIO DE CONTRASEÑA CON 2FA
# ===========================================================
class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    twofa_code: str
    method: str = "email"  # email | totp


@router.post("/change-password")
def change_password(
    data: PasswordChangeRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    # 1️⃣ Validar contraseña actual
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(400, "La contraseña actual es incorrecta")

    # 2️⃣ Intentos fallidos (solo email)
    check_attempts(user)

    # 3️⃣ Validar 2FA
    if data.method == "email":
        valid = verify_email_code(user, data.twofa_code)
    elif data.method == "totp":
        valid = verify_totp_code(user, data.twofa_code)
    else:
        raise HTTPException(400, "Método inválido")

    if not valid:
        register_failed_attempt(user, db)
        raise HTTPException(400, "Código 2FA incorrecto")

    reset_attempts(user, db)

    # 4️⃣ Cambiar contraseña
    user.password_hash = hash_password(data.new_password)
    db.commit()

    return {"message": "Contraseña actualizada correctamente"}


# ===========================================================
# 🔍 VALIDACIÓN REALTIME (Para frontend)
# ===========================================================
@router.post("/check-2fa")
def check_2fa(payload: dict, db: Session = Depends(get_db)):

    user_id = payload.get("user_id")
    method = payload.get("method")
    code = payload.get("code")

    if not user_id or not method or not code:
        raise HTTPException(400, "Datos incompletos")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    # Validación simple sin activar login
    if method == "email":
        valid = verify_email_code(user, code)
    elif method == "totp":
        valid = verify_totp_code(user, code)
    else:
        raise HTTPException(400, "Método inválido")

    return {"valid": valid}

