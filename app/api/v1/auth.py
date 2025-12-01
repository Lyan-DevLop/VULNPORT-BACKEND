from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from sqlalchemy.orm import Session

from app.core.security import create_access_token, verify_password
from app.core.settings import get_settings
from app.database import get_db
from app.models.users import User

router = APIRouter(prefix="/auth", tags=["Auth"])

# Tiempo de expiración
ACCESS_TOKEN_EXPIRE_MIN = 15           # 15 minutos para el access token
REFRESH_TOKEN_EXPIRE_DAYS = 30          # 30 días para el refresh token


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

    # Access Token
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
    )

    # Refresh Token
    refresh_token = create_access_token(
        data={"sub": str(user.id), "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

settings = get_settings()
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



