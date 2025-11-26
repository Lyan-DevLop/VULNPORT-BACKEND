from datetime import datetime, timedelta

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.users import User

from .settings import get_settings

settings = get_settings()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

#  DEFINIR ESQUEMA OAUTH2 — NECESARIO PARA DEPENDENCIAS
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# Hash a la contraseña
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


# Creo el JWT
def create_access_token(data: dict, expires_minutes: int | None = None):
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(minutes=expires_minutes or settings.JWT_EXPIRES_MINUTES)
    to_encode.update({"exp": expire})

    encoded = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded


# Tomar el usuario actual (logueado)
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        username: str = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")

    return user
