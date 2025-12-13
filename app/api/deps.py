from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.logger import get_logger
from app.core.settings import get_settings
from app.database import get_db
from app.models.users import User

settings = get_settings()
log = get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas o token expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decodifica JWT correctamente
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        sub = payload.get("sub")
        if sub is None:
            raise credentials_exception

        user_id = int(sub)

    except (JWTError, ValueError):
        raise credentials_exception

    # Busca al usuario por ID
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise credentials_exception

    return user


# SOLO ADMIN
def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permisos para realizar esta acción",
        )
    return current_user


# Cualquier usuario autenticado
def require_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user

