# app/api/deps.py

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from app.database import get_db
from app.models.users import User
from app.core.settings import get_settings
from app.core.logger import get_logger

settings = get_settings()
log = get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# Dependencia de la BD
def get_db_dep():
    """
    Retorna una sesión de base de datos para usar en los endpoints.
    """
    db = get_db()
    try:
        yield db
    finally:
        db.close()


# Obtiene usuario mediante el token
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db_dep)
) -> User:
    """
    Extrae el usuario actual desde el token JWT.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )

        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise credentials_exception

    return user


# Verifica el rol de admin
def require_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Restricción de acceso solo para administradores.
    """

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permisos para realizar esta acción"
        )

    return current_user

# Verifica los roles (user - admin)
def require_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Usuarios normales o administradores tienen acceso.
    """
    return current_user
