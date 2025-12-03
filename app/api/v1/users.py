from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import hash_password
from app.database import get_db
from app.models.users import User
from app.schemas.users import UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/users", tags=["Users"])


# ===========================================================
# 🧑 CREAR USUARIO
# ===========================================================
@router.post("/", response_model=UserOut)
def create_user(data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "El username ya existe")

    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "El email ya existe")

    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        is_2fa_enabled=False,
        totp_secret=None,
        email_2fa_code=None,
        email_2fa_expiration=None,
        two_fa_attempts=0,
        two_fa_locked_until=None
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ===========================================================
# 👤 OBTENER MI PERFIL
# ===========================================================
@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ===========================================================
# 🔧 ACTUALIZAR MI PERFIL
# ===========================================================
@router.put("/me", response_model=UserOut)
def update_me(
    data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    if data.username:
        if db.query(User).filter(User.username == data.username, User.id != current_user.id).first():
            raise HTTPException(400, "El username ya existe")
        current_user.username = data.username

    if data.email:
        if db.query(User).filter(User.email == data.email, User.id != current_user.id).first():
            raise HTTPException(400, "El email ya existe")
        current_user.email = data.email

    if data.password:
        current_user.password_hash = hash_password(data.password)

    db.commit()
    db.refresh(current_user)
    return current_user


# ===========================================================
# 👥 LISTAR TODOS LOS USUARIOS
# ===========================================================
@router.get("/", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()


# ===========================================================
# 🔎 OBTENER UN USUARIO POR ID
# ===========================================================
@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    return user


# ===========================================================
# 🛠️ ACTUALIZAR USUARIO POR ID
# ===========================================================
@router.put("/{user_id}", response_model=UserOut)
def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    user.username = data.username or user.username
    user.email = data.email or user.email

    if data.password:
        user.password_hash = hash_password(data.password)

    db.commit()
    db.refresh(user)
    return user


# ===========================================================
# ❌ ELIMINAR USUARIO
# ===========================================================
@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado con éxito"}
