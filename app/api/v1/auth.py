from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.security import create_access_token, verify_password
from app.database import get_db
from app.models.users import User

router = APIRouter(prefix="/auth", tags=["Auth"])


# EndPoint de autenticacion
@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()

    if not user:
        raise HTTPException(400, "Credenciales inválidas")

    if not verify_password(form.password, user.password_hash):
        raise HTTPException(400, "Credenciales inválidas")

    token = create_access_token({"sub": user.username})

    return {"access_token": token, "token_type": "bearer"}
