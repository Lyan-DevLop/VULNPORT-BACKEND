from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field

from app.schemas.hosts import HostOut   # <-- ahora sí, relación correcta


# Base
class UserBase(BaseModel):
    username: str = Field(..., max_length=50)
    email: EmailStr


# Crear Usuario
class UserCreate(UserBase):
    password: str = Field(..., min_length=6)


# Actualizar usuario
class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=6)


# Salida Basica
class UserOut(UserBase):
    id: int
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


# Salida extendida (para historial)
class UserWithHosts(UserOut):
    """
    Incluye los hosts asociados al usuario.
    Lo usarás para:
    - /me/history
    - /reports/history
    - vistas de historial en el dashboard
    """
    hosts: List[HostOut] = []  # se llena automáticamente vía ORM

    model_config = {"from_attributes": True}


