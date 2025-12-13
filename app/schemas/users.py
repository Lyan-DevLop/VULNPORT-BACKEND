from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field

from app.schemas.hosts import HostOut


class UserBase(BaseModel):
    username: str = Field(..., max_length=50)
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=6)


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=6)


class UserOut(UserBase):
    id: int
    role: str
    created_at: datetime
    is_2fa_enabled: bool

    model_config = {"from_attributes": True}


class UserWithHosts(UserOut):
    hosts: List[HostOut] = []

    model_config = {"from_attributes": True}


