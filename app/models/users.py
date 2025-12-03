from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, String, Boolean, Integer
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user")  # admin / user
    created_at = Column(DateTime, default=datetime.utcnow)

    # ======================
    # 🔐 CAMPOS 2FA
    # ======================

    is_2fa_enabled = Column(Boolean, default=False)       # ¿2FA activo?
    totp_secret = Column(String(255), nullable=True)      # Authy / Google Authenticator

    # Códigos por correo
    email_2fa_code = Column(String(6), nullable=True)
    email_2fa_expiration = Column(DateTime, nullable=True)

    # Control de intentos
    two_fa_attempts = Column(Integer, default=0)
    two_fa_locked_until = Column(DateTime, nullable=True)

    # Relación inversa (no tocar)
    hosts = relationship(
        "Host",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
