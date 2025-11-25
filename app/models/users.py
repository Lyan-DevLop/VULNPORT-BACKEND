from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, String
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

    # 🔥 RELACIÓN INVERSA
    hosts = relationship("Host", back_populates="user", cascade="all, delete-orphan", passive_deletes=True)
