from datetime import datetime
from sqlalchemy import Column, BigInteger, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class Host(Base):
    __tablename__ = "hosts"

    id = Column(BigInteger, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    os_detected = Column(String(100), nullable=True)

    total_ports = Column(Integer, default=0)
    high_risk_count = Column(Integer, default=0)

    # Nuevo: ID del usuario dueño del escaneo
    user_id = Column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # RELACIONES
    ports = relationship(
        "Port",
        back_populates="host",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    risk_assessments = relationship(
        "RiskAssessment",
        back_populates="host",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # Relación opcional hacia usuarios
    user = relationship("User", back_populates="hosts")

