from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String
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

    user_id = Column(
        BigInteger,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ============================
    # RELACIONES
    # ============================

    # 1) Puertos asociados al host
    ports = relationship(
        "Port",
        back_populates="host",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",     # RÁPIDO para frontend
    )

    # 2) Evaluaciones de riesgo
    risk_assessments = relationship(
        "RiskAssessment",
        back_populates="host",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    # 3) Vulnerabilidades indirectas (a través de puertos)
    vulnerabilities = relationship(
        "Vulnerability",
        secondary="ports",
        primaryjoin="Host.id == Port.host_id",
        secondaryjoin="Port.id == Vulnerability.port_id",
        viewonly=True,
        lazy="selectin",
    )

    # 4) Propietario del host
    user = relationship("User", back_populates="hosts", lazy="joined")

