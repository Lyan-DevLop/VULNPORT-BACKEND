from datetime import datetime
from sqlalchemy import Column, BigInteger, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("host_id", "port_number", "protocol", name="uq_host_port_protocol"),
    )

    id = Column(BigInteger, primary_key=True, index=True)
    host_id = Column(
        BigInteger,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)     # tcp / udp
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(100), nullable=True)
    status = Column(String(20), nullable=False)       # open / closed / filtered
    scanned_at = Column(DateTime, default=datetime.utcnow)

    # RELACIONES
    host = relationship("Host", back_populates="ports")

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="port",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
