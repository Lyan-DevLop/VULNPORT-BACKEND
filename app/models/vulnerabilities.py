from sqlalchemy import BigInteger, Column, Date, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(BigInteger, primary_key=True, index=True)
    port_id = Column(BigInteger, ForeignKey("ports.id", ondelete="CASCADE"), nullable=False, index=True)

    cve_id = Column(String(20), nullable=True)
    cvss_score = Column(Numeric(3, 1), nullable=True)
    severity = Column(String(20), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=True)
    published_date = Column(Date, nullable=True)
    source = Column(String(100), default="NVD")


    #   RELACIONES
    # Puerto al que pertenece la vulnerabilidad
    port = relationship(
        "Port",
        back_populates="vulnerabilities",
        lazy="joined"
    )

