from datetime import datetime
from sqlalchemy import Column, BigInteger, String, Numeric, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(BigInteger, primary_key=True, index=True)
    host_id = Column(
        BigInteger,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    overall_risk_score = Column(Numeric(4, 2), nullable=True)
    risk_level = Column(String(20), nullable=True)   # LOW, MEDIUM, HIGH, CRITICAL
    evaluated_at = Column(DateTime, default=datetime.utcnow)
    model_version = Column(String(20), nullable=True)

    # RELACIÓN
    host = relationship("Host", back_populates="risk_assessments")
