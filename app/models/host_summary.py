from sqlalchemy import BigInteger, Column, DateTime, Integer, Numeric, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class HostSummary(Base):
    __tablename__ = "host_summary"
    __table_args__ = {"info": {"is_view": True}}

    id = Column(BigInteger, primary_key=True)
    ip_address = Column(String(45))
    total_ports = Column(Integer)
    total_vulns = Column(Integer)
    risk_level = Column(String(20))  # LOW, MEDIUM, HIGH, CRITICAL o 'N/A'
    risk_score = Column(Numeric(4, 2))
    scan_date = Column(DateTime)
