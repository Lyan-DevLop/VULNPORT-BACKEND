from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from .ports import PortOut as PortDetailOut
from .risk import RiskOut
from .vulnerabilities import VulnerabilityMini


# HOST BASE=
class HostBase(BaseModel):
    ip_address: str = Field(..., max_length=45)
    hostname: Optional[str] = None
    os_detected: Optional[str] = None

    # Relación con agente remoto
    agent_id: Optional[str] = None

# HOST CREATE
class HostCreate(HostBase):
    user_id: int

# HOST UPDATE
class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    total_ports: Optional[int] = None
    high_risk_count: Optional[int] = None
    agent_id: Optional[str] = None

# HOST OUT (básico)
class HostOut(HostBase):
    id: int
    scan_date: datetime
    total_ports: int
    high_risk_count: int
    user_id: int

    model_config = {"from_attributes": True}

# HOST DETALLADO (con puertos, riesgos, vulns y AGENTE)
class HostDetailOut(HostOut):
    ports: List[PortDetailOut] = []
    risk_assessments: List[RiskOut] = []
    vulnerabilities: List[VulnerabilityMini] = []
    agent_id: Optional[str] = None

    agent: Optional[dict] = None

    model_config = {"from_attributes": True}

# HOST SUMMARY
class HostSummaryOut(BaseModel):
    id: int
    ip_address: str
    total_ports: int
    total_vulns: int
    risk_level: Optional[str] = "N/A"
    risk_score: Optional[float] = 0.0
    scan_date: datetime

    model_config = {"from_attributes": True}
