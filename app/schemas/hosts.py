from datetime import datetime, date
from typing import List, Optional

from pydantic import BaseModel, Field


# ============================================================
# 🔹 Vulnerability Mini (para puertos y hosts)
# ============================================================
class VulnerabilityMini(BaseModel):
    id: int
    cve_id: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None

    model_config = {"from_attributes": True}


# ============================================================
# 🔹 PORT OUT (con vulnerabilidades anidadas)
# ============================================================
class PortOut(BaseModel):
    id: int
    port_number: int
    protocol: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    status: str
    scanned_at: datetime

    # Vulnerabilidades del puerto
    vulnerabilities: List[VulnerabilityMini] = []

    model_config = {"from_attributes": True}


# ============================================================
# 🔹 RISK OUT (si ya lo tienes definido)
# ============================================================
class RiskOut(BaseModel):
    id: int
    score: Optional[float] = Field(alias="overall_risk_score")
    level: Optional[str] = Field(alias="risk_level")
    evaluated_at: datetime
    model_version: Optional[str] = None

    model_config = {
        "from_attributes": True,
        "populate_by_name": True
    }


# ============================================================
# 🔹 HOST BASE
# ============================================================
class HostBase(BaseModel):
    ip_address: str = Field(..., max_length=45)
    hostname: Optional[str] = None
    os_detected: Optional[str] = None


# ============================================================
# 🔹 HOST CREATE
# ============================================================
class HostCreate(HostBase):
    user_id: int


# ============================================================
# 🔹 HOST UPDATE
# ============================================================
class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    total_ports: Optional[int] = None
    high_risk_count: Optional[int] = None


# ============================================================
# 🔹 HOST OUT (lista)
# ============================================================
class HostOut(HostBase):
    id: int
    scan_date: datetime
    total_ports: int
    high_risk_count: int
    user_id: int

    model_config = {"from_attributes": True}


# ============================================================
# 🔥 HOST DETALLADO (TODO LO QUE NECESITA EL FRONTEND)
# ============================================================
class HostDetailOut(HostOut):
    # Puertos con vulnerabilidades anidadas
    ports: List[PortOut] = []

    # Evaluaciones de riesgo
    risk_assessments: List[RiskOut] = []

    # Vulnerabilidades agregadas del host (secundaria)
    vulnerabilities: List[VulnerabilityMini] = []

    model_config = {"from_attributes": True}

