from datetime import date
from typing import Optional

from pydantic import BaseModel, Field


# HOST LIGERO o BASICO
class HostLite(BaseModel):
    id: int
    ip_address: str
    hostname: Optional[str] = None

    model_config = {"from_attributes": True}

# PORT LIGERO PARA VULNS
class PortLite(BaseModel):
    id: int
    port_number: int
    protocol: str
    service_name: Optional[str] = None
    host: Optional[HostLite] = None

    model_config = {"from_attributes": True}

# VULNERABILITY BASE
class VulnerabilityBase(BaseModel):
    cve_id: Optional[str] = Field(None, max_length=20)
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    severity: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[date] = None
    source: str = Field(default="NVD")


class VulnerabilityCreate(VulnerabilityBase):
    port_id: int


class VulnerabilityUpdate(BaseModel):
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[date] = None
    source: Optional[str] = None


class VulnerabilityOut(VulnerabilityBase):
    id: int
    port_id: int
    port: Optional[PortLite] = None

    model_config = {"from_attributes": True}

# VERSIÓN MINI (para hosts / resúmenes / riesgos)
class VulnerabilityMini(BaseModel):
    id: int
    cve_id: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None

    model_config = {"from_attributes": True}


