from datetime import date
from typing import Optional
from pydantic import BaseModel, Field


# ===========================
# HOST
# ===========================
class HostOut(BaseModel):
    id: int
    ip_address: str
    hostname: Optional[str] = None

    model_config = {"from_attributes": True}


# ===========================
# PORT
# ===========================
class PortOut(BaseModel):
    id: int
    port_number: int
    protocol: str
    service_name: Optional[str] = None
    host: Optional[HostOut] = None

    model_config = {"from_attributes": True}


# ===========================
# VULNERABILITY BASE
# ===========================
class VulnerabilityBase(BaseModel):
    cve_id: Optional[str] = Field(None, max_length=20)
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    severity: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[date] = None
    source: str = Field(default="NVD")


# ===========================
# CREATE
# ===========================
class VulnerabilityCreate(VulnerabilityBase):
    port_id: int


# ===========================
# UPDATE
# ===========================
class VulnerabilityUpdate(BaseModel):
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[date] = None
    source: Optional[str] = None


# ===========================
# OUTPUT
# ===========================
class VulnerabilityOut(VulnerabilityBase):
    id: int
    port_id: int
    port: Optional[PortOut] = None    # 👈🔥 RELACIÓN COMPLETA

    model_config = {"from_attributes": True}

