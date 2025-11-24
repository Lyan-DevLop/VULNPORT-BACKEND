from datetime import date
from typing import Optional
from pydantic import BaseModel, Field


# Base
class VulnerabilityBase(BaseModel):
    cve_id: Optional[str] = Field(None, max_length=20)
    cvss_score: Optional[float] = Field(
        None, ge=0, le=10, description="CVSS v3 Score (0.0 - 10.0)"
    )
    severity: Optional[str] = Field(
        None, description="LOW, MEDIUM, HIGH, CRITICAL"
    )
    description: Optional[str] = None
    published_date: Optional[date] = None
    source: str = Field(default="NVD", description="Source of vulnerability data")


# Crear Vulnerabilidad
class VulnerabilityCreate(VulnerabilityBase):
    port_id: int


# Actualizar Vulnerabilidad
class VulnerabilityUpdate(BaseModel):
    cve_id: Optional[str] = Field(None, max_length=20)
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    severity: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[date] = None
    source: Optional[str] = None


# Respuesta
class VulnerabilityOut(VulnerabilityBase):
    id: int
    port_id: int

    model_config = {"from_attributes": True}

