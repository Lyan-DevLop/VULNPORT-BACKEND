from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# Base
class RiskBase(BaseModel):
    overall_risk_score: Optional[float] = Field(None, ge=0, le=100, description="Risk score 0-100")
    risk_level: Optional[str] = Field(None, description="LOW, MEDIUM, HIGH, CRITICAL")
    model_version: Optional[str] = None


# Crear riesgo
class RiskCreate(RiskBase):
    host_id: int


# Actualizar riesgo
class RiskUpdate(BaseModel):
    overall_risk_score: Optional[float] = Field(None, ge=0, le=100)
    risk_level: Optional[str] = None
    model_version: Optional[str] = None


# Respuesta
class RiskOut(RiskBase):
    id: int
    host_id: int
    evaluated_at: datetime

    model_config = {"from_attributes": True}
