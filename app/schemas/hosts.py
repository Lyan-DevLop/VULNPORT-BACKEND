from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field

from .ports import PortOut
from .risk import RiskOut


# Base
class HostBase(BaseModel):
    ip_address: str = Field(..., max_length=45)
    hostname: Optional[str] = None
    os_detected: Optional[str] = None


# Crear Host
class HostCreate(HostBase):
    """
    Para creación:
    - user_id es necesario para relacionar el escaneo al usuario logueado
    """
    user_id: int


# Actualizar Host
class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    total_ports: Optional[int] = None
    high_risk_count: Optional[int] = None


# Respuesta (BD)
class HostOut(HostBase):
    id: int
    scan_date: datetime
    total_ports: int
    high_risk_count: int
    user_id: int 

    model_config = {"from_attributes": True}


# Respuesta completa
class HostDetailOut(HostOut):
    ports: List[PortOut] = []
    risk_assessments: List[RiskOut] = []

    model_config = {"from_attributes": True}


