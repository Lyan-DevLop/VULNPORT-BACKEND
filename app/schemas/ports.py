from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from .vulnerabilities import VulnerabilityOut


class PortBase(BaseModel):
    port_number: int = Field(..., ge=1, le=65535)
    protocol: str = Field(..., pattern="^(tcp|udp)$")
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    status: str = Field(..., pattern="^(open|closed|filtered|Unknown)$")


class PortCreate(PortBase):
    host_id: int


class PortUpdate(BaseModel):
    port_number: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, pattern="^(tcp|udp)$")
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(open|closed|filtered)$")


class PortOut(PortBase):
    id: int
    host_id: int
    scanned_at: datetime
    vulnerabilities: List[VulnerabilityOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}
