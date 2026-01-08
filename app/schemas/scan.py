from typing import Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    ip: str = Field(..., description="Dirección IP a escanear")
    ports: Optional[str] = Field(
        None, description="Ejemplo: '22,80,443' o '1-1024'"
    )


class RangeScanRequest(BaseModel):
    network: str = Field(..., description="CIDR Ej: 192.168.1.0/24")
    ports: Optional[str] = Field(
        None, description="Ejemplo: '22,80' o '1-1024'"
    )


class ScanStatusMessage(BaseModel):
    type: str = Field(..., description="'status' | 'progress' | 'result' | 'error'")
    message: Optional[str] = None
    current_ip: Optional[str] = None
    progress: Optional[float] = Field(None, ge=0, le=100)
    host_id: Optional[int] = None
    result: Optional[dict] = None

