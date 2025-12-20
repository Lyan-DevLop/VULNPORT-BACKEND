from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class HostSummaryOut(BaseModel):
    id: int
    ip_address: str
    total_ports: int
    total_vulns: int
    risk_level: Optional[str] = "N/A"
    risk_score: Optional[float] = 0.0
    scan_date: datetime

    model_config = {"from_attributes": True}
