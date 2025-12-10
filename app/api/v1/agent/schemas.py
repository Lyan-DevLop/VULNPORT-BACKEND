from typing import List, Optional

from pydantic import BaseModel


class AgentRegister(BaseModel):
    agent_id: str
    hostname: str
    os_type: str


class PortInfo(BaseModel):
    port: int | str | None = None
    pid: int | str | None = None
    process_name: Optional[str] = None
    user: Optional[str] = None
    port_number: Optional[int] = None
    protocol: Optional[str] = None
    status: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None

    model_config = {"extra": "allow"}


class ReportIn(BaseModel):
    agent_id: str
    ip_address: str
    ports: List[dict]

    model_config = {"extra": "allow"}


class ConfirmCommand(BaseModel):
    command_id: int

