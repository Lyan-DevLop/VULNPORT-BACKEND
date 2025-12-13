from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_current_user
from app.api.v1.agent.models import Agent, CommandQueue
from app.database import get_db
from app.models.hosts import Host
from app.models.ports import Port
from app.models.users import User
from app.schemas.hosts import HostCreate, HostDetailOut, HostOut

router = APIRouter(prefix="/hosts", tags=["Hosts"])

# CREAR HOST
@router.post("/", response_model=HostOut)
def create_host(data: HostCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):

    exists = db.query(Host).filter(
        Host.ip_address == data.ip_address,
        Host.user_id == user.id
    ).first()

    if exists:
        raise HTTPException(400, "El host ya existe para este usuario")

    host = Host(
        ip_address=data.ip_address,
        hostname=data.hostname,
        os_detected=data.os_detected,
        user_id=user.id
    )

    db.add(host)
    db.commit()
    db.refresh(host)
    return host

# LISTAR MIS HOSTS DETALLADO (CON AGENTE)
@router.get("/me", response_model=list[HostDetailOut])
def list_my_hosts(db: Session = Depends(get_db), user: User = Depends(get_current_user)):

    hosts = (
        db.query(Host)
        .options(
            selectinload(Host.ports).options(selectinload(Port.vulnerabilities)),
            selectinload(Host.vulnerabilities),
            selectinload(Host.risk_assessments)
        )
        .filter(Host.user_id == user.id)
        .all()
    )

    enriched = []
    for h in hosts:
        agent_info = None

        if h.agent_id:
            agent = db.query(Agent).filter(Agent.id == h.agent_id).first()
            if agent:
                agent_info = {
                    "id": agent.id,
                    "hostname": agent.hostname,
                    "os_type": agent.os_type,
                    "last_seen": agent.last_seen,
                    "status": "ONLINE"
                    if (datetime.utcnow() - agent.last_seen) < timedelta(seconds=30)
                    else "OFFLINE"
                }

        enriched.append({**h.__dict__, "agent": agent_info})

    return enriched

# HOST DETALLADO
@router.get("/{host_id}", response_model=HostDetailOut)
def get_host(host_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):

    host = (
        db.query(Host)
        .options(
            selectinload(Host.ports).options(selectinload(Port.vulnerabilities)),
            selectinload(Host.vulnerabilities),
            selectinload(Host.risk_assessments)
        )
        .filter(Host.id == host_id)
        .first()
    )

    if not host:
        raise HTTPException(404, "Host no encontrado")

    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    agent_info = None

    if host.agent_id:
        agent = db.query(Agent).filter(Agent.id == host.agent_id).first()
        if agent:
            agent_info = {
                "id": agent.id,
                "hostname": agent.hostname,
                "os_type": agent.os_type,
                "last_seen": agent.last_seen,
                "status": "ONLINE"
                if (datetime.utcnow() - agent.last_seen) < timedelta(seconds=30)
                else "OFFLINE"
            }

    return {**host.__dict__, "agent": agent_info}

# ASIGNAR MANUALMENTE AGENTE
@router.put("/{host_id}/assign-agent")
def assign_agent(host_id: int, agent_id: Optional[str] = None, db: Session = Depends(get_db)):

    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")

    host.agent_id = agent_id
    db.commit()
    db.refresh(host)

    return {
        "message": "Agent assigned successfully" if agent_id else "Agent removed",
        "host_id": host_id,
        "agent_id": agent_id,
    }

# NUEVO — CERRAR PUERTO DESDE EL HOST
@router.post("/{host_id}/close-port")
def host_close_port(host_id: int, port: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):

    host = db.query(Host).filter(Host.id == host_id).first()

    if not host:
        raise HTTPException(404, "Host no encontrado")

    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    if not host.agent_id:
        raise HTTPException(400, "Este host no tiene agente asignado")

    cmd = CommandQueue(
        agent_id=host.agent_id,
        action="close_port",
        port=port
    )

    db.add(cmd)
    db.commit()

    return {
        "message": f"Comando para cerrar el puerto {port} enviado correctamente.",
        "agent_id": host.agent_id,
        "port": port
    }
