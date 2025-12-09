from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from app.database import get_db
from app.models.hosts import Host
from app.api.deps import get_current_user
from .models import Agent, AgentReport, CommandQueue
from .schemas import AgentRegister, ReportIn, ConfirmCommand
from .security import validate_agent_id

router = APIRouter(prefix="/agent", tags=["Agent"])


# ============================================================
# LISTAR AGENTES DEL USUARIO AUTENTICADO
# ============================================================
@router.get("/list")
def get_agents(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    user_hosts = db.query(Host).filter(Host.user_id == current_user.id).all()
    agent_ids = {h.agent_id for h in user_hosts if h.agent_id}

    agents = db.query(Agent).filter(Agent.id.in_(agent_ids)).all()

    return [
        {
            "id": agent.id,
            "hostname": agent.hostname,
            "os_type": agent.os_type,
            "last_seen": agent.last_seen,
            "status": "ONLINE"
            if (datetime.utcnow() - agent.last_seen) < timedelta(seconds=30)
            else "OFFLINE"
        }
        for agent in agents
    ]


# ============================================================
# REGISTRAR AGENTE
# ============================================================
@router.post("/register")
def register(
    data: AgentRegister,
    db: Session = Depends(get_db)
):
    if not data.agent_id or data.agent_id.strip() == "":
        raise HTTPException(400, "agent_id cannot be empty")

    existing = db.query(Agent).filter(Agent.id == data.agent_id).first()

    if existing:
        existing.last_seen = datetime.utcnow()
        db.commit()
        return {"status": "already_registered", "api_key": existing.api_key}

    api_key = secrets.token_hex(32)

    agent = Agent(
        id=data.agent_id,
        hostname=data.hostname,
        os_type=data.os_type,
        api_key=api_key,
        last_seen=datetime.utcnow(),
    )

    db.add(agent)
    db.commit()

    return {"status": "registered", "api_key": api_key}


# ============================================================
# RECIBIR REPORTE DEL AGENTE (USA IP REAL DEL AGENTE)
# ============================================================
@router.post("/report")
async def report_debug(
    data: ReportIn,
    db: Session = Depends(get_db)
):
    real_ip = data.ip_address.strip()

    if not real_ip:
        raise HTTPException(400, "ip_address is required in report")

    # Buscar host por IP real
    host = db.query(Host).filter(Host.ip_address == real_ip).first()

    if not host:
        raise HTTPException(
            404,
            f"No hay un host registrado con la IP real {real_ip} para asociar el agente."
        )

    # Si ya hay otro agente, bloquear
    if host.agent_id and host.agent_id != data.agent_id:
        raise HTTPException(
            409,
            f"Este host ya está vinculado al agente '{host.agent_id}'."
        )

    # Si el host aún no está asignado → asignarlo ahora
    if not host.agent_id:
        host.agent_id = data.agent_id

    # Asegurar que el agente exista y actualizar last_seen
    agent = db.query(Agent).filter(Agent.id == data.agent_id).first()
    if not agent:
        api_key = secrets.token_hex(32)
        agent = Agent(
            id=data.agent_id,
            hostname=None,
            os_type="Unknown",
            api_key=api_key,
            last_seen=datetime.utcnow(),
        )
        db.add(agent)
    else:
        agent.last_seen = datetime.utcnow()

    # Normalizar puertos del reporte
    normalized_ports = []
    for item in data.ports:
        if isinstance(item, int):
            normalized_ports.append({"port": item})
        else:
            try:
                pi = item.dict()
            except AttributeError:
                pi = item  # ya es dict

            port_val = pi.get("port") or pi.get("port_number")
            if isinstance(port_val, str):
                try:
                    port_val = int(port_val)
                except ValueError:
                    port_val = None

            if not isinstance(port_val, int):
                continue

            entry = {"port": port_val}
            for k in (
                "pid",
                "process_name",
                "user",
                "protocol",
                "status",
                "service_name",
                "service_version",
            ):
                v = pi.get(k)
                if v is not None:
                    entry[k] = v

            normalized_ports.append(entry)

    # --------------------------------------------------------
    # 🔥 AQUÍ FALTABA GUARDAR ip_address EN AgentReport
    # --------------------------------------------------------
    report = AgentReport(
        agent_id=data.agent_id,
        ip_address=real_ip,          # <<--- ESTE CAMPO ES EL NUEVO
        ports=normalized_ports
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return {
        "status": "ok",
        "agent_id": data.agent_id,
        "reported_ip": real_ip,
        "host_id": host.id
    }


# ============================================================
# OBTENER ÚLTIMO REPORTE
# ============================================================
@router.get("/reports/{agent_id}")
def get_latest_report(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    owner = db.query(Host).filter(
        Host.agent_id == agent_id,
        Host.user_id == current_user.id
    ).first()

    if not owner:
        raise HTTPException(403, "Not allowed")

    rep = (
        db.query(AgentReport)
        .filter(AgentReport.agent_id == agent_id)
        .order_by(AgentReport.id.desc())
        .first()
    )

    if not rep:
        raise HTTPException(404, "No report found")

    return {"agent_id": agent_id, "ports": rep.ports}


# ============================================================
# AGREGAR COMANDO PARA CERRAR PUERTO
# ============================================================
@router.post("/command/close-port")
def add_close_port_command(
    agent_id: str,
    port: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    owner = db.query(Host).filter(
        Host.agent_id == agent_id,
        Host.user_id == current_user.id
    ).first()

    if not owner:
        raise HTTPException(403, "No tienes permiso para controlar este agente.")

    cmd = CommandQueue(
        agent_id=agent_id,
        action="close_port",
        port=port
    )

    db.add(cmd)
    db.commit()

    return {
        "status": "queued",
        "message": f"El puerto {port} fue enviado al agente {agent_id}."
    }


# ============================================================
# CONSULTAR COMANDOS PENDIENTES
# ============================================================
@router.get("/command/{agent_id}")
def get_command(
    agent_id: str,
    db: Session = Depends(get_db),
    agent=Depends(validate_agent_id)
):
    cmd = (
        db.query(CommandQueue)
        .filter(CommandQueue.agent_id == agent_id, CommandQueue.executed == False)
        .first()
    )

    if not cmd:
        return {}

    return {
        "command_id": cmd.id,
        "action": cmd.action,
        "port": cmd.port,
    }


# ============================================================
# CONFIRMAR COMANDO
# ============================================================
@router.post("/confirm")
def confirm(
    data: ConfirmCommand,
    db: Session = Depends(get_db),
    agent=Depends(validate_agent_id)
):
    cmd = db.query(CommandQueue).filter(CommandQueue.id == data.command_id).first()

    if not cmd:
        raise HTTPException(404, "Command not found")

    cmd.executed = True
    db.commit()

    return {"status": "confirmed"}

