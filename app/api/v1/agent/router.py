import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.logger import get_logger
from app.database import get_db
from app.models.hosts import Host
from app.services.scanner.worker import scan_worker

from .models import Agent, AgentReport, CommandQueue
from .schemas import AgentRegister, ConfirmCommand, ReportIn
from .security import validate_agent_id

log = get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["Agent"])

# RETENCIÓN: no saturar agent_reports
MAX_REPORTS_PER_AGENT = 20


@router.get("/list")
def get_agents(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
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
            else "OFFLINE",
        }
        for agent in agents
    ]


@router.post("/register")
def register(data: AgentRegister, db: Session = Depends(get_db)):
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


@router.post("/report")
async def report_debug(data: ReportIn, db: Session = Depends(get_db)):
    real_ip = data.ip_address.strip()
    if not real_ip:
        raise HTTPException(400, "ip_address is required in report")

    # Host debe existir (según tu lógica actual)
    host = db.query(Host).filter(Host.ip_address == real_ip).first()
    if not host:
        raise HTTPException(
            404,
            f"No hay un host registrado con la IP real {real_ip} para asociar el agente.",
        )

    # Si ya hay otro agente, bloquear
    if host.agent_id and host.agent_id != data.agent_id:
        raise HTTPException(409, f"Este host ya está vinculado al agente '{host.agent_id}'.")

    # Asignar agente al host si aún no está
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
            continue

        try:
            pi = item.dict()
        except AttributeError:
            pi = item

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

    # Guardar reporte crudo (histórico corto)
    report = AgentReport(agent_id=data.agent_id, ip_address=real_ip, ports=normalized_ports)
    db.add(report)

    #  Flujo completo: NVD + Risk + Persistencia + agente
    try:
        await scan_worker.process_agent_report(
            ip=real_ip,
            agent_ports=normalized_ports,
            db=db,
            user_id=host.user_id,
        )
    except Exception as e:
        # No se pierde el reporte si falla NVD o riesgo
        log.exception(f"Fallo procesando reporte de agente {data.agent_id} ({real_ip}): {e}")

    # Retención para no saturar agent_reports (mantine solo últimos reportes)
    try:
        old_ids = (
            db.query(AgentReport.id)
            .filter(AgentReport.agent_id == data.agent_id)
            .order_by(AgentReport.id.desc())
            .offset(MAX_REPORTS_PER_AGENT)
            .all()
        )
        old_ids = [x[0] for x in old_ids]
        if old_ids:
            db.query(AgentReport).filter(AgentReport.id.in_(old_ids)).delete(synchronize_session=False)
    except Exception as e:
        log.exception(f"No se pudo aplicar retención de reportes para {data.agent_id}: {e}")

    db.commit()
    db.refresh(report)

    return {
        "status": "ok",
        "agent_id": data.agent_id,
        "reported_ip": real_ip,
        "host_id": host.id,
        "report_id": report.id,
    }


@router.get("/reports/{agent_id}")
def get_latest_report(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    owner = db.query(Host).filter(Host.agent_id == agent_id, Host.user_id == current_user.id).first()
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


@router.post("/command/close-port")
def add_close_port_command(
    agent_id: str,
    port: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    owner = db.query(Host).filter(Host.agent_id == agent_id, Host.user_id == current_user.id).first()
    if not owner:
        raise HTTPException(403, "No tienes permiso para controlar este agente.")

    cmd = CommandQueue(agent_id=agent_id, action="close_port", port=port)
    db.add(cmd)
    db.commit()

    return {"status": "queued", "message": f"El puerto {port} fue enviado al agente {agent_id}."}


@router.get("/command/{agent_id}")
def get_command(agent_id: str, db: Session = Depends(get_db), agent=Depends(validate_agent_id)):
    cmd = (
        db.query(CommandQueue)
        .filter(CommandQueue.agent_id == agent_id, CommandQueue.executed.is_(False))
        .first()
    )

    if not cmd:
        return {}

    return {"command_id": cmd.id, "action": cmd.action, "port": cmd.port}


@router.post("/confirm")
def confirm(data: ConfirmCommand, db: Session = Depends(get_db), agent=Depends(validate_agent_id)):
    cmd = db.query(CommandQueue).filter(CommandQueue.id == data.command_id).first()
    if not cmd:
        raise HTTPException(404, "Command not found")

    cmd.executed = True

    # Si el comando fue close_port, se refleja en la tabla Port como (closed)
    if cmd.action == "close_port":
        host = db.query(Host).filter(Host.agent_id == cmd.agent_id).first()
        if host:
            try:
                scan_worker.apply_closed_ports(
                    db=db,
                    ip=host.ip_address,
                    closed_ports=[cmd.port],
                )
            except Exception as e:
                log.exception(f"Error aplicando cierre de puerto en BD (agent={cmd.agent_id}): {e}")

    db.commit()
    return {"status": "confirmed"}

