from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_current_user
from app.database import get_db
from app.models.hosts import Host
from app.models.users import User
from app.models.ports import Port
from app.models.vulnerabilities import Vulnerability
from app.schemas.hosts import HostCreate, HostOut, HostUpdate, HostDetailOut

router = APIRouter(prefix="/hosts", tags=["Hosts"])


# ============================================================
# CREAR HOST
# ============================================================
@router.post("/", response_model=HostOut)
def create_host(
    data: HostCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Crea un host asignado al usuario autenticado.
    """
    if db.query(Host).filter(
        Host.ip_address == data.ip_address,
        Host.user_id == user.id
    ).first():
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


# ============================================================
# LISTAR TODOS LOS HOSTS (solo admins)
# ============================================================
@router.get("/", response_model=list[HostOut])
def list_hosts(db: Session = Depends(get_db)):
    return db.query(Host).all()


# ============================================================
# LISTAR MIS HOSTS (DETALLADO)
# ============================================================
@router.get("/me", response_model=list[HostDetailOut])
def list_my_hosts(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Devuelve los hosts del usuario actual con:
    - Puertos
    - Vulnerabilidades por puerto
    - Vulnerabilidades agregadas
    - Evaluaciones de riesgo
    """
    hosts = (
        db.query(Host)
        .options(
            selectinload(Host.ports).options(
                selectinload(Port.vulnerabilities)
            ),
            selectinload(Host.vulnerabilities),
            selectinload(Host.risk_assessments)
        )
        .filter(Host.user_id == user.id)
        .all()
    )

    return hosts


# ============================================================
# OBTENER HOST DETALLADO /hosts/{id}
# ============================================================
@router.get("/{host_id}", response_model=HostDetailOut)
def get_host(
    host_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    host = (
        db.query(Host)
        .options(
            selectinload(Host.ports).options(
                selectinload(Port.vulnerabilities)
            ),
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

    return host


# ============================================================
# ACTUALIZAR HOST
# ============================================================
@router.put("/{host_id}", response_model=HostOut)
def update_host(
    host_id: int,
    data: HostUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    host = db.query(Host).filter(Host.id == host_id).first()

    if not host:
        raise HTTPException(404, "Host no encontrado")

    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(host, k, v)

    db.commit()
    db.refresh(host)
    return host


# ============================================================
# ELIMINAR HOST
# ============================================================
@router.delete("/{host_id}")
def delete_host(
    host_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = db.query(Host).filter(Host.id == host_id).first()

    if not host:
        raise HTTPException(404, "Host no encontrado")

    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    db.delete(host)
    db.commit()

    return {"message": "Host eliminado"}


