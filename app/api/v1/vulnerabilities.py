from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.hosts import Host
from app.models.ports import Port
from app.models.users import User
from app.models.vulnerabilities import Vulnerability
from app.schemas.vulnerabilities import VulnerabilityCreate, VulnerabilityOut, VulnerabilityUpdate

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

# 1) CREAR VULNERABILIDAD (solo si el puerto pertenece al usuario)
@router.post("/", response_model=VulnerabilityOut)
def create_vuln(
    data: VulnerabilityCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    # Obtener puerto
    port = db.query(Port).filter(Port.id == data.port_id).first()
    if not port:
        raise HTTPException(404, "El puerto no existe")

    # Verificar que el puerto sea del usuario
    if port.host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    vuln = Vulnerability(**data.dict())
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


# 2) LISTAR SOLO LAS VULNERABILIDADES DEL USUARIO
@router.get("/", response_model=list[VulnerabilityOut])
def list_vulns(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Devuelve SOLO las vulnerabilidades asociadas a hosts del usuario actual.
    """
    vulns = (
        db.query(Vulnerability)
        .join(Port, Vulnerability.port_id == Port.id)
        .join(Host, Port.host_id == Host.id)
        .filter(Host.user_id == user.id)
        .all()
    )

    return vulns


# 3) OBTENER VULNERABILIDAD POR ID (solo si pertenece al usuario)
@router.get("/{vuln_id}", response_model=VulnerabilityOut)
def get_vuln(
    vuln_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vuln = (
        db.query(Vulnerability)
        .join(Port)
        .join(Host)
        .filter(Vulnerability.id == vuln_id, Host.user_id == user.id)
        .first()
    )

    if not vuln:
        raise HTTPException(404, "Vulnerabilidad no encontrada o no autorizada")

    return vuln


# 4) ACTUALIZAR vulnerabilidad (solo si pertenece al usuario)
@router.put("/{vuln_id}", response_model=VulnerabilityOut)
def update_vuln(
    vuln_id: int,
    data: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vuln = (
        db.query(Vulnerability)
        .join(Port)
        .join(Host)
        .filter(Vulnerability.id == vuln_id, Host.user_id == user.id)
        .first()
    )

    if not vuln:
        raise HTTPException(404, "Vulnerabilidad no encontrada o no autorizada")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(vuln, k, v)

    db.commit()
    db.refresh(vuln)
    return vuln


# 5) ELIMINAR vulnerabilidad (solo si pertenece al usuario)
@router.delete("/{vuln_id}")
def delete_vuln(
    vuln_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    vuln = (
        db.query(Vulnerability)
        .join(Port)
        .join(Host)
        .filter(Vulnerability.id == vuln_id, Host.user_id == user.id)
        .first()
    )

    if not vuln:
        raise HTTPException(404, "Vulnerabilidad no encontrada o no autorizada")

    db.delete(vuln)
    db.commit()

    return {"message": "Vulnerabilidad eliminada"}

