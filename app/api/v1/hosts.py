from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.hosts import Host
from app.models.users import User
from app.schemas.hosts import HostCreate, HostOut, HostUpdate

router = APIRouter(prefix="/hosts", tags=["Hosts"])


@router.post("/", response_model=HostOut)
def create_host(
    data: HostCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Crea un host asignado al usuario autenticado.
    """
    if db.query(Host).filter(Host.ip_address == data.ip_address, Host.user_id == user.id).first():
        raise HTTPException(400, "El host ya existe para este usuario")

    host = Host(**data.dict(), user_id=user.id)
    db.add(host)
    db.commit()
    db.refresh(host)
    return host


@router.get("/", response_model=list[HostOut])
def list_hosts(db: Session = Depends(get_db)):
    """
    Devuelve TODOS los hosts de la BD.
    (Para administradores o propósitos internos)
    """
    return db.query(Host).all()


@router.get("/me", response_model=list[HostOut])
def list_my_hosts(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Devuelve solo los hosts escaneados por el usuario autenticado.
    """
    return db.query(Host).filter(Host.user_id == user.id).all()


@router.get("/{host_id}", response_model=HostOut)
def get_host(
    host_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    host = db.query(Host).filter(Host.id == host_id).first()

    if not host:
        raise HTTPException(404, "Host no encontrado")

    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    return host


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

