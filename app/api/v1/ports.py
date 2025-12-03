from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.hosts import Host
from app.models.ports import Port
from app.models.users import User
from app.schemas.ports import PortCreate, PortOut, PortUpdate

router = APIRouter(prefix="/ports", tags=["Ports"])


@router.post("/", response_model=PortOut)
def create_port(
    data: PortCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    # Verificar que el host existe
    host = db.query(Host).filter(Host.id == data.host_id).first()
    if not host:
        raise HTTPException(404, "El host no existe")

    # Verificar que el host sea del usuario
    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado para agregar puertos a este host")

    port = Port(**data.dict())
    db.add(port)
    db.commit()
    db.refresh(port)
    return port

@router.get("/", response_model=list[PortOut])
def list_ports(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Devuelve SOLO los puertos de los hosts del usuario actual.
    """
    return (
        db.query(Port)
        .join(Host, Port.host_id == Host.id)
        .filter(Host.user_id == user.id)
        .all()
    )


@router.get("/{port_id}", response_model=PortOut)
def get_port(
    port_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    port = (
        db.query(Port)
        .join(Host)
        .filter(Port.id == port_id, Host.user_id == user.id)
        .first()
    )

    if not port:
        raise HTTPException(404, "Puerto no encontrado o no autorizado")

    return port

@router.put("/{port_id}", response_model=PortOut)
def update_port(
    port_id: int,
    data: PortUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    port = (
        db.query(Port)
        .join(Host)
        .filter(Port.id == port_id, Host.user_id == user.id)
        .first()
    )

    if not port:
        raise HTTPException(404, "Puerto no encontrado o no autorizado")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(port, k, v)

    db.commit()
    db.refresh(port)
    return port

@router.delete("/{port_id}")
def delete_port(
    port_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    port = (
        db.query(Port)
        .join(Host)
        .filter(Port.id == port_id, Host.user_id == user.id)
        .first()
    )

    if not port:
        raise HTTPException(404, "Puerto no encontrado o no autorizado")

    db.delete(port)
    db.commit()

    return {"message": "Puerto eliminado"}

