from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.hosts import Host
from app.schemas.hosts import HostCreate, HostOut, HostUpdate

router = APIRouter(prefix="/hosts", tags=["Hosts"])


# Endpoints de los hosts
@router.post("/", response_model=HostOut)
def create_host(data: HostCreate, db: Session = Depends(get_db)):
    if db.query(Host).filter(Host.ip_address == data.ip_address).first():
        raise HTTPException(400, "El host ya existe")

    host = Host(**data.dict())
    db.add(host)
    db.commit()
    db.refresh(host)
    return host


@router.get("/", response_model=list[HostOut])
def list_hosts(db: Session = Depends(get_db)):
    return db.query(Host).all()


@router.get("/{host_id}", response_model=HostOut)
def get_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host no encontrado")
    return host


@router.put("/{host_id}", response_model=HostOut)
def update_host(host_id: int, data: HostUpdate, db: Session = Depends(get_db)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host no encontrado")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(host, k, v)

    db.commit()
    db.refresh(host)
    return host


@router.delete("/{host_id}")
def delete_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host no encontrado")

    db.delete(host)
    db.commit()
    return {"message": "Host eliminado"}
