from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ports import Port
from app.schemas.ports import PortCreate, PortUpdate, PortOut

router = APIRouter(prefix="/ports", tags=["Ports"])

# Endpoints de los puertos
@router.post("/", response_model=PortOut)
def create_port(data: PortCreate, db: Session = Depends(get_db)):
    port = Port(**data.dict())
    db.add(port)
    db.commit()
    db.refresh(port)
    return port


@router.get("/", response_model=list[PortOut])
def list_ports(db: Session = Depends(get_db)):
    return db.query(Port).all()


@router.get("/{port_id}", response_model=PortOut)
def get_port(port_id: int, db: Session = Depends(get_db)):
    port = db.query(Port).filter(Port.id == port_id).first()
    if not port:
        raise HTTPException(404, "Puerto no encontrado")
    return port


@router.put("/{port_id}", response_model=PortOut)
def update_port(port_id: int, data: PortUpdate, db: Session = Depends(get_db)):
    port = db.query(Port).filter(Port.id == port_id).first()
    if not port:
        raise HTTPException(404, "Puerto no encontrado")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(port, k, v)

    db.commit()
    db.refresh(port)
    return port


@router.delete("/{port_id}")
def delete_port(port_id: int, db: Session = Depends(get_db)):
    port = db.query(Port).filter(Port.id == port_id).first()
    if not port:
        raise HTTPException(404, "Puerto no encontrado")

    db.delete(port)
    db.commit()
    return {"message": "Puerto eliminado"}
