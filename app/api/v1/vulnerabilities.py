from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.vulnerabilities import Vulnerability
from app.schemas.vulnerabilities import VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityOut

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

# Endpoints de las vulnerabilidades
@router.post("/", response_model=VulnerabilityOut)
def create_vuln(data: VulnerabilityCreate, db: Session = Depends(get_db)):
    vuln = Vulnerability(**data.dict())
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


@router.get("/", response_model=list[VulnerabilityOut])
def list_vulns(db: Session = Depends(get_db)):
    return db.query(Vulnerability).all()


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
def get_vuln(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerabilidad no encontrada")
    return vuln


@router.put("/{vuln_id}", response_model=VulnerabilityOut)
def update_vuln(vuln_id: int, data: VulnerabilityUpdate, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerabilidad no encontrada")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(vuln, k, v)

    db.commit()
    db.refresh(vuln)
    return vuln


@router.delete("/{vuln_id}")
def delete_vuln(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerabilidad no encontrada")

    db.delete(vuln)
    db.commit()
    return {"message": "Vulnerabilidad eliminada"}
