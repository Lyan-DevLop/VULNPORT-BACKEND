from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.risk import RiskAssessment
from app.schemas.risk import RiskCreate, RiskOut, RiskUpdate

router = APIRouter(prefix="/risk", tags=["Risk Assessments"])


# Endpoints de la red neural
@router.post("/", response_model=RiskOut)
def create_risk(data: RiskCreate, db: Session = Depends(get_db)):
    risk = RiskAssessment(**data.dict())
    db.add(risk)
    db.commit()
    db.refresh(risk)
    return risk


@router.get("/", response_model=list[RiskOut])
def list_risks(db: Session = Depends(get_db)):
    return db.query(RiskAssessment).all()


@router.get("/{risk_id}", response_model=RiskOut)
def get_risk(risk_id: int, db: Session = Depends(get_db)):
    risk = db.query(RiskAssessment).filter(RiskAssessment.id == risk_id).first()
    if not risk:
        raise HTTPException(404, "Evaluación no encontrada")
    return risk


@router.put("/{risk_id}", response_model=RiskOut)
def update_risk(risk_id: int, data: RiskUpdate, db: Session = Depends(get_db)):
    risk = db.query(RiskAssessment).filter(RiskAssessment.id == risk_id).first()
    if not risk:
        raise HTTPException(404, "Evaluación no encontrada")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(risk, k, v)

    db.commit()
    db.refresh(risk)
    return risk


@router.delete("/{risk_id}")
def delete_risk(risk_id: int, db: Session = Depends(get_db)):
    risk = db.query(RiskAssessment).filter(RiskAssessment.id == risk_id).first()
    if not risk:
        raise HTTPException(404, "Evaluación no encontrada")

    db.delete(risk)
    db.commit()
    return {"message": "Evaluación eliminada"}
