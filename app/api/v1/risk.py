from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.hosts import Host
from app.models.risk import RiskAssessment
from app.models.users import User
from app.schemas.risk import RiskCreate, RiskOut, RiskUpdate
from app.services.risk_model.neural_model import risk_model
from app.services.risk_model.risk_evaluator import risk_evaluator

router = APIRouter(prefix="/risk", tags=["Risk Assessments"])


@router.get("/", response_model=list[RiskOut])
def list_risks(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return (
        db.query(RiskAssessment)
        .join(Host)
        .filter(Host.user_id == user.id)
        .all()
    )

@router.post("/", response_model=RiskOut)
def create_risk(
    data: RiskCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = db.query(Host).filter(Host.id == data.host_id).first()
    if not host:
        raise HTTPException(404, "Host no encontrado")
    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    evaluation = risk_evaluator.evaluate(host, host.ports)

    risk = RiskAssessment(
        host_id=host.id,
        overall_risk_score=evaluation["overall_risk_score"],
        risk_level=evaluation["risk_level"],
        model_version=evaluation["model_version"],
    )

    db.add(risk)
    db.commit()
    db.refresh(risk)

    risk_model.auto_train()

    return risk

@router.get("/{risk_id}", response_model=RiskOut)
def get_risk(
    risk_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    risk = (
        db.query(RiskAssessment)
        .join(Host)
        .filter(RiskAssessment.id == risk_id, Host.user_id == user.id)
        .first()
    )

    if not risk:
        raise HTTPException(404, "Evaluación no encontrada o no autorizada")

    return risk

@router.put("/{risk_id}", response_model=RiskOut)
def update_risk(
    risk_id: int,
    data: RiskUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    risk = (
        db.query(RiskAssessment)
        .join(Host)
        .filter(RiskAssessment.id == risk_id, Host.user_id == user.id)
        .first()
    )

    if not risk:
        raise HTTPException(404, "Evaluación no encontrada")

    for k, v in data.dict(exclude_unset=True).items():
        setattr(risk, k, v)

    db.commit()
    db.refresh(risk)

    risk_model.auto_train()

    return risk

@router.delete("/{risk_id}")
def delete_risk(
    risk_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    risk = (
        db.query(RiskAssessment)
        .join(Host)
        .filter(RiskAssessment.id == risk_id, Host.user_id == user.id)
        .first()
    )

    if not risk:
        raise HTTPException(404, "Evaluación no encontrada")

    db.delete(risk)
    db.commit()

    risk_model.auto_train()

    return {"message": "Evaluación eliminada"}
