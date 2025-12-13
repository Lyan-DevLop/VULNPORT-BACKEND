import os

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.hosts import Host
from app.models.ports import Port
from app.models.vulnerabilities import Vulnerability
from app.services.risk_model.neural_model import risk_model

router = APIRouter(prefix="/risk_status", tags=["Risk Model Status"])


@router.get("/status")
def get_risk_model_status(db: Session = Depends(get_db), user=Depends(get_current_user)):
    host_count = db.query(Host).count()
    port_count = db.query(Port).count()
    vuln_count = db.query(Vulnerability).count()

    model_file_exists = os.path.exists("risk_model.pkl")
    scaler_file_exists = os.path.exists("risk_scaler.pkl")

    return {
        "model_ready": model_file_exists and scaler_file_exists,
        "model_version": risk_model.get_version() if model_file_exists else "fallback",
        "files": {
            "risk_model.pkl": model_file_exists,
            "risk_scaler.pkl": scaler_file_exists
        },
        "dataset": {
            "hosts": host_count,
            "ports": port_count,
            "vulnerabilities": vuln_count
        },
        "requirements": {
            "min_hosts": risk_model.MIN_HOSTS,
            "min_vulnerabilities": risk_model.MIN_VULNS,
            "meets_requirements":
                host_count >= risk_model.MIN_HOSTS and vuln_count >= risk_model.MIN_VULNS
        }
    }

