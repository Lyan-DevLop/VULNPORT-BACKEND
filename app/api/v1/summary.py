from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.host_summary import HostSummary
from app.schemas.summary import HostSummaryOut

router = APIRouter(prefix="/summary", tags=["Summary"])


@router.get("/", response_model=list[HostSummaryOut])
def get_summary(db: Session = Depends(get_db)):
    return db.query(HostSummary).all()
