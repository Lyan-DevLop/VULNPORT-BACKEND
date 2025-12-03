from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.host_summary import HostSummary
from app.models.hosts import Host
from app.models.users import User
from app.schemas.summary import HostSummaryOut

router = APIRouter(prefix="/summary", tags=["Summary"])


@router.get("/", response_model=list[HostSummaryOut])
def get_summary(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Devuelve los resúmenes de host pertenecientes al usuario autenticado.
    """

    # Obtener las IPs pertenecientes al usuario
    user_ips_subquery = select(Host.ip_address).where(Host.user_id == user.id)

    summaries = (
        db.query(HostSummary)
        .filter(HostSummary.ip_address.in_(user_ips_subquery))
        .all()
    )

    return summaries



