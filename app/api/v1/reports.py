from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.api.deps import get_current_user

from app.models.users import User
from app.models.hosts import Host

from app.services.reports.report_generator import ReportGenerator
from app.services.reports.excel_generator import ExcelReportGenerator


router = APIRouter(prefix="/reports", tags=["Reports"])

# Helper: validar que el host pertenece al usuario
async def validate_host_ownership(db: Session, host_id: int, user: User) -> Host:
    host = db.query(Host).filter(Host.id == host_id).first()

    if not host:
        raise HTTPException(status_code=404, detail="Host no encontrado")

    if str(host.ip_address).startswith("127.") or str(host.ip_address).startswith("localhost"):
        pass  # opcional: hosts internos

    # Si el usuario solo debe ver los suyos, activa esto:
    # if host.user_id != user.id:
    #      raise HTTPException(status_code=403, detail="No autorizado para este host")

    return host

# PDF — Último escaneo del usuario
@router.get("/pdf/latest")
async def report_pdf_latest(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = (
        db.query(Host)
        .filter(Host.user_id == user.id)
        .order_by(Host.scan_date.desc())
        .first()
    )

    if not host:
        raise HTTPException(404, "No hay escaneos recientes")

    ports = host.ports
    risks = host.risk_assessments

    output_path = f"reports/report_latest_user_{user.id}.pdf"

    ReportGenerator().generate_host_report(host, ports, risks, output_path)

    return FileResponse(
        output_path,
        filename=f"latest_scan_{host.ip_address}.pdf",
        media_type="application/pdf"
    )


# PDF — Historial por host
@router.get("/pdf/history/{host_id}")
async def report_pdf_history(
    host_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = validate_host_ownership(db, host_id, user)
    ports = host.ports
    risks = host.risk_assessments

    output_path = f"reports/history_{host_id}.pdf"

    ReportGenerator().generate_host_report(host, ports, risks, output_path)

    return FileResponse(
        output_path,
        filename=f"history_{host.ip_address}.pdf",
        media_type="application/pdf"
    )

# EXCEL — Último escaneo del usuario
@router.get("/excel/latest")
async def report_excel_latest(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = (
        db.query(Host)
        .filter(Host.user_id == user.id)
        .order_by(Host.scan_date.desc())
        .first()
    )

    if not host:
        raise HTTPException(404, "No hay escaneos recientes")

    ports = host.ports
    risks = host.risk_assessments

    output_path = f"reports/report_latest_user_{user.id}.xlsx"

    ExcelReportGenerator().generate_host_excel(host, ports, risks, output_path)

    return FileResponse(
        output_path,
        filename=f"latest_scan_{host.ip_address}.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# EXCEL — Historial por host
@router.get("/excel/history/{host_id}")
async def report_excel_history(
    host_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = validate_host_ownership(db, host_id, user)
    ports = host.ports
    risks = host.risk_assessments

    output_path = f"reports/history_{host_id}.xlsx"

    ExcelReportGenerator().generate_host_excel(host, ports, risks, output_path)

    return FileResponse(
        output_path,
        filename=f"history_{host.ip_address}.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
