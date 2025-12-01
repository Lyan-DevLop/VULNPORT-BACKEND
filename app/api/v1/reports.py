import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.hosts import Host
from app.models.users import User
from app.services.reports.excel_generator import ExcelReportGenerator
from app.services.reports.report_generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["Reports"])

# Asegurar carpeta
if not os.path.exists("reports"):
    os.makedirs("reports")


async def validate_host_ownership(db: Session, host_id: int, user: User) -> Host:
    """
    Verifica que el host exista y que pertenezca al usuario autenticado.
    """
    host = db.query(Host).filter(Host.id == host_id).first()

    if not host:
        raise HTTPException(404, "Host no encontrado")

    if host.user_id != user.id:
        raise HTTPException(403, "No autorizado")

    return host

@router.get("/pdf/latest")
async def report_pdf_latest(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    hosts = (
        db.query(Host)
        .filter(Host.user_id == user.id)
        .order_by(Host.ip_address.asc())
        .all()
    )

    if not hosts:
        raise HTTPException(404, "No hay escaneos recientes del usuario")

    output_path = f"reports/report_network_user_{user.id}.pdf"

    ReportGenerator().generate_network_report(hosts, output_path)

    return FileResponse(
        output_path,
        filename=f"network_scan_user_{user.id}.pdf",
        media_type="application/pdf",
    )

@router.get("/pdf/history/{host_id}")
async def report_pdf_history(
    host_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = await validate_host_ownership(db, host_id, user)

    output_path = f"reports/history_{host_id}.pdf"

    ReportGenerator().generate_host_report(
        host,
        host.ports,
        host.risk_assessments,
        output_path
    )

    return FileResponse(
        output_path,
        filename=f"history_{host.ip_address}.pdf",
        media_type="application/pdf"
    )

@router.get("/excel/latest")
async def report_excel_latest(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    hosts = (
        db.query(Host)
        .filter(Host.user_id == user.id)
        .order_by(Host.ip_address.asc())
        .all()
    )

    if not hosts:
        raise HTTPException(404, "No hay escaneos recientes del usuario")

    output_path = f"reports/report_network_user_{user.id}.xlsx"

    ExcelReportGenerator().generate_network_excel(hosts, output_path)

    return FileResponse(
        output_path,
        filename=f"network_scan_user_{user.id}.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

@router.get("/excel/history/{host_id}")
async def report_excel_history(
    host_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    host = await validate_host_ownership(db, host_id, user)

    output_path = f"reports/history_{host_id}.xlsx"

    ExcelReportGenerator().generate_host_excel(
        host,
        host.ports,
        host.risk_assessments,
        output_path
    )

    return FileResponse(
        output_path,
        filename=f"history_{host.ip_address}.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

