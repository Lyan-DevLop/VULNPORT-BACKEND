from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os

from app.api.deps import get_current_user, get_db_dep
from app.models.users import User
from app.models.hosts import Host

from app.services.reports.report_generator import ReportGenerator
from app.services.reports.excel_generator import ExcelReportGenerator

router = APIRouter(prefix="/reports", tags=["Reports"])

# Asegurar carpeta de reports
if not os.path.exists("reports"):
    os.makedirs("reports")


async def validate_host_ownership(db: Session, host_id: int, user: User) -> Host:
    host = db.query(Host).filter(Host.id == host_id).first()

    if not host:
        raise HTTPException(404, "Host no encontrado")

    # activar si cada host debe ser del user
    # if host.user_id != user.id:
    #     raise HTTPException(403, "No autorizado")

    return host

# PDF — REPORTE GLOBAL (TODOS LOS HOSTS DEL USUARIO)
@router.get("/pdf/latest")
async def report_pdf_latest(
    db: Session = Depends(get_db_dep),
    user: User = Depends(get_current_user)
):
    hosts = (
        db.query(Host)
        .filter(Host.user_id == user.id)
        .order_by(Host.ip_address.asc())
        .all()
    )

    if not hosts:
        raise HTTPException(404, "No hay escaneos recientes")

    output_path = f"reports/report_network_user_{user.id}.pdf"

    ReportGenerator().generate_network_report(hosts, output_path)

    return FileResponse(
        output_path,
        filename=f"network_scan_user_{user.id}.pdf",
        media_type="application/pdf"
    )

# PDF — HISTORIAL POR HOST (SINGLE HOST)
@router.get("/pdf/history/{host_id}")
async def report_pdf_history(
    host_id: int,
    db: Session = Depends(get_db_dep),
    user: User = Depends(get_current_user)
):
    host = await validate_host_ownership(db, host_id, user)

    output_path = f"reports/history_{host_id}.pdf"

    ReportGenerator().generate_host_report(host, host.ports, host.risk_assessments, output_path)

    return FileResponse(
        output_path,
        filename=f"history_{host.ip_address}.pdf",
        media_type="application/pdf"
    )

# EXCEL — REPORTE GLOBAL (TODOS LOS HOSTS DEL USUARIO)
@router.get("/excel/latest")
async def report_excel_latest(
    db: Session = Depends(get_db_dep),
    user: User = Depends(get_current_user)
):
    hosts = (
        db.query(Host)
        .filter(Host.user_id == user.id)
        .order_by(Host.ip_address.asc())
        .all()
    )

    if not hosts:
        raise HTTPException(404, "No hay escaneos recientes")

    output_path = f"reports/report_network_user_{user.id}.xlsx"

    ExcelReportGenerator().generate_network_excel(hosts, output_path)

    return FileResponse(
        output_path,
        filename=f"network_scan_user_{user.id}.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# EXCEL — HISTORIAL POR HOST (SINGLE HOST)
@router.get("/excel/history/{host_id}")
async def report_excel_history(
    host_id: int,
    db: Session = Depends(get_db_dep),
    user: User = Depends(get_current_user)
):
    host = await validate_host_ownership(db, host_id, user)

    output_path = f"reports/history_{host_id}.xlsx"

    ExcelReportGenerator().generate_host_excel(host, host.ports, host.risk_assessments, output_path)

    return FileResponse(
        output_path,
        filename=f"history_{host.ip_address}.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


