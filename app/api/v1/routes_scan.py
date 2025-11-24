# app/api/v1/routes_scan.py

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.database import get_db
from app.websocket_manager import ws_manager

from app.schemas.scan import ScanRequest, RangeScanRequest
from app.utils.parsing import normalize_ports
from app.utils.network import get_local_network_cidr

from app.services.scanner.worker import scan_worker


router = APIRouter(prefix="/scan", tags=["Scanner"])


# Scaneo simple o individual (REST) – Escaneo completo + Persistencia
@router.post("/single")
async def scan_single(data: ScanRequest, db: Session = Depends(get_db)):
    """
    Escaneo COMPLETO:
    - Puertos abiertos
    - Banner
    - Detección de SO
    - CVEs NVD
    - IA de riesgo
    - Persistencia en BD
    """
    ports = normalize_ports(data.ports)

    result = await scan_worker.scan_single_host(
        ip=data.ip,
        ports=ports,
        db=db
    )

    # Filtrar solo puertos útiles
    open_only = {
        p: info for p, info in result["ports"].items()
        if info["status"] in ("open", "open|filtered", "filtered")
    }

    return {
        "ip": data.ip,
        "ports_scanned": ports,
        "open_ports": open_only,
        "os": result["os"],
        "risk": result["risk"],
        "vulnerabilities": result["vulnerabilities"]
    }


# Scaneo completo (REST) – Descubre activos + escaneo completo
@router.post("/range")
async def scan_range_hosts(data: RangeScanRequest, db: Session = Depends(get_db)):
    """
    Escaneo completo de todos los hosts activos de la red.
    - Solo hosts con puertos abiertos
    - Incluye NVD + IA + persistencia
    """
    ports = normalize_ports(data.ports)

    results = await scan_worker.scan_network_range(
        cidr=data.network,
        ports=ports,
        db=db
    )

    return {
        "network": data.network,
        "ports_scanned": ports,
        "results": results
    }



# WEBSOCKET SCAN (Single + Range)
@router.websocket("/ws")
async def scan_ws(ws: WebSocket):
    await ws_manager.connect(ws)

    async def send_update(msg):
        await ws_manager.send_to(ws, msg)

    try:
        while True:
            data = await ws.receive_json()
            cmd = data.get("type")

            # Host individual
            if cmd == "single":
                ip = data.get("ip")
                ports_raw = data.get("ports")
                ports = normalize_ports(ports_raw)

                await send_update({"type": "status", "message": f"Escaneando {ip}..."})

                result = await scan_worker.scan_single_host(
                    ip=ip,
                    ports=ports,
                    on_update=send_update,
                )

                open_ports = {
                    p: info for p, info in result["ports"].items()
                    if info["status"] in ("open", "open|filtered", "filtered")
                }

                await send_update({
                    "type": "single_result",
                    "ip": ip,
                    "ports": ports,
                    "open_ports": open_ports,
                    "os": result["os"],
                    "risk": result["risk"],
                    "vulnerabilities": result["vulnerabilities"]
                })

            # Rango completo
            elif cmd == "range":
                cidr = data.get("cidr")
                ports_raw = data.get("ports")
                ports = normalize_ports(ports_raw)

                await send_update({"type": "status", "message": f"Escaneando red {cidr}..."})

                results = await scan_worker.scan_network_range(
                    cidr=cidr,
                    ports=ports,
                    on_update=send_update,
                )

                await send_update({
                    "type": "range_result",
                    "cidr": cidr,
                    "ports": ports,
                    "results": results
                })

    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# Scaneo automatico
@router.get("/auto")
async def auto_scan_rest(db: Session = Depends(get_db)):
    """
    Escaneo automático completo:
    - Detecta la red local
    - Escanea solo hosts activos
    - NVD + IA
    - Persistencia total
    """
    network_cidr = get_local_network_cidr(mask=24)

    results = await scan_worker.scan_network_range(
        cidr=network_cidr,
        ports=list(range(1, 1024)),     # recomendado Nmap style
        db=db
    )

    return {
        "network": network_cidr,
        "results": results
    }

# AUTO SCAN – WebSocket
@router.websocket("/auto/ws")
async def auto_scan_ws(ws: WebSocket):
    await ws_manager.connect(ws)

    async def send_update(msg):
        await ws_manager.send_to(ws, msg)

    try:
        network_cidr = get_local_network_cidr(mask=24)

        await send_update({"type": "start", "message": f"Escaneando {network_cidr}..."})

        results = await scan_worker.scan_network_range(
            cidr=network_cidr,
            ports=list(range(1, 1024)),
            on_update=send_update
        )

        await send_update({
            "type": "status",
            "message": "Escaneo completo",
            "results": results
        })

    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
