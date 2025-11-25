from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.database import get_db
from app.websocket_manager import ws_manager

from app.schemas.scan import ScanRequest, RangeScanRequest
from app.utils.parsing import normalize_ports
from app.utils.network import get_local_network_cidr

from app.services.scanner.worker import scan_worker

from app.api.deps import get_current_user
from app.models.users import User

router = APIRouter(prefix="/scan", tags=["Scanner"])


# ESCANEO INDIVIDUAL (REST)
@router.post("/single")
async def scan_single(
    data: ScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Escaneo COMPLETO individual
    """
    ports = normalize_ports(data.ports)

    result = await scan_worker.scan_single_host(
        ip=data.ip,
        ports=ports,
        db=db,
        user_id=user.id
    )

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

# ESCANEO DE RANGO (REST)
@router.post("/range")
async def scan_range_hosts(
    data: RangeScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Escaneo de rango de red completo.
    """
    ports = normalize_ports(data.ports)

    results = await scan_worker.scan_network_range(
        cidr=data.network,
        ports=ports,
        db=db,
        user_id=user.id 
    )

    return {
        "network": data.network,
        "ports_scanned": ports,
        "results": results
    }

# 3. WEBSOCKET: ESCANEO INDIVIDUAL Y RANGO
@router.websocket("/ws")
async def scan_ws(ws: WebSocket):
    await ws_manager.connect(ws)

    async def send_update(msg):
        await ws_manager.send_to(ws, msg)

    try:
        while True:
            data = await ws.receive_json()
            cmd = data.get("type")

            token = data.get("token")
            user = await get_current_user(token=token)

            # SCAN SINGLE
            if cmd == "single":
                ip = data.get("ip")
                ports_raw = data.get("ports")
                ports = normalize_ports(ports_raw)

                await send_update({"type": "status", "message": f"Escaneando {ip}..."})

                result = await scan_worker.scan_single_host(
                    ip=ip,
                    ports=ports,
                    on_update=send_update,
                    user_id=user.id 
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

            # SCAN RANGE
            elif cmd == "range":
                cidr = data.get("cidr")
                ports_raw = data.get("ports")
                ports = normalize_ports(ports_raw)

                await send_update({"type": "status", "message": f"Escaneando red {cidr}..."})

                results = await scan_worker.scan_network_range(
                    cidr=cidr,
                    ports=ports,
                    on_update=send_update,
                    user_id=user.id 
                )

                await send_update({
                    "type": "range_result",
                    "cidr": cidr,
                    "ports": ports,
                    "results": results
                })

    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# ESCANEO AUTOMÁTICO (REST)
@router.get("/auto")
async def auto_scan_rest(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Escaneo automático completo usando el usuario autenticado.
    """
    network_cidr = get_local_network_cidr(mask=24)

    results = await scan_worker.scan_network_range(
        cidr=network_cidr,
        ports=list(range(1, 1024)),
        db=db,
        user_id=user.id 
    )

    return {
        "network": network_cidr,
        "results": results
    }

# 5. ESCANEO AUTOMÁTICO (WS)
@router.websocket("/auto/ws")
async def auto_scan_ws(ws: WebSocket):
    await ws_manager.connect(ws)

    async def send_update(msg):
        await ws_manager.send_to(ws, msg)

    try:
        # Obtener token desde querystring
        params = dict(x.split("=") for x in ws.scope["query_string"].decode().split("&") if "=" in x)
        token = params.get("token")

        # Usuario real
        user = await get_current_user(token=token)

        network_cidr = get_local_network_cidr(mask=24)

        await send_update({"type": "start", "message": f"Escaneando {network_cidr}..."})

        results = await scan_worker.scan_network_range(
            cidr=network_cidr,
            ports=list(range(1, 1024)),
            on_update=send_update,
            user_id=user.id
        )

        await send_update({
            "type": "status",
            "message": "Escaneo completo",
            "results": results
        })

    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


