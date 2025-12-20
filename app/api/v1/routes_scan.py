from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.database import SessionLocal, get_db
from app.models.users import User
from app.schemas.scan import RangeScanRequest, ScanRequest
from app.services.scanner.worker import scan_worker
from app.utils.network import get_local_network_cidr
from app.utils.parsing import normalize_ports
from app.websocket_manager import ws_manager

router = APIRouter(prefix="/scan", tags=["Scanner"])


#   FUNCIÓN COMPATIBLE CON WEBSOCKETS PARA USAR JWT
async def get_user_from_ws_token(token: str):
    """
    Decodifica el JWT y devuelve el usuario desde la BD.
    Solo para uso en WebSockets (no usa Depends).

    Aquí NO usamos get_db() como generador
    para evitar fugas de conexión.
    """
    if not token or token in ("null", "undefined", ""):
        return None

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id = payload.get("sub")
        if not user_id:
            return None
    except JWTError:
        return None

    # Sesión manual, SIEMPRE cerrando
    db = SessionLocal()
    try:
        return db.query(User).filter(User.id == user_id).first()
    finally:
        db.close()


# 1. ESCANEO INDIVIDUAL (REST)
@router.post("/single")
async def scan_single(
    data: ScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Escaneo individual completo para el usuario autenticado.
    """
    ports = normalize_ports(data.ports)

    result = await scan_worker.scan_single_host(
        ip=data.ip,
        ports=ports,
        db=db,
        user_id=user.id,
    )

    open_only = {
        p: info
        for p, info in result["ports"].items()
        if info["status"] in ("open", "open|filtered", "filtered")
    }

    return {
        "ip": data.ip,
        "ports_scanned": ports,
        "open_ports": open_only,
        "os": result["os"],
        "risk": result["risk"],
        "vulnerabilities": result["vulnerabilities"],
    }


# 2. ESCANEO DE RANGO (REST)
@router.post("/range")
async def scan_range_hosts(
    data: RangeScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Escaneo de rango de red para el usuario autenticado.
    """
    ports = normalize_ports(data.ports)

    results = await scan_worker.scan_network_range(
        cidr=data.network,
        ports=ports,
        db=db,
        user_id=user.id,
    )

    return {
        "network": data.network,
        "ports_scanned": ports,
        "results": results,
    }


# 3. WEBSOCKET PRINCIPAL (single + range)
@router.websocket("/ws")
async def scan_ws(ws: WebSocket):
    await ws.accept()
    await ws_manager.connect(ws)

    async def send(msg: dict):
        await ws_manager.send_to(ws, msg)

    try:
        while True:
            data = await ws.receive_json()
            cmd = data.get("type")
            token = data.get("token")

            # Obtener usuario desde token mediante helper
            user = await get_user_from_ws_token(token)
            if not user:
                await send({"type": "error", "message": "Token inválido o usuario no encontrado"})
                continue

            # SINGLE
            if cmd == "single":
                ip = data.get("ip")
                ports = normalize_ports(data.get("ports"))

                await send({"type": "status", "message": f"Escaneando {ip}..."})

                result = await scan_worker.scan_single_host(
                    ip=ip,
                    ports=ports,
                    on_update=send,
                    user_id=user.id,
                )

                open_ports = {
                    p: info
                    for p, info in result["ports"].items()
                    if info["status"] in ("open", "open|filtered", "filtered")
                }

                await send({
                    "type": "single_result",
                    "ip": ip,
                    "ports": ports,
                    "open_ports": open_ports,
                    "os": result["os"],
                    "risk": result["risk"],
                    "vulnerabilities": result["vulnerabilities"],
                })

            # RANGE
            elif cmd == "range":
                cidr = data.get("cidr")
                ports = normalize_ports(data.get("ports"))

                await send({"type": "status", "message": f"Escaneando red {cidr}..."})

                results = await scan_worker.scan_network_range(
                    cidr=cidr,
                    ports=ports,
                    on_update=send,
                    user_id=user.id,
                )

                await send({
                    "type": "range_result",
                    "cidr": cidr,
                    "ports": ports,
                    "results": results,
                })

            else:
                await send({"type": "error", "message": f"Comando no soportado: {cmd}"})

    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception as e:
        try:
            await send({"type": "error", "message": f"Error interno: {str(e)}"})
        except Exception:
            pass
        ws_manager.disconnect(ws)


# 4. AUTO SCAN (REST)
@router.get("/auto")
async def auto_scan_rest(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Auto escaneo de la red local para el usuario autenticado.
    """
    cidr = get_local_network_cidr(mask=24)

    results = await scan_worker.scan_network_range(
        cidr=cidr,
        ports=list(range(1, 1024)),
        db=db,
        user_id=user.id,
    )

    return {"network": cidr, "results": results}


# 5. AUTO SCAN (WebSocket)
@router.websocket("/auto/ws")
async def auto_scan_ws(ws: WebSocket):
    await ws.accept()

    # Token desde query param
    raw = ws.scope.get("query_string", b"").decode()
    params = dict(x.split("=", 1) for x in raw.split("&") if "=" in x)
    token = params.get("token")

    user = await get_user_from_ws_token(token)
    if not user:
        await ws.send_json({"type": "error", "message": "Token inválido o usuario no encontrado"})
        await ws.close()
        return

    await ws_manager.connect(ws)

    async def send(msg: dict):
        await ws_manager.send_to(ws, msg)

    try:
        cidr = get_local_network_cidr(mask=24)
        await send({"type": "start", "message": f"Escaneando {cidr}..."})

        results = await scan_worker.scan_network_range(
            cidr=cidr,
            ports=list(range(1, 1024)),
            on_update=send,
            user_id=user.id,
        )

        await send({
            "type": "status",
            "message": "Escaneo completo",
            "results": results,
        })

    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception as e:
        await send({"type": "error", "message": f"Error interno: {str(e)}"})
        ws_manager.disconnect(ws)
