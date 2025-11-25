# app/websocket_manager.py

from typing import Any, Dict, List

from fastapi import WebSocket

from app.core.logger import get_logger

log = get_logger(__name__)


class WebSocketManager:
    def __init__(self):
        # Lista global de conexiones WebSocket
        self.active_connections: List[WebSocket] = []
        # Salas: cada escaneo puede tener múltiples clientes escuchando
        self.scan_rooms: Dict[str, List[WebSocket]] = {}

    # GESTIÓN DE CONEXIONES
    async def connect(self, websocket: WebSocket):
        """Conectar cliente y aceptarlo."""
        await websocket.accept()
        self.active_connections.append(websocket)
        log.info(f"Cliente conectado → Total activos: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Desconectar cliente de conexiones globales y salas."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            log.info(f"Cliente desconectado → Total activos: {len(self.active_connections)}")

        # También eliminarlo de las salas
        for room_id, clients in list(self.scan_rooms.items()):
            if websocket in clients:
                clients.remove(websocket)
                if not clients:
                    del self.scan_rooms[room_id]

    # ENVÍO INDIVIDUAL
    async def send_to(self, websocket: WebSocket, message: Any):
        """Envía mensaje a un solo cliente."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)

    # BROADCAST GLOBAL
    async def broadcast(self, message: Any):
        """Envia mensaje a TODOS los clientes conectados."""
        for ws in list(self.active_connections):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)

    # SALAS DE ESCANEO
    def join_room(self, scan_id: str, websocket: WebSocket):
        """Añadir cliente a la sala del escaneo."""
        if scan_id not in self.scan_rooms:
            self.scan_rooms[scan_id] = []
        self.scan_rooms[scan_id].append(websocket)
        log.info(f"Cliente unido a sala {scan_id} → {len(self.scan_rooms[scan_id])} clientes en sala")

    async def broadcast_room(self, scan_id: str, message: Any):
        """Enviar mensaje a todos los clientes mirando un mismo escaneo."""
        if scan_id not in self.scan_rooms:
            return

        for ws in list(self.scan_rooms[scan_id]):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)

    # ENVÍO SEGURO INDIVIDUAL
    async def safe_emit(self, websocket: WebSocket, message: Any):
        """Envío seguro a un cliente sin romper servidor."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)


# INSTANCIA GLOBAL
ws_manager = WebSocketManager()
