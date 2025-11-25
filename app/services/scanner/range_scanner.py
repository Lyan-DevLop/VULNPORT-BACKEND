import ipaddress
from typing import AsyncGenerator, Dict, Optional

from app.core.logger import get_logger
from app.services.scanner.port_scanner import scan_single_host
from app.utils.network import discover_active_hosts
from app.utils.parsing import normalize_ports

log = get_logger(__name__)


class RangeScanner:
    # STREAMING (WebSocket) — solo hosts con puertos abiertos
    async def scan_stream(self, network_cidr: str, ports_raw: Optional[str] = None) -> AsyncGenerator[Dict, None]:
        # Validar puertos
        try:
            ports_raw = normalize_ports(ports_raw)
        except Exception as e:
            yield {"type": "error", "message": str(e)}
            return

        # Validar rango
        try:
            ipaddress.ip_network(network_cidr)
        except ValueError:
            yield {"type": "error", "message": f"CIDR inválido: {network_cidr}"}
            return

        # Solo hosts activos vía ARP
        active_hosts = discover_active_hosts(network_cidr)
        total = len(active_hosts)

        if total == 0:
            yield {"type": "error", "message": "No hay hosts activos en la red."}
            return

        # Escaneo real
        for idx, ip in enumerate(active_hosts):
            progress = round(((idx + 1) / total) * 100, 2)

            yield {"type": "progress", "ip": ip, "progress": progress, "message": f"Escaneando {ip}"}

            try:
                host_result = await scan_single_host(ip, ports_raw)
            except Exception as e:
                host_result = {"error": str(e)}

            # Si no tiene puertos abiertos → ignorar
            if not host_result.get("open_ports"):
                continue

            yield {"type": "result", "ip": ip, "data": host_result, "progress": progress}

        yield {"type": "status", "message": "Escaneo completado", "progress": 100}

    # REST MODE — solo devuelve hosts con puertos abiertos
    async def scan_network(self, network_cidr: str, ports_raw: Optional[str] = None) -> Dict[str, Dict]:
        # Validar puertos
        try:
            ports_raw = normalize_ports(ports_raw)
        except Exception as e:
            return {"error": str(e)}

        # Detectar hosts activos
        active_hosts = discover_active_hosts(network_cidr)

        if not active_hosts:
            return {"error": "No se detectaron hosts activos en la red."}

        results = {}

        for ip in active_hosts:
            log.info(f"Escaneando host activo {ip}")

            try:
                host_result = await scan_single_host(ip, ports_raw)
            except Exception as e:
                results[ip] = {"error": str(e)}
                continue

            # No agregamos hosts sin puertos abiertos
            if not host_result.get("open_ports"):
                continue

            results[ip] = host_result

        return results


# Instancia global
range_scanner = RangeScanner()
