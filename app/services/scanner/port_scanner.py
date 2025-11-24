import asyncio
import socket
import platform
from typing import Optional, Dict, List

from app.utils.ports import guess_service, normalize_protocol
from app.utils.parsing import normalize_ports
from app.core.logger import get_logger

log = get_logger(__name__)


# AUTO-SELECCIONAR LÍMITE DE CONCURRENCIA
def get_optimal_limit():
    system = platform.system()

    if system == "Windows":
        return 200      # Windows select() soporta poco
    if system == "Linux":
        return 800      # Linux permite más conexiones
    return 300          # Fallback seguro


class PortScanner:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.cancel_flag = False
        self.semaphore_limit = get_optimal_limit()

    # Cancelar el scaneo
    def cancel(self):
        log.warning("⛔ Escaneo cancelado por el usuario")
        self.cancel_flag = True

    def reset_cancel(self):
        self.cancel_flag = False

    # Scaneo TCP
    async def scan_tcp(self, ip: str, port: int) -> Dict:

        if self.cancel_flag:
            return {"status": "cancelled"}

        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

            banner = await self._read_banner(reader)

            writer.close()
            await writer.wait_closed()

            return {
                "protocol": "tcp",
                "status": "open",
                "service_name": guess_service(port),
                "service_version": banner or None,
            }

        except Exception:
            # NO devolvemos "closed" → lo filtramos arriba
            return {"status": "closed"}

    #Scaneo UDP
    async def scan_udp(self, ip: str, port: int) -> Dict:

        if self.cancel_flag:
            return {"status": "cancelled"}

        try:
            loop = asyncio.get_event_loop()
            status = await loop.run_in_executor(None, self._udp_probe, ip, port)

            # Filtrar cerrados
            if status == "closed":
                return {"status": "closed"}

            return {
                "protocol": "udp",
                "status": status,          # open | open|filtered
                "service_name": guess_service(port),
                "service_version": None,
            }

        except Exception:
            return {"status": "closed"}

    def _udp_probe(self, ip: str, port: int) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            sock.sendto(b"", (ip, port))
            data, _ = sock.recvfrom(1024)

            if data:
                return "open"

            return "open|filtered"

        except socket.timeout:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
        except Exception:
            return "closed"
        finally:
            sock.close()


    # BANNER GRABBING
    async def _read_banner(self, reader: asyncio.StreamReader) -> Optional[str]:
        try:
            data = await asyncio.wait_for(reader.read(128), timeout=0.5)
            if data:
                banner = data.decode(errors="ignore").strip()
                return banner
        except Exception:
            return None


    # MULTIPORT CONCURRENCY SAFE + PROGRESO + CANCEL
    async def scan_ports(self, ip: str, ports: List[int], progress_cb=None) -> Dict[int, Dict]:

        self.reset_cancel()

        semaphore = asyncio.Semaphore(self.semaphore_limit)
        total = len(ports)
        completed = 0

        async def scan_with_limit(port):
            nonlocal completed

            async with semaphore:

                if self.cancel_flag:
                    return port, {"status": "cancelled"}

                result = await self.scan_tcp(ip, port)

                completed += 1

                # Emitir progreso
                if progress_cb:
                    await progress_cb({
                        "type": "progress",
                        "completed": completed,
                        "total": total,
                        "percent": round((completed / total) * 100, 2),
                        "current_port": port
                    })

                return port, result

        tasks = [scan_with_limit(port) for port in ports]
        raw = await asyncio.gather(*tasks)

        # Filtra solo abiertos y filtrando
        filtered = {
            port: result
            for port, result in raw
            if result.get("status") in ("open", "open|filtered", "filtered")
        }

        return filtered


# INSTANCIA GLOBAL
port_scanner = PortScanner(timeout=1.0)


async def scan_single_host(ip: str, ports_raw: Optional[str] = None, progress_cb=None) -> Dict:

    ports = normalize_ports(ports_raw)

    # Prioriza puertos comunes
    common = [22, 80, 443, 445, 3389, 8080]
    common = [p for p in common if p in ports]
    remaining = [p for p in ports if p not in common]

    results = {}

    if common:
        first = await port_scanner.scan_ports(ip, common, progress_cb)
        results.update(first)

    if remaining and not port_scanner.cancel_flag:
        second = await port_scanner.scan_ports(ip, remaining, progress_cb)
        results.update(second)

    return {
        "ip": ip,
        "ports_scanned": ports,
        "results": results,
        "open_ports": list(results.keys()),
        "cancelled": port_scanner.cancel_flag,
    }




