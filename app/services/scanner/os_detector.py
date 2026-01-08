import platform
import subprocess
from typing import Optional

from app.core.logger import get_logger

log = get_logger(__name__)


TTL_OS_MAPPING = {
    # Linux
    range(0, 65): "Linux/Unix",
    # Windows
    range(65, 129): "Windows",
    # Cisco / Network devices
    range(129, 255): "Cisco/Network Device",
}


def detect_os(ip: str) -> Optional[str]:
    """
    Detecta sistema operativo estimado usando TTL obtenido por 'ping'.

    Funciona en:
        - Windows
        - Linux
        - macOS

    Retorna:
        "Windows", "Linux/Unix", "Cisco/Network Device" o "Unknown".
    """

    ttl = _get_ttl(ip)

    if ttl is None:
        log.warning(f"OS detection failed → no TTL for {ip}")
        return "Unknown"

    # Mapea el TTL al sistema operativo
    for ttl_range, os_name in TTL_OS_MAPPING.items():
        if ttl in ttl_range:
            log.info(f"OS detected for {ip}: {os_name} (TTL={ttl})")
            return os_name

    log.info(f"Could not match TTL={ttl} for {ip}")
    return "Unknown"


# Funciones internas
# Obtiene el TTL
def _get_ttl(ip: str) -> Optional[int]:
    """
    Obtiene el TTL real utilizando ping del sistema operativo.
    """

    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]  # Linux/macOS

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except Exception:
        return None

    ttl_value = _extract_ttl(output)
    return ttl_value


# Extrae el TTL
def _extract_ttl(output: str) -> Optional[int]:
    """
    Extrae el TTL de la salida del ping.
    Funciona para Windows, Linux y macOS.
    """

    output = output.lower()

    # Windows → "ttl=128"
    # Linux   → "ttl=64"
    for piece in output.split():
        if "ttl=" in piece:
            try:
                return int(piece.replace("ttl=", ""))
            except ValueError:
                pass

    return None
