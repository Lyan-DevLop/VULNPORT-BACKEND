import ipaddress
import socket

# Importamos Scapy.
# Si no está disponible, ARP-scan quedará deshabilitado.
try:
    from scapy.all import ARP, Ether, srp

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


#  Get a IP local
def get_local_ip() -> str:
    """
    Obtiene la IP local real enviando un paquete "fake" a 8.8.8.8.
    No se establece una conexión real, solo usa la interfaz predeterminada.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


#  Genera automaticamente la red local
def get_default_network(cidr_mask: int = 24) -> str | None:
    """
    Retorna la red completa basada en la IP local:
       192.168.1.57 → 192.168.1.0/24
    """
    try:
        ip = get_local_ip()
        network = ipaddress.IPv4Network(f"{ip}/{cidr_mask}", strict=False)
        return str(network)
    except Exception:
        return None


def get_local_network_cidr(mask: int = 24) -> str:
    """
    Igual que get_default_network, pero falla si algo sale mal.
    """
    ip = get_local_ip()
    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(network)


#  ARP-SCAN para encontrar hosts activos
def discover_active_hosts(network_cidr: str) -> list[str]:
    """
    Descubre hosts activos usando ARP Scan.
    Si Scapy NO está disponible, retorna una lista vacía.
    """
    if not SCAPY_AVAILABLE:
        print("WARNING: Scapy no está instalado. ARP-scan deshabilitado.")
        return []

    try:
        # ARP Broadcast
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)

        ans, _ = srp(packet, timeout=1, verbose=0)

        hosts = [received.psrc for _, received in ans]

        return hosts

    except PermissionError:
        print("Necesitas permisos de administrador para ARP-scan.")
        return []
    except Exception as e:
        print(f"Error en ARP-scan: {e}")
        return []
