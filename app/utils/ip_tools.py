import ipaddress

#Valida la IP
def is_valid_ip(ip: str) -> bool:
    """
    Valida si una cadena representa una IP válida (IPv4 o IPv6).
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

#Normaliza la IP
def normalize_ip(ip: str) -> str:
    """
    Normaliza una IP:
    - elimina espacios
    - valida formato
    """
    ip = ip.strip()
    if not is_valid_ip(ip):
        raise ValueError(f"IP inválida: {ip}")
    return ip

# CONVERTIR CIDR en LISTA DE IPs
def cidr_to_ips(cidr: str) -> list[str]:
    """
    Convierte un CIDR en lista de hosts válidos.
    Ejemplo:
        192.168.1.0/30 → ["192.168.1.1", "192.168.1.2"]
    (no incluye network y broadcast)
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception:
        raise ValueError(f"CIDR inválido: {cidr}")


# Expandir el rango de las IP
def expand_ip_range(start_ip: str, end_ip: str) -> list[str]:
    """
    Expande un rango de IP:
        192.168.1.10 - 192.168.1.20
    Devuelve todas las IP del rango.
    """
    start_ip = normalize_ip(start_ip)
    end_ip   = normalize_ip(end_ip)

    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)

    if start > end:
        raise ValueError("El IP inicial no puede ser mayor que el final")

    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]

# Parseo flexible de la entrada
def parse_ip_input(input_str: str) -> list[str]:
    """
    Permite 3 modos de entrada:
    
    IP única
        "192.168.1.10"
    Rango
        "192.168.1.10 - 192.168.1.50"
    CIDR
        "192.168.1.0/24"

    Devuelve SIEMPRE lista de IPs normalizadas.
    """
    input_str = input_str.strip()

    # Caso CIDR
    if "/" in input_str:
        return cidr_to_ips(input_str)

    # Caso rango
    if "-" in input_str:
        start, end = [x.strip() for x in input_str.split("-")]
        return expand_ip_range(start, end)

    # Caso IP única
    if is_valid_ip(input_str):
        return [normalize_ip(input_str)]

    raise ValueError(f"Formato de IP desconocido: {input_str}")

