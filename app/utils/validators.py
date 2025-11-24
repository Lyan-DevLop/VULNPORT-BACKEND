from app.utils.ip_tools import is_valid_ip
from app.utils.ports import validate_port, normalize_protocol


def validate_ip_or_raise(ip: str):
    """
    Valida una IP y muestra error si no es válida.
    """
    if not is_valid_ip(ip):
        raise ValueError(f"IP inválida: {ip}")
    return ip


def validate_port_or_raise(port: int):
    """
    Valida un puerto y muestra error si es incorrecto.
    """
    if not validate_port(port):
        raise ValueError(f"Puerto inválido: {port}")
    return port


def validate_protocol_or_raise(proto: str):
    """
    Normaliza y valida el protocolo.
    """
    return normalize_protocol(proto)


def validate_non_empty_string(value: str, field: str):
    """
    Valida que un campo o cadena no esté vacío.
    """
    if value is None or value.strip() == "":
        raise ValueError(f"El campo '{field}' no puede estar vacío")
    return value.strip()


def validate_cve_format(cve: str):
    """
    Valida formato muy básico de CVE:
        CVE-YYYY-NNNN
    """
    if not cve.startswith("CVE-") or len(cve.split("-")) < 3:
        raise ValueError(f"Formato CVE inválido: {cve}")
    return cve
