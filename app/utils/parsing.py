from app.utils.ports import validate_port, COMMON_SERVICES


def parse_port_list(port_str: str) -> list[int]:
    """
    Convierte cadenas como:
        "22,80,443"
        "1-1024"
        "22,ssh,http"
        "ftp,100-200"
    en una lista VALIDADA de puertos.

    Con soporte a:
    - servicios por nombre ("http", "ssh", "mysql")
    - mezcla de servicios + puertos
    - rangos válidos
    """

    if not port_str:
        raise ValueError("No se especificaron puertos.")

    ports = set()
    parts = [p.strip().lower() for p in port_str.split(",")]

    for part in parts:
        # ¿Es un NOMBRE DE SERVICIO? ej: "http"
        if part in COMMON_SERVICES.values():
            # busca puerto asociado
            service_port = next(
                (port for port, name in COMMON_SERVICES.items() if name == part),
                None
            )
            if service_port is not None:
                ports.add(service_port)
                continue
            else:
                raise ValueError(f"Servicio desconocido: {part}")
        # ¿Es un rango? ej: "20-80"
        if "-" in part:
            start, end = part.split("-")
            try:
                start = int(start)
                end = int(end)
            except ValueError:
                raise ValueError(f"Rango inválido: {part}")
            if not validate_port(start) or not validate_port(end):
                raise ValueError(f"Rango fuera de límites: {part}")
            ports.update(range(start, end + 1))
            continue
        # ¿Es un puerto individual?
        try:
            p = int(part)
        except ValueError:
            raise ValueError(f"Entrada inválida: {part}")
        if not validate_port(p):
            raise ValueError(f"Puerto inválido: {p}")
        ports.add(p)

    return sorted(list(ports))


def normalize_ports(port_input: str | None) -> list[int]:
    """
    Normaliza la lista de puertos.
    Si NO se envían puertos:
        Retorna SOLO los puertos "importantes" (COMMON_SERVICES).
    Esto evita escaneo 1–65535 por defecto.
    """

    if port_input is None or port_input.strip() == "":
        # Escaneo solo al COMMON_SERVICES
        return sorted(COMMON_SERVICES.keys())

    return parse_port_list(port_input)


