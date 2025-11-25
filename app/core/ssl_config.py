import os
from dataclasses import dataclass

from app.core.logger import get_logger

log = get_logger(__name__)


# Configuracion SSL para uso de conexiones HTTPS (Faltan ajustes)
@dataclass
class SSLConfig:
    enabled: bool
    certfile: str | None
    keyfile: str | None


def get_ssl_config() -> SSLConfig:
    """
    Lee la configuración SSL desde variables de entorno (.env).

    Variables usadas:
      - SSL_ENABLED (true/false)
      - SSL_CERTFILE (ruta al certificado PEM)
      - SSL_KEYFILE  (ruta a la clave privada PEM)
    """
    enabled_raw = os.getenv("SSL_ENABLED", "false").strip().lower()
    enabled = enabled_raw in ("1", "true", "yes", "on")

    certfile = os.getenv("SSL_CERTFILE")
    keyfile = os.getenv("SSL_KEYFILE")

    if enabled:
        if not certfile or not keyfile:
            # Error fuerte: se habilitó SSL pero faltan archivos
            msg = (
                "SSL_ENABLED=true pero falta SSL_CERTFILE o SSL_KEYFILE en el .env. "
                "Deshabilita SSL o configura las rutas correctas."
            )
            log.error(msg)
            raise RuntimeError(msg)
        else:
            log.info(f"SSL habilitado. Cert: {certfile}  Key: {keyfile}")
    else:
        log.info("SSL deshabilitado. La API correrá sobre HTTP.")

    return SSLConfig(
        enabled=enabled,
        certfile=certfile,
        keyfile=keyfile,
    )


def get_uvicorn_ssl_kwargs() -> dict:
    """
    Devuelve un dict con los argumentos SSL para uvicorn.run(),
    o un dict vacío si SSL está deshabilitado.

    Ejemplo de retorno cuando SSL está activo:
      {
        "ssl_certfile": "certs/cert.pem",
        "ssl_keyfile": "certs/key.pem"
      }
    """
    cfg = get_ssl_config()

    if not cfg.enabled:
        return {}

    return {
        "ssl_certfile": cfg.certfile,
        "ssl_keyfile": cfg.keyfile,
    }
