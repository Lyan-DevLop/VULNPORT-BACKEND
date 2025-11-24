from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI

from app.core.settings import get_settings
from app.core.logger import get_logger

settings = get_settings()
log = get_logger(__name__)

#Configuracion general de la API
class AppConfig:
    """
    Configuración general de la app FastAPI.
    Encapsula:
      - CORS
      - Prefix de API
      - Datos generales
      - Logs de arranque
    """

    API_PREFIX = "/api/v1"
    APP_NAME = settings.APP_NAME
    DEBUG = settings.DEBUG

    # Orígenes permitidos
    CORS_ORIGINS = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost",
        "http://127.0.0.1",
        "*",  # Para cualquier origen
    ]

    @staticmethod
    def init_app(app: FastAPI):
        # CORS
        app.add_middleware(
            CORSMiddleware,
            allow_origins=AppConfig.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        # Logging
        log.info(f"== Iniciando {AppConfig.APP_NAME} ==")
        log.info(f"Debug: {AppConfig.DEBUG}")
        log.info(f"API prefix: {AppConfig.API_PREFIX}")

        return app


def get_api_prefix() -> str:
    return AppConfig.API_PREFIX
