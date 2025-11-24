from fastapi import FastAPI

from app.config import AppConfig, get_api_prefix
from app.database import init_db
from app.core.logger import get_logger
from app.core.ssl_config import get_uvicorn_ssl_kwargs #Config SSL para https

# Routers v1
from app.api.v1.hosts import router as hosts_router
from app.api.v1.ports import router as ports_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router
from app.api.v1.risk import router as risk_router
from app.api.v1.users import router as users_router
from app.api.v1.auth import router as auth_router
from app.api.v1.routes_scan import router as scan_router
from app.api.v1.reports import router as reports_router

from sqlalchemy import text # Prueba conexion a la BD


log = get_logger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title="VULNPORTS API",
        description="Sistema de escaneo de puertos, vulnerabilidades (NVD) y evaluación de riesgo.",
        version="1.0.0",
    )


    # Config general (CORS, middlewares, etc.)
    AppConfig.init_app(app)


    # Prefijo base /api/v1
    api_prefix = get_api_prefix()


    # rutas REST
    app.include_router(hosts_router, prefix=api_prefix)
    app.include_router(ports_router, prefix=api_prefix)
    app.include_router(vulnerabilities_router, prefix=api_prefix)
    app.include_router(risk_router, prefix=api_prefix)
    app.include_router(users_router, prefix=api_prefix)
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(reports_router, prefix=api_prefix)
    # Router de escaneo (incluye WebSocket /scan/ws)
    app.include_router(scan_router, prefix=api_prefix)


    # Rutas básicas
    @app.get("/", tags=["Root"])
    def root():
        return {
            "message": "VULNPORTS backend running",
            "docs": "/docs",
            "openapi": "/openapi.json",
        }

    
    # verifica estado de la backend
    @app.get("/health", tags=["Health"])
    def health_check():
        return {"status": "ok"}


    #Verifica conexion a la BD
    @app.get("/debug/db")
    def debug_db():
        """
        Endpoint simple para verificar conexión a la base de datos.
        """
        try:
            from app.database import engine
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {"status": "ok", "message": "DB connection successful"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    return app


app = create_app()


# Eventos de ciclo de vida
@app.on_event("startup")
def on_startup():
    log.info("Iniciando aplicación...")
    # Crear tablas si no existen
    init_db()
    log.info("Base de datos inicializada.")


# Ejecución directa con SSL opcional (leyendo .env)
if __name__ == "__main__":
    import uvicorn

    ssl_kwargs = {}
    try:
        ssl_kwargs = get_uvicorn_ssl_kwargs()
    except Exception as e:
        # Si hay error en SSL, logueamos y seguimos sin SSL
        log.error(f"Error al configurar SSL: {e}")
        ssl_kwargs = {}

    log.info(f"Iniciando Uvicorn con SSL: {bool(ssl_kwargs)}")

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        **ssl_kwargs,
    )

