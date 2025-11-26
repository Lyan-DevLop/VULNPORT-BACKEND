from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

from app.core.logger import get_logger
from app.core.settings import get_settings

settings = get_settings()
log = get_logger(__name__)


# DATABASE ENGINE
DATABASE_URL = settings.DATABASE_URL


# Modo especial para SQLite (threading)
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=NullPool,  # Evita errores por pooling en SQLite
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


# SESSION LOCAL
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Base para los modelos declarativos
Base = declarative_base()


# DEPENDENCIA PARA FASTAPI
def get_db() -> Session:
    """
    Retorna una sesión de BD.
    Se usa con: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# INICIALIZACIÓN OPCIONAL (CREAR TABLAS)
def init_db():
    """
    Inicializa las tablas si no existen.
    OJO: host_summary es una vista, no se crea.
    """

    log.info("Creando tablas si no existen...")
    Base.metadata.create_all(bind=engine)
    log.info("Tablas listas.")
