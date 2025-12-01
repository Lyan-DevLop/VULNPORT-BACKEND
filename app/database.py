from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.logger import get_logger
from app.core.settings import get_settings

settings = get_settings()
log = get_logger(__name__)

DATABASE_URL = settings.DATABASE_URL


# CONFIG PARA SQLITE (solo local)
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )

# CONFIG PARA SUPABASE (Transaction Mode — puerto 6543)
else:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"sslmode": "require"},
        pool_pre_ping=True,
        pool_size=5,            # Concurrency
        max_overflow=10,        # Permito picos de carga
        pool_timeout=30,
        pool_recycle=1800,      # Evita conexiones muertas
    )

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

def get_db() -> Session:
    """
    Cada request recibe una conexión limpia y garantizada.
    Pool_pre_ping evita conexiones muertas.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    NO usar en Supabase (DDL prohibido).
    Se deja por compatibilidad.
    """
    log.warning("init_db() desactivado — Supabase usa Transaction Pooling.")

