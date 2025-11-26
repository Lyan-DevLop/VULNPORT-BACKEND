import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from app.core import settings

DATABASE_URL =  settings.DATABASE_URL


def test_database_connection():
    """Verifica que la base de datos acepta conexiones."""
    engine = create_engine(DATABASE_URL)

    try:
        with engine.connect() as conn:
            result = conn.execute("SELECT 1")
            assert result.scalar() == 1
    except SQLAlchemyError as e:
        pytest.fail(f"Error conectando a la base de datos: {e}")
