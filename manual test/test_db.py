# test_db.py

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

print("🔍 Probando conexión a la base de datos...")
print(f"URL: {DATABASE_URL}")


def test_connection():
    try:
        engine = create_engine(DATABASE_URL, pool_pre_ping=True)

        with engine.connect() as conn:
            result = conn.execute(text("SELECT NOW();"))
            row = result.fetchone()
            print("\n✅ Conexión exitosa a la BD!")
            print(f"🕒 Hora del servidor: {row[0]}\n")

    except SQLAlchemyError as e:
        print("\n❌ Error en conexión a la base de datos:")
        print(str(e.__cause__ or e))
    except Exception as ex:
        print("\n❌ Error inesperado:")
        print(str(ex))


if __name__ == "__main__":
    test_connection()
