# test_nvd.py

import asyncio
from app.core.nvd_client import nvd_client
from app.core.logger import get_logger

log = get_logger(__name__)


async def test_nvd():
    print("🔍 Probando conexión a la API de NVD...")

    data = await nvd_client.fetch_cves("OpenSSH 8.0")

    if data is None:
        print("❌ No se pudo conectar a la API de NVD.")
        return

    if "vulnerabilities" not in data:
        print("⚠️ Conexión OK pero sin datos (puede ser rate-limit).")
        return

    print(f"✅ Conexión exitosa. Vulnerabilidades recibidas: {len(data['vulnerabilities'])}")


if __name__ == "__main__":
    asyncio.run(test_nvd())
