from typing import Optional

import httpx

from app.core.logger import get_logger
from app.core.settings import get_settings

settings = get_settings()
log = get_logger(__name__)


class NVDClient:
    def __init__(self):
        self.base_url = settings.NVD_BASE_URL
        self.api_key = settings.NVD_API_KEY

    async def fetch_cves(self, keyword: str) -> Optional[dict]:
        """
        Consulta CVEs relacionadas con un servicio o versión (ej: 'OpenSSH 7.6')
        """
        params = {
            "keywordSearch": keyword,
        }

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.get(self.base_url, params=params, headers=headers)
                response.raise_for_status()
                return response.json()

        except Exception as e:
            log.error(f"Error consultando NVD: {e}")
            return None


# Instancia global reutilizable
nvd_client = NVDClient()
