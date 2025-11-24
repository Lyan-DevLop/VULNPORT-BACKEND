# app/services/external/nvd_cve_lookup.py

from datetime import datetime, timedelta
from typing import List, Dict, Optional

from app.core.nvd_client import nvd_client
from app.config import settings
from app.core.logger import get_logger

log = get_logger(__name__)


class CVELookupService:
    """
    Servicio externo que consulta NVD y devuelve CVEs filtrados
    y limitados según el .env.
    """

# Busca en la API NVD los archivos historicos
    async def search_cves_for_service(self, service_name: str, version: Optional[str] = None) -> List[Dict]:
        if not service_name:
            return []

        keyword = service_name
        if version:
            keyword += f" {version}"

        log.info(f"Buscando CVEs en NVD para: {keyword}")

        # Fetch básico (sin parámetros extra porque tu NVDClient no los soporta)
        data = await nvd_client.fetch_cves(keyword)

        if not data or "vulnerabilities" not in data:
            log.warning(f"No se encontraron CVEs para: {keyword}")
            return []

        vulns = data["vulnerabilities"]

        # FILTRAR POR AÑOS HACIA ATRÁS
        years_back = settings.NVD_YEARS_BACK
        cutoff_date = datetime.utcnow() - timedelta(days=years_back * 365)

        filtered_vulns = []
        for item in vulns:
            cve_data = item.get("cve", {})
            published = cve_data.get("published")  # formato ISO 8601

            if published:
                try:
                    pub_date = datetime.fromisoformat(published.replace("Z", ""))
                    if pub_date >= cutoff_date:
                        filtered_vulns.append(item)
                except:
                    pass

        # Si no hay resultados tras filtrar, devuelve lo que encuentre
        if not filtered_vulns:
            filtered_vulns = vulns

        # Limita la cantidad de resultados (MAX_RESULTS)
        max_results = settings.NVD_MAX_RESULTS
        limited_vulns = filtered_vulns[:max_results]

        #  Adapta a la BD
        results = []
        for item in limited_vulns:
            cve_data = item.get("cve", {})
            metrics = cve_data.get("metrics", {})

            results.append({
                "cve_id": cve_data.get("id"),
                "cvss_score": self._extract_cvss_score(metrics),
                "severity": self._extract_severity(metrics),
                "description": self._extract_description(cve_data),
                "published_date": cve_data.get("published"),
                "source": "NVD",
            })

        log.info(f"{len(results)} CVEs devueltos después de filtros y límites")
        return results

    # =======================================================
    # Helpers privados
    # =======================================================

    def _extract_cvss_score(self, metrics: Dict) -> Optional[float]:
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                return metrics[key][0].get("cvssData", {}).get("baseScore")
        return None


    def _extract_severity(self, metrics: Dict) -> str | None:
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                return metrics[key][0].get("cvssData", {}).get("baseSeverity")
        return None


    def _extract_description(self, cve_data: Dict) -> str:
        descriptions = cve_data.get("descriptions", [])
        if descriptions:
            return descriptions[0].get("value", "")
        return ""


cve_lookup_service = CVELookupService()



