from typing import List
from statistics import mean

from app.models.hosts import Host
from app.models.ports import Port
from app.models.vulnerabilities import Vulnerability

from .neural_model import risk_model
from app.core.logger import get_logger

log = get_logger(__name__)


class RiskEvaluator:

    def evaluate(self, host: Host, ports: List[Port]) -> dict:
        """
        Evalúa riesgo total del host usando:
            - nº total de puertos
            - nº de puertos high risk
            - CVSS promedio
            - nº total de vulnerabilidades
        """

        # Extracion de datos
        total_ports = len(ports)
        high_risk_ports = sum(1 for p in ports if p.status == "open" and len(p.vulnerabilities) > 0)

        all_vulns: List[Vulnerability] = []
        for p in ports:
            all_vulns.extend(p.vulnerabilities)

        vuln_count = len(all_vulns)

        avg_cvss = mean([v.cvss_score for v in all_vulns if v.cvss_score]) if vuln_count > 0 else 0.0

        # Vector final para la red
        feature_vector = [
            total_ports,
            high_risk_ports,
            avg_cvss,
            vuln_count
        ]
        # Predicción
        score = risk_model.predict(feature_vector)
        level = self._risk_level(score)

        log.info(
            f"Evaluación de riesgo para {host.ip_address}: "
            f"Score={score:.2f}, Nivel={level}"
        )

        return {
            "overall_risk_score": score,
            "risk_level": level,
            "model_version": risk_model.get_version(),
        }

    # Clasificación basada en score
    def _risk_level(self, score: float) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 15:
            return "LOW"
        return "LOW"


# Instancia reutilizable
risk_evaluator = RiskEvaluator()
