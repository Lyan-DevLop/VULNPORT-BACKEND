from statistics import mean
from typing import List

from app.core.logger import get_logger
from app.models.hosts import Host
from app.models.ports import Port

from .neural_model import risk_model

log = get_logger(__name__)


class RiskEvaluator:
    def evaluate(self, host: Host, ports: List[Port]) -> dict:
        """
        - score max = 99.99
        - risk_level permitido: LOW, MEDIUM, HIGH, CRITICAL
        """

        total_ports = len(ports)
        high_risk_ports = sum(1 for p in ports if p.status == "open" and len(p.vulnerabilities) > 0)

        all_vulns = []
        for p in ports:
            all_vulns.extend(p.vulnerabilities)

        vuln_count = len(all_vulns)
        avg_cvss = mean([v.cvss_score for v in all_vulns if v.cvss_score]) if vuln_count > 0 else 0.0

        feature_vector = [total_ports, high_risk_ports, avg_cvss, vuln_count]

        # 1) Se intenta predecir con la red neural
        score = risk_model.predict(feature_vector)

        if score and score > 0:
            score = float(min(99.99, max(0.0, round(score, 2))))
            level = self._risk_level(score)

            return {
                "overall_risk_score": score,
                "risk_level": level,
                "model_version": risk_model.get_version(),
            }

        # 2) Fallback basado en fórmula
        score = (avg_cvss * 20) + (high_risk_ports * 8) + (vuln_count * 2)

        # Ajuste al rango maximo y minimo de la BD
        score = float(min(99.99, max(0.0, round(score, 2))))

        level = self._risk_level(score)

        return {"overall_risk_score": score, "risk_level": level, "model_version": "fallback-1.0"}

    # Niveles de riesgo
    def _risk_level(self, score: float) -> str:
        """
        Niveles de riesgo
        LOW, MEDIUM, HIGH, CRITICAL
        """
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"


risk_evaluator = RiskEvaluator()
