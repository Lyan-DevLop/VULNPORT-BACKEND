from statistics import mean
from typing import List

from app.core.logger import get_logger
from app.models.hosts import Host
from app.models.ports import Port
from app.services.risk_model.neural_model import risk_model

log = get_logger(__name__)


class RiskEvaluator:
    def evaluate(self, host: Host, ports: List[Port]) -> dict:

        total_ports = len(ports)
        high_risk_ports = sum(1 for p in ports if p.status == "open" and len(p.vulnerabilities) > 0)

        all_vulns = []
        for p in ports:
            all_vulns.extend(p.vulnerabilities)

        vuln_count = len(all_vulns)
        avg_cvss = mean([v.cvss_score for v in all_vulns if v.cvss_score]) if vuln_count else 0.0

        features = [total_ports, high_risk_ports, avg_cvss, vuln_count]

        score = risk_model.predict(features)

        if score > 0:
            return {
                "overall_risk_score": score,
                "risk_level": self._risk_level(score),
                "model_version": risk_model.get_version(),
            }

        score = (avg_cvss * 20) + (high_risk_ports * 8) + (vuln_count * 2)
        score = float(min(99.99, max(0.0, round(score, 2))))

        return {
            "overall_risk_score": score,
            "risk_level": self._risk_level(score),
            "model_version": "fallback-1.0"
        }

    def _risk_level(self, score: float) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"


risk_evaluator = RiskEvaluator()

