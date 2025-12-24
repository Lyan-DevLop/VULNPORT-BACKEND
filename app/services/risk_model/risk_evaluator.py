from typing import List

from app.core.logger import get_logger
from app.models.hosts import Host
from app.models.ports import Port
from app.services.risk_model.neural_model import risk_model

log = get_logger(__name__)


class RiskEvaluator:
    def evaluate(self, host: Host, ports: List[Port]) -> dict:
        """
        Evaluación robusta:
        - Construye features con entorno + exposición + CVEs
        - Intenta modelo ML
        - Si no hay modelo, usa fallback coherente con las mismas features
        """

        # Para entrenar/decidir consistentemente, usamos el builder del modelo.
        # build_features_for_host usa host.ports; aquí se reciben ports, pero host.ports debe estar consistente.
        # Si host.ports no está cargado, igual funcionará en fallback.
        try:
            features = risk_model.build_features_for_host(host)
        except Exception:
            features = self._fallback_feature_build(host, ports)

        score = risk_model.predict(features)

        # Si el ML existe
        if score > 0:
            return {
                "overall_risk_score": score,
                "risk_level": self._risk_level(score),
                "model_version": risk_model.get_version(),
            }

        # Fallback robusto (mismo concepto del target)
        score = self._fallback_score_from_features(features)
        return {
            "overall_risk_score": score,
            "risk_level": self._risk_level(score),
            "model_version": "fallback-2.0-env",
        }

    def _fallback_feature_build(self, host: Host, ports: List[Port]) -> list[float]:
        total_ports = float(len(ports))
        open_ports = [p for p in ports if getattr(p, "status", "") == "open"]
        open_count = float(len(open_ports))

        all_vulns = []
        for p in ports:
            all_vulns.extend(getattr(p, "vulnerabilities", []) or [])
        vuln_count = float(len(all_vulns))

        cvss_vals = [v.cvss_score for v in all_vulns if getattr(v, "cvss_score", None)]
        avg_cvss = float(sum(cvss_vals) / len(cvss_vals)) if cvss_vals else 0.0

        high_risk_ports = float(sum(1 for p in open_ports if len(getattr(p, "vulnerabilities", []) or []) > 0))

        # Exposición básica por OS
        os_name = (getattr(host, "os_detected", None) or "").lower()
        is_windows = 1.0 if "windows" in os_name else 0.0
        is_linux = 1.0 if ("linux" in os_name or "ubuntu" in os_name or "debian" in os_name) else 0.0

        weights_win = {445: 20, 139: 12, 135: 10, 3389: 18, 1433: 15, 1434: 15}
        weights_linux = {22: 8, 2375: 18, 3306: 10, 5432: 10}

        exposure = 0.0
        critical_open_count = 0.0
        for p in open_ports:
            pn = getattr(p, "port_number", None)
            try:
                pn = int(pn)
            except Exception:
                continue

            if is_windows == 1.0 and pn in weights_win:
                exposure += weights_win[pn]
                critical_open_count += 1
            elif is_linux == 1.0 and pn in weights_linux:
                exposure += weights_linux[pn]
                critical_open_count += 1

        exposure = float(min(60.0, max(0.0, exposure)))

        # Entorno por IP
        ip = (getattr(host, "ip_address", "") or "").strip()
        is_private = 1.0 if (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")) else 0.0
        is_loopback = 1.0 if ip.startswith("127.") else 0.0

        days_since_scan = 0.0

        return [
            total_ports,
            open_count,
            high_risk_ports,
            avg_cvss,
            vuln_count,
            exposure,
            float(critical_open_count),
            float(is_private),
            float(is_loopback),
            float(is_windows),
            float(is_linux),
            float(days_since_scan),
        ]

    def _fallback_score_from_features(self, f: list[float]) -> float:
        # Mapeo según builder (12 features)
        __annotations__total_ports = f[0]
        __annotations__open_count = f[1]
        high_risk_ports = f[2]
        avg_cvss = f[3]
        vuln_count = f[4]
        exposure = f[5]
        critical_open = f[6]
        is_private = int(f[7])

        base = (avg_cvss * 18.0) + (high_risk_ports * 10.0) + (vuln_count * 2.5) + (exposure * 1.2) + (critical_open * 3.0)
        env_mult = 1.0 if is_private == 1 else 1.25
        score = float(min(99.99, max(0.0, round(base * env_mult, 2))))
        return score

    def _risk_level(self, score: float) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"


risk_evaluator = RiskEvaluator()

