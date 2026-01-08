# app/services/risk_model/risk_evaluator.py
from typing import List
import numpy as np

from app.core.logger import get_logger
from app.models.hosts import Host
from app.models.ports import Port
from app.services.risk_model.neural_model import risk_model

log = get_logger(__name__)


class RiskEvaluator:
    """
    - NN aporta prior P(attack) (sin flows: baseline 0.5)
    - Score final = mezcla (prior + contexto de host)
    """

    W_PRIOR = 0.40
    W_CONTEXT = 0.60

    def evaluate(self, host: Host, ports: List[Port]) -> dict:
        # 12 features contextuales (si falla, usa builder fallback)
        try:
            features12 = self._build_context_features(host, ports)
        except Exception as e:
            log.warning(f"Fallo building context features: {e}")
            features12 = self._fallback_feature_build(host, ports)

        context_score = self._fallback_score_from_features(features12)  # 0..100 aprox
        prob_attack = risk_model.predict_attack_probability(flow_features=None)  # baseline prior
        prior_score = float(round(prob_attack * 100.0, 2))

        final_score = (self.W_PRIOR * prior_score) + (self.W_CONTEXT * context_score)
        final_score = float(min(99.99, max(0.0, round(final_score, 2))))

        return {
            "overall_risk_score": final_score,
            "risk_level": self._risk_level(final_score),
            "model_version": f"fusion(prior={risk_model.get_version()}+context=fallback-12f)",
            "extras": {
                "prior_attack_prob": round(prob_attack, 4),
                "prior_score": prior_score,
                "context_score": round(float(context_score), 2),
                "fusion_weights": {"prior": self.W_PRIOR, "context": self.W_CONTEXT},
            },
        }

    def _build_context_features(self, host: Host, ports: List[Port]) -> list[float]:
        # Usa 12 features
        return self._fallback_feature_build(host, ports)

    def _fallback_feature_build(self, host: Host, ports: List[Port]) -> list[float]:
        total_ports = float(len(ports))
        open_ports = [p for p in ports if getattr(p, "status", "") == "open"]
        open_count = float(len(open_ports))

        all_vulns = []
        for p in ports:
            all_vulns.extend(getattr(p, "vulnerabilities", []) or [])
        vuln_count = float(len(all_vulns))

        cvss_vals = [v.cvss_score for v in all_vulns if getattr(v, "cvss_score", None)]
        avg_cvss = float(np.mean(cvss_vals)) if cvss_vals else 0.0

        high_risk_ports = float(sum(1 for p in open_ports if len(getattr(p, "vulnerabilities", []) or []) > 0))

        os_name = (getattr(host, "os_detected", None) or "").lower()
        is_windows = 1.0 if "windows" in os_name else 0.0
        is_linux = 1.0 if ("linux" in os_name or "ubuntu" in os_name or "debian" in os_name) else 0.0

        weights_win = {445: 20, 139: 12, 135: 10, 3389: 18, 5985: 12, 5986: 12, 1433: 15, 1434: 15}
        weights_linux = {22: 8, 2375: 18, 3306: 10, 5432: 10, 6379: 12, 9200: 12}

        exposure = 0.0
        critical_open_count = 0.0
        for p in open_ports:
            try:
                pn = int(getattr(p, "port_number", 0))
            except Exception:
                continue

            if is_windows == 1.0 and pn in weights_win:
                exposure += weights_win[pn]
                critical_open_count += 1
            elif is_linux == 1.0 and pn in weights_linux:
                exposure += weights_linux[pn]
                critical_open_count += 1

        exposure = float(min(60.0, max(0.0, exposure)))

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
            float(exposure),
            float(critical_open_count),
            float(is_private),
            float(is_loopback),
            float(is_windows),
            float(is_linux),
            float(days_since_scan),
        ]

    def _fallback_score_from_features(self, f: list[float]) -> float:
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
