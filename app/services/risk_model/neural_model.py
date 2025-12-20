import os
from datetime import datetime
from ipaddress import ip_address

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesRegressor
from sklearn.preprocessing import MinMaxScaler

from app.core.logger import get_logger
from app.database import SessionLocal
from app.models.hosts import Host

log = get_logger(__name__)

MODEL_PATH = "model_store/risk_model.pkl"
SCALER_PATH = "model_store/risk_scaler.pkl"
MODEL_VERSION = "2.0.0-env"


def _is_private_ip(value: str) -> int:
    try:
        ip = ip_address(value.strip())
        return 1 if ip.is_private else 0
    except Exception:
        return 0


def _is_loopback_ip(value: str) -> int:
    try:
        ip = ip_address(value.strip())
        return 1 if ip.is_loopback else 0
    except Exception:
        return 0


def _os_flags(os_detected: str | None) -> tuple[int, int]:
    s = (os_detected or "").lower()
    is_windows = 1 if "windows" in s else 0
    is_linux = 1 if ("linux" in s or "ubuntu" in s or "debian" in s or "centos" in s or "rhel" in s) else 0
    return is_windows, is_linux


class RiskModel:
    """
    Nuevo modelo mas robusto:
    - Se incluye entorno (privado/publico), OS, exposición, puertos críticos, etc.
    - Compatibilidad: si el scaler/model antiguo tiene n_features_in_ distinto, predict() no revienta.
    """

    MIN_HOSTS = 10
    MIN_VULNS = 10  # se dismuye la cantidad ya que ahora el riesgo no depende solo de CVEs

    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_model()

    def load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)

                n = getattr(self.scaler, "n_features_in_", None)
                log.info(f"Modelo de riesgo cargado. Versión {MODEL_VERSION}. Features esperadas: {n}")
            except Exception as e:
                self.model = None
                self.scaler = None
                log.error(f"Error cargando modelo de riesgo: {e}")
        else:
            log.warning("Modelo de riesgo no encontrado. Se usará fallback hasta entrenar.")

    # ---------- Feature engineering ----------
    def build_features_for_host(self, host: Host) -> list[float]:
        """
        Construye features robustas. No depende de NVD obligatoriamente.
        Requiere que host.ports y p.vulnerabilities existan (relaciones).
        """
        ports = getattr(host, "ports", []) or []

        total_ports = len(ports)
        open_ports = [p for p in ports if getattr(p, "status", "") == "open"]
        open_count = len(open_ports)

        # CVEs reales
        all_vulns = []
        for p in ports:
            all_vulns.extend(getattr(p, "vulnerabilities", []) or [])
        vuln_count = len(all_vulns)
        cvss_vals = [v.cvss_score for v in all_vulns if getattr(v, "cvss_score", None)]
        avg_cvss = float(np.mean(cvss_vals)) if cvss_vals else 0.0

        high_risk_ports = sum(1 for p in open_ports if len(getattr(p, "vulnerabilities", []) or []) > 0)

        # Entorno por IP
        ip = getattr(host, "ip_address", "") or ""
        is_private = _is_private_ip(ip)
        is_loopback = _is_loopback_ip(ip)

        # Flags OS
        is_windows, is_linux = _os_flags(getattr(host, "os_detected", None))

        # Exposición (reglas)
        exposure_score, critical_open_count = self._exposure_from_ports(os_detected=getattr(host, "os_detected", None), ports=open_ports)

        # “Freshness” del scan (si existe)
        scan_date = getattr(host, "scan_date", None)
        days_since_scan = 0.0
        try:
            if scan_date:
                dt = scan_date
                if isinstance(dt, datetime):
                    days_since_scan = float((datetime.utcnow() - dt).total_seconds() / 86400.0)
                    days_since_scan = float(min(365.0, max(0.0, round(days_since_scan, 2))))
        except Exception:
            days_since_scan = 0.0

        # Feature final (12)
        return [
            float(total_ports),
            float(open_count),
            float(high_risk_ports),
            float(avg_cvss),
            float(vuln_count),
            float(exposure_score),
            float(critical_open_count),
            float(is_private),
            float(is_loopback),
            float(is_windows),
            float(is_linux),
            float(days_since_scan),
        ]

    def _exposure_from_ports(self, os_detected: str | None, ports) -> tuple[float, int]:
        """
        Exposición: sube riesgo por puertos típicamente peligrosos aunque no haya CVE.
        Además da peso extra si el host es Windows y están expuestos SMB/NetBIOS/RPC.
        """
        s = (os_detected or "").lower()
        is_windows = "windows" in s
        is_linux = ("linux" in s or "ubuntu" in s or "debian" in s or "centos" in s or "rhel" in s)

        weights_win = {445: 20, 139: 12, 135: 10, 3389: 18, 5985: 12, 5986: 12, 1433: 15, 1434: 15}
        weights_linux = {22: 8, 2375: 18, 3306: 10, 5432: 10, 6379: 12, 9200: 12}

        exposure = 0.0
        critical_count = 0

        for p in ports:
            pn = getattr(p, "port_number", None)
            try:
                pn = int(pn)
            except Exception:
                continue

            if is_windows and pn in weights_win:
                exposure += weights_win[pn]
                critical_count += 1
            elif is_linux and pn in weights_linux:
                exposure += weights_linux[pn]
                critical_count += 1
            else:
                # genérico (se puede agregar 0)
                pass

        # limitar para evitar sobre-inflar
        exposure = float(min(60.0, max(0.0, exposure)))
        return exposure, critical_count

    # ---------- Training ----------
    def auto_train(self) -> bool:
        db = SessionLocal()
        try:
            hosts = db.query(Host).all()

            if len(hosts) < self.MIN_HOSTS:
                log.warning(f"No hay suficientes hosts ({len(hosts)}) para entrenar.")
                return False

            X = []
            y = []
            total_vulns = 0

            for h in hosts:
                feats = self.build_features_for_host(h)
                X.append(feats)

                # Target heurístico “ground truth” (robusto): CVEs + exposición + entorno
                # - Si es público, el mismo hallazgo pesa más 
                is_private = int(feats[7])
                exposure = feats[5]
                avg_cvss = feats[3]
                vuln_count = feats[4]
                high_risk_ports = feats[2]
                critical_open_count = feats[6]

                total_vulns += int(vuln_count)

                base = (avg_cvss * 18.0) + (high_risk_ports * 10.0) + (vuln_count * 2.5) + (exposure * 1.2) + (critical_open_count * 3.0)
                env_mult = 1.0 if is_private == 1 else 1.25  # público pesa más
                score = float(min(99.99, max(0.0, base * env_mult)))

                y.append(score)

            if total_vulns < self.MIN_VULNS:
                log.warning(f"No hay suficientes vulnerabilidades ({total_vulns}) para entrenar ML fuerte. Aun así puedes entrenar por exposición.")
                # Permitimos entrenar aunque haya pocas CVEs.

            self.train(np.array(X, dtype=float), np.array(y, dtype=float))
            log.info("Entrenamiento automático completado.")
            return True

        finally:
            db.close()

    def train(self, X: np.ndarray, y: np.ndarray):
        log.info("Entrenando modelo de riesgo (ExtraTrees) ...")

        self.scaler = MinMaxScaler()
        X_scaled = self.scaler.fit_transform(X)

        # ExtraTrees ya que suele generalizar mejor que RF en datasets pequeños/ruidosos
        self.model = ExtraTreesRegressor(
            n_estimators=300,
            max_depth=14,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled, y)

        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

        log.info(f"Modelo entrenado y guardado correctamente. Versión {MODEL_VERSION}")

    # ---------- Predict ----------
    def predict(self, features: list[float]) -> float:
        """
        Compatibilidad: si el modelo cargado espera N features y se le pasa más/menos,
        se recorta o se rellena con ceros para no romper.
        """
        if self.model is None or self.scaler is None:
            return 0.0

        try:
            expected = int(getattr(self.scaler, "n_features_in_", len(features)))
        except Exception:
            expected = len(features)

        feats = list(features)

        if len(feats) > expected:
            feats = feats[:expected]
        elif len(feats) < expected:
            feats = feats + [0.0] * (expected - len(feats))

        X = np.array([feats], dtype=float)
        X_scaled = self.scaler.transform(X)

        raw = float(self.model.predict(X_scaled)[0])
        return float(min(99.99, max(0.0, round(raw, 2))))

    def get_version(self):
        return MODEL_VERSION


risk_model = RiskModel()
