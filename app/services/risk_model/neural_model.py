import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import MinMaxScaler

from app.core.logger import get_logger
from app.database import SessionLocal
from app.models.hosts import Host

log = get_logger(__name__)


MODEL_PATH = "risk_model.pkl"
SCALER_PATH = "risk_scaler.pkl"
MODEL_VERSION = "1.1.0"


class RiskModel:
    MIN_HOSTS = 10
    MIN_VULNS = 20

    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_model()

    # CARGAR MODELO SI EXISTE
    def load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                log.info(f"Modelo IA cargado. Versión {MODEL_VERSION}")
            except Exception as e:
                log.error(f"Error cargando modelo IA: {e}")
        else:
            log.warning("Modelo neural no encontrado. Se usará fallback hasta entrenar.")

    # AUTOENTRENAMIENTO (si hay suficientes datos)
    def auto_train(self):
        """
        Entrena automáticamente cuando exista:
        - MIN_HOSTS ó más hosts
        - MIN_VULNS ó más vulnerabilidades
        """
        db = SessionLocal()

        hosts = db.query(Host).all()
        if len(hosts) < self.MIN_HOSTS:
            log.warning(f"No hay suficientes hosts ({len(hosts)}) para entrenar IA.")
            return False

        X = []
        y = []
        total_vulns = 0

        for h in hosts:
            ports = h.ports

            total_ports = len(ports)
            high_risk_ports = sum(1 for p in ports if len(p.vulnerabilities) > 0)

            vulns = []
            for p in ports:
                vulns.extend(p.vulnerabilities)

            vuln_count = len(vulns)
            total_vulns += vuln_count

            avg_cvss = np.mean([v.cvss_score for v in vulns if v.cvss_score]) if vuln_count else 0

            # Feature vector
            X.append([total_ports, high_risk_ports, avg_cvss, vuln_count])

            # Bootstrapped label
            y.append(min(99.99, max(0.0, (avg_cvss * 20) + (high_risk_ports * 8) + (vuln_count * 2))))

        if total_vulns < self.MIN_VULNS:
            log.warning(f"No hay suficientes vulnerabilidades ({total_vulns}) para entrenar la red.")
            return False

        self.train(np.array(X), np.array(y))
        log.info("Entrenamiento neural automático completado.")
        return True

    # Modelo de entrenamiento neural
    def train(self, X: np.ndarray, y: np.ndarray):
        log.info("Entrenando modelo neural de riesgo ...")

        self.scaler = MinMaxScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = RandomForestRegressor(n_estimators=150, max_depth=10, random_state=42)
        self.model.fit(X_scaled, y)

        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

        log.info("Modelo neural entrenado y guardado correctamente.")

    # Predicion segun BD
    def predict(self, features: list[float]) -> float:
        """
        Devuelve score ajustado entre 0 y 99.99
        """
        if self.model is None or self.scaler is None:
            return 0.0

        X = np.array([features], dtype=float)
        X_scaled = self.scaler.transform(X)

        raw_score = float(self.model.predict(X_scaled)[0])

        score = min(99.99, max(0.0, round(raw_score, 2)))

        return score

    # METADATOS
    def get_version(self):
        return MODEL_VERSION


# Instancia global
risk_model = RiskModel()
