import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import MinMaxScaler
from datetime import datetime

from app.core.logger import get_logger

log = get_logger(__name__)


MODEL_PATH = "risk_model.pkl"
SCALER_PATH = "risk_scaler.pkl"
MODEL_VERSION = "1.0.0"


class RiskModel:

    def __init__(self):
        self.model = None
        self.scaler = None

        # Intentar cargar el modelo automáticamente
        self.load_model()

    #  CARGAR MODELO
    def load_model(self):
        """Carga modelo y scaler si existen; sino, crea uno vacío."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                log.info(f"Modelo de riesgo cargado. Versión: {MODEL_VERSION}")

            except Exception as e:
                log.error(f"Error cargando modelo IA: {e}")
        else:
            log.warning("Modelo de riesgo no encontrado. Se entrenará cuando haya datos.")


    #  ENTRENAR MODELO (DESDE DATASET)
    def train(self, X: np.ndarray, y: np.ndarray):
        """
        Entrena el modelo IA usando un dataset (X, y).

        X → matriz de características:
              [total_ports, high_risk_ports, avg_cvss, vuln_count]

        y → score de riesgo real (0-100)
        """

        log.info("Entrenando modelo de riesgo AI...")

        # Escalado de entrada
        self.scaler = MinMaxScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Crear modelo RandomForest
        self.model = RandomForestRegressor(
            n_estimators=120,
            max_depth=8,
            random_state=42
        )
        self.model.fit(X_scaled, y)

        # Guardar archivos
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

        log.info("Modelo entrenado y guardado correctamente.")
        return True


    #  PREDICCIÓN DE RIESGO
    def predict(self, features: list[float]) -> float:
        """
        Predice un puntaje de riesgo basado en 4 valores:
            - total_ports
            - high_risk_ports
            - avg_cvss
            - vuln_count

        Devuelve el score en rango 0–100.
        """

        if self.model is None or self.scaler is None:
            log.warning("Predicción fallida: no existe modelo entrenado.")
            return 0.0

        # Convertir vector a matriz
        X = np.array([features], dtype=float)

        # Escalar
        X_scaled = self.scaler.transform(X)

        # Predecir
        score = float(self.model.predict(X_scaled)[0])

        # Limitar 0–100
        return max(0.0, min(100.0, score))

    #  METADATOS
    def get_version(self):
        return MODEL_VERSION


# Instancia global reutilizable
risk_model = RiskModel()
