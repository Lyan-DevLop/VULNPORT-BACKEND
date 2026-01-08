# app/services/risk_model/neural_model.py
import os

import joblib
import numpy as np
import torch
import torch.nn as nn

from app.core.logger import get_logger

log = get_logger(__name__)

MODEL_DIR = "model_store"
MODEL_PATH = os.path.join(MODEL_DIR, "risk_model_torch.pt")
SCALER_PATH = os.path.join(MODEL_DIR, "risk_scaler.pkl")
META_PATH = os.path.join(MODEL_DIR, "risk_model_meta.pkl")

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


class MLPBinary(nn.Module):
    # Debe coincidir EXACTO con el script de entrenamiento
    def __init__(self, in_dim: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.15),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.15),
            nn.Linear(64, 1),  # logits
        )

    def forward(self, x):
        return self.net(x)


class RiskModel:
    """
    Modelo NN entrenado con CIC-IDS2017 (78 features).
    En runtime:
    - Si NO hay features de flujo -> usa baseline neutral (0.5) para obtener un prior P(attack).
    - Ese prior se mezcla con el score contextual del host (12 features) en RiskEvaluator.
    """

    def __init__(self):
        self.model: MLPBinary | None = None
        self.scaler = None
        self.meta = None
        self.in_dim = None
        self.load_model()

    def load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(META_PATH):
            try:
                self.scaler = joblib.load(SCALER_PATH)
                self.meta = joblib.load(META_PATH)
                self.in_dim = int(self.meta.get("n_features", getattr(self.scaler, "n_features_in_", 78)))

                m = MLPBinary(self.in_dim).to(DEVICE)
                state = torch.load(MODEL_PATH, map_location=DEVICE)
                m.load_state_dict(state)
                m.eval()
                self.model = m

                log.info(
                    f"NN cargada OK. Version={self.meta.get('version')} "
                    f"in_dim={self.in_dim} device={DEVICE}"
                )
            except Exception as e:
                log.error(f"Error cargando NN: {e}")
                self.model = None
                self.scaler = None
                self.meta = None
                self.in_dim = None
        else:
            log.warning("NN no encontrada en model_store/. Se usará solo fallback contextual.")

    def is_ready(self) -> bool:
        return self.model is not None and self.in_dim is not None

    def predict_attack_probability(self, flow_features: list[float] | None = None) -> float:
        """
        Retorna P(attack) en [0,1].
        - Si flow_features is None: usa baseline neutral 0.5 (ya en escala MinMax).
        - Si se entregan flow_features: se escalan con scaler y se predice.
        """
        if not self.is_ready():
            return 0.0

        # 1) construir Xs (features ya escaladas 0..1)
        if flow_features is None:
            # baseline neutral (no inventa tráfico; sólo prior estable)
            Xs = np.full((1, self.in_dim), 0.5, dtype=np.float32)
        else:
            feats = list(flow_features)
            if len(feats) > self.in_dim:
                feats = feats[: self.in_dim]
            elif len(feats) < self.in_dim:
                feats = feats + [0.0] * (self.in_dim - len(feats))

            X = np.array([feats], dtype=np.float32)
            # escala a 0..1 con el scaler entrenado
            Xs = self.scaler.transform(X).astype(np.float32)

        xt = torch.tensor(Xs, dtype=torch.float32, device=DEVICE)

        with torch.no_grad():
            logits = self.model(xt)
            prob = torch.sigmoid(logits).cpu().numpy()[0][0]

        return float(min(1.0, max(0.0, prob)))

    def get_version(self) -> str:
        if self.meta and "version" in self.meta:
            return str(self.meta["version"])
        return "unknown-nn"


risk_model = RiskModel()
