import glob
import json
import os
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

# Config
DATA_GLOB = "datasets/CICIDS2017/*.csv"
OUT_DIR = "model_store"

MODEL_PATH = os.path.join(OUT_DIR, "risk_model_torch.pt")
SCALER_PATH = os.path.join(OUT_DIR, "risk_scaler.pkl")
META_PATH = os.path.join(OUT_DIR, "risk_model_meta.pkl")

SEED = 42
TEST_SIZE = 0.2
MAX_ROWS = None  # ej: 1_500_000 para limitar. None = usa todo (RAM)
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

EPOCHS = 8
BATCH_SIZE = 4096
LR = 1e-3
WEIGHT_DECAY = 1e-4


# Model
class MLPBinary(nn.Module):
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


def set_seed(seed: int):
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_csvs(pattern: str) -> pd.DataFrame:
    files = sorted(glob.glob(pattern))
    if not files:
        raise RuntimeError(f"No se encontraron CSV con patrón: {pattern}")

    dfs = []
    total = 0
    for f in files:
        print(f"[+] Leyendo: {f}")
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]

        # normalizar valores raros
        df = df.replace([np.inf, -np.inf], np.nan)

        dfs.append(df)
        total += len(df)

        if MAX_ROWS and total >= MAX_ROWS:
            break

    data = pd.concat(dfs, ignore_index=True)

    if MAX_ROWS and len(data) > MAX_ROWS:
        data = data.sample(n=MAX_ROWS, random_state=SEED).reset_index(drop=True)

    print(f"[+] Filas cargadas: {len(data):,}")
    return data


def prepare_xy(df: pd.DataFrame):
    if "Label" not in df.columns:
        raise RuntimeError("No existe la columna 'Label' en los CSV.")

    # y binaria: BENIGN=0, cualquier ataque=1
    y_raw = df["Label"].astype(str).str.strip().str.upper()
    y = (y_raw != "BENIGN").astype(np.int64).values

    Xdf = df.drop(columns=["Label"])

    # CIC-IDS2017 puede traer columnas no numéricas (p.ej. Timestamp)
    X = Xdf.select_dtypes(include=[np.number]).copy()

    # eliminar columnas totalmente vacías
    X = X.dropna(axis=1, how="all")

    # imputación rápida
    X = X.fillna(0.0)

    return X, y


def make_loader(X: np.ndarray, y: np.ndarray, batch_size: int, shuffle: bool):
    ds = torch.utils.data.TensorDataset(
        torch.tensor(X, dtype=torch.float32),
        torch.tensor(y.reshape(-1, 1), dtype=torch.float32),
    )
    return torch.utils.data.DataLoader(ds, batch_size=batch_size, shuffle=shuffle, drop_last=False)


def main():
    set_seed(SEED)
    os.makedirs(OUT_DIR, exist_ok=True)

    df = load_csvs(DATA_GLOB)
    Xdf, y = prepare_xy(df)

    # Split estratificado
    X_train, X_test, y_train, y_test = train_test_split(
        Xdf.values, y, test_size=TEST_SIZE, random_state=SEED, stratify=y
    )

    # Escalado (MinMax para compatibilidad)
    scaler = MinMaxScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    train_loader = make_loader(X_train_s, y_train, BATCH_SIZE, shuffle=True)
    test_loader = make_loader(X_test_s, y_test, BATCH_SIZE, shuffle=False)

    in_dim = X_train_s.shape[1]
    model = MLPBinary(in_dim=in_dim).to(DEVICE)

    # Pos_weight para desbalance (ataques suelen ser menos)
    pos = float(np.sum(y_train == 1))
    neg = float(np.sum(y_train == 0))
    pos_weight = torch.tensor([neg / max(pos, 1.0)], dtype=torch.float32, device=DEVICE)

    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)

    print(f"[+] Entrenando en {DEVICE} | in_dim={in_dim} | pos_weight={float(pos_weight.item()):.3f}")

    # Train
    model.train()
    for epoch in range(1, EPOCHS + 1):
        losses = []
        for xb, yb in train_loader:
            xb = xb.to(DEVICE)
            yb = yb.to(DEVICE)

            opt.zero_grad()
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            opt.step()
            losses.append(loss.item())

        print(f"Epoch {epoch}/{EPOCHS} - loss={np.mean(losses):.5f}")

    # Eval
    model.eval()
    probs_all = []
    y_true_all = []

    with torch.no_grad():
        for xb, yb in test_loader:
            xb = xb.to(DEVICE)
            logits = model(xb)
            probs = torch.sigmoid(logits).cpu().numpy().reshape(-1)
            probs_all.append(probs)
            y_true_all.append(yb.numpy().reshape(-1))

    probs_all = np.concatenate(probs_all)
    y_true_all = np.concatenate(y_true_all).astype(np.int64)
    y_pred = (probs_all >= 0.5).astype(np.int64)

    print("\n[+] Confusion matrix")
    print(confusion_matrix(y_true_all, y_pred))

    print("\n[+] F1:", f1_score(y_true_all, y_pred))
    try:
        print("[+] ROC-AUC:", roc_auc_score(y_true_all, probs_all))
    except Exception:
        pass

    print("\n[+] Report")
    print(classification_report(y_true_all, y_pred, target_names=["BENIGN", "ATTACK"]))

    # Guardar para backend
    torch.save(model.state_dict(), MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    meta = {
        "n_features": int(in_dim),
        "version": "3.0.0-mlp-torch-cicids2017",
        "trained_at_utc": datetime.utcnow().isoformat(),
        "device": DEVICE,
        "dataset": "CIC-IDS2017",
        "csv_glob": DATA_GLOB,
        "max_rows": MAX_ROWS,
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
        "lr": LR,
        "test_size": TEST_SIZE,
    }
    joblib.dump(meta, META_PATH)

    print("\n[+] Guardado OK:")
    print(" -", MODEL_PATH)
    print(" -", SCALER_PATH)
    print(" -", META_PATH)
    print("\nMeta:\n", json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
