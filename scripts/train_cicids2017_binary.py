import glob
import json
import os
from datetime import datetime

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

# ================= CONFIG =================

DATA_GLOB = "datasets/CICIDS2017/*.csv"
OUT_DIR = "model_store"

MODEL_PATH = os.path.join(OUT_DIR, "risk_model_torch.pt")
SCALER_PATH = os.path.join(OUT_DIR, "risk_scaler.pkl")
METRICS_JSON_PATH = os.path.join(OUT_DIR, "training_metrics.json")
EXCEL_PATH = os.path.join(OUT_DIR, "training_report.xlsx")

SEED = 42
TEST_SIZE = 0.2
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

EPOCHS = 8
BATCH_SIZE = 4096
LR = 1e-3
WEIGHT_DECAY = 1e-4


# ================= UTIL =================

def convert_numpy(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: convert_numpy(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy(i) for i in obj]
    else:
        return obj


# ================= MODEL =================

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
            nn.Linear(64, 1),
        )

    def forward(self, x):
        return self.net(x)


# ================= MAIN =================

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    np.random.seed(SEED)
    torch.manual_seed(SEED)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # -------- Cargar datos --------
    files = sorted(glob.glob(DATA_GLOB))
    dfs = []

    for f in files:
        print(f"[+] Leyendo {f}")
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df = df.replace([np.inf, -np.inf], np.nan)
        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    df = df.fillna(0)

    y = (df["Label"].str.upper() != "BENIGN").astype(int).values
    X = df.drop(columns=["Label"]).select_dtypes(include=[np.number]).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=SEED
    )

    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    train_ds = torch.utils.data.TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train.reshape(-1, 1), dtype=torch.float32),
    )
    train_loader = torch.utils.data.DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)

    model = MLPBinary(X_train.shape[1]).to(DEVICE)

    pos = float(np.sum(y_train == 1))
    neg = float(np.sum(y_train == 0))
    pos_weight = torch.tensor([neg / max(pos, 1.0)], device=DEVICE)

    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)

    train_losses = []

    # -------- ENTRENAMIENTO --------
    for epoch in range(EPOCHS):
        model.train()
        losses = []

        for xb, yb in train_loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            optimizer.step()
            losses.append(loss.item())

        avg_loss = np.mean(losses)
        train_losses.append(avg_loss)
        print(f"Epoch {epoch+1}/{EPOCHS} - loss={avg_loss:.5f}")

    # -------- EVALUACIÓN --------
    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(X_test, dtype=torch.float32).to(DEVICE))
        probs = torch.sigmoid(logits).cpu().numpy().reshape(-1)

    y_pred = (probs >= 0.5).astype(int)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, probs)
    pr_auc = average_precision_score(y_test, probs)
    mcc = matthews_corrcoef(y_test, y_pred)
    balanced_acc = balanced_accuracy_score(y_test, y_pred)
    logloss = log_loss(y_test, probs)
    brier = brier_score_loss(y_test, probs)

    specificity = tn / (tn + fp)
    fpr_value = fp / (fp + tn)
    fnr = fn / (fn + tp)

    fpr_curve, tpr_curve, _ = roc_curve(y_test, probs)
    prec_curve, rec_curve, _ = precision_recall_curve(y_test, probs)

    print("\n[+] ROC-AUC:", roc_auc)
    print("[+] PR-AUC:", pr_auc)
    print("\n", classification_report(y_test, y_pred))

    # -------- GRÁFICAS PROFESIONALES --------

    def save_plot(name):
        png = os.path.join(OUT_DIR, f"{name}_{timestamp}.png")
        jpg = os.path.join(OUT_DIR, f"{name}_{timestamp}.jpg")
        plt.savefig(png, dpi=300)
        plt.savefig(jpg, dpi=300)
        plt.close()

    # Confusion Matrix
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    save_plot("confusion_matrix")

    # ROC Curve
    plt.figure(figsize=(6,5))
    plt.plot(fpr_curve, tpr_curve, label=f"AUC = {roc_auc:.4f}")
    plt.plot([0,1],[0,1], linestyle="--")
    plt.title("ROC Curve")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend()
    plt.tight_layout()
    save_plot("roc_curve")

    # PR Curve
    plt.figure(figsize=(6,5))
    plt.plot(rec_curve, prec_curve, label=f"PR-AUC = {pr_auc:.4f}")
    plt.title("Precision-Recall Curve")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.legend()
    plt.tight_layout()
    save_plot("pr_curve")

    # Loss Curve
    plt.figure(figsize=(6,5))
    plt.plot(train_losses)
    plt.title("Training Loss")
    plt.xlabel("Epoch")
    plt.ylabel("Loss")
    plt.tight_layout()
    save_plot("training_loss")

    # -------- EXPORTAR MÉTRICAS --------
    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "mcc": mcc,
        "balanced_accuracy": balanced_acc,
        "log_loss": logloss,
        "brier_score": brier,
        "false_positive_rate": fpr_value,
        "false_negative_rate": fnr,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp
    }

    # JSON seguro
    with open(METRICS_JSON_PATH, "w") as f:
        json.dump(convert_numpy(metrics), f, indent=2)

    # Excel
    with pd.ExcelWriter(EXCEL_PATH, engine="openpyxl") as writer:
        pd.DataFrame([metrics]).to_excel(writer, sheet_name="Metrics", index=False)
        pd.DataFrame(cm).to_excel(writer, sheet_name="Confusion Matrix", index=False)
        pd.DataFrame({"FPR": fpr_curve, "TPR": tpr_curve}).to_excel(writer, sheet_name="ROC Curve", index=False)
        pd.DataFrame({"Recall": rec_curve, "Precision": prec_curve}).to_excel(writer, sheet_name="PR Curve", index=False)

    # Guardar modelo
    torch.save(model.state_dict(), MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print("\n[+] TODO GUARDADO EN:", OUT_DIR)


if __name__ == "__main__":
    main()