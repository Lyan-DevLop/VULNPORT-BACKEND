# Script simple para generar un modelo de ejemplo y guardarlo en app/model.pt
import os

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from app.risk_model import RiskNet

np.random.seed(42)
num_samples = 2000
open_ports = np.random.randint(1, 50, num_samples)
high_risk_ports = np.random.randint(0, 10, num_samples)
vuln_count = np.random.randint(0, 20, num_samples)
avg_cvss = np.random.uniform(0, 10, num_samples)

risk_score = 0.4 * (high_risk_ports / 10) + 0.3 * (vuln_count / 20) + 0.3 * (avg_cvss / 10)
risk_score = np.clip(risk_score, 0, 1)

X = np.stack([open_ports, high_risk_ports, vuln_count, avg_cvss], axis=1).astype("float32")
y = risk_score.reshape(-1, 1).astype("float32")

X_tensor = torch.tensor(X)
y_tensor = torch.tensor(y)

model = RiskNet()
criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=1e-3)

epochs = 200
for epoch in range(epochs):
    optimizer.zero_grad()
    outputs = model(X_tensor)
    loss = criterion(outputs, y_tensor)
    loss.backward()
    optimizer.step()
    if (epoch + 1) % 20 == 0:
        print(f"Epoch {epoch + 1}/{epochs} loss={loss.item():.4f}")

os.makedirs("app", exist_ok=True)
torch.save(model.state_dict(), "app/model.pt")
print("Modelo guardado en app/model.pt")
