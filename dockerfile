# ----------------------------------------------------
# Imagen base ligera con Python 3.11
# ----------------------------------------------------
FROM python:3.11-slim

# Configuración general
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ----------------------------------------------------
# Dependencias del sistema necesarias
# ----------------------------------------------------
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------
# WORKDIR en /app
# ----------------------------------------------------
WORKDIR /app

# ----------------------------------------------------
# Copiar requirements primero (mejor cache)
# ----------------------------------------------------
COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ----------------------------------------------------
# Copiar todo el backend
# ----------------------------------------------------
COPY . .

# ----------------------------------------------------
# Variables de entorno de BD (Docker Compose las setea)
# ----------------------------------------------------
ENV DATABASE_URL=${DATABASE_URL}

# ----------------------------------------------------
# Exponer FastAPI
# ----------------------------------------------------
EXPOSE 8000

# ----------------------------------------------------
# Comando principal
# ----------------------------------------------------
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

