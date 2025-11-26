# ----------------------------------------------------
# Imagen base ligera con Python 3.11
# ----------------------------------------------------
FROM python:3.11-slim

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
# Variables completas de Supabase (QUEMADAS)
# ----------------------------------------------------
ENV SUPABASE_USER="postgres.tiortfqvhbpulhovbtmz" \
    SUPABASE_PASSWORD="Vacios#Port9900*" \
    SUPABASE_HOST="aws-1-us-east-1.pooler.supabase.com" \
    SUPABASE_PORT="5432" \
    SUPABASE_DB="postgres" \
    SUPABASE_SSL="require" \
    SUPABASE_OPTIONS="-4"

# ----------------------------------------------------
# Construcción automática del DATABASE_URL
# ----------------------------------------------------
ENV DATABASE_URL="postgresql://${SUPABASE_USER}:${SUPABASE_PASSWORD}@${SUPABASE_HOST}:${SUPABASE_PORT}/${SUPABASE_DB}"

# ----------------------------------------------------
# Exponer FastAPI
# ----------------------------------------------------
EXPOSE 8000

# ----------------------------------------------------
# Comando principal (FastAPI/Uvicorn)
# ----------------------------------------------------
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


