FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Dependencias del sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    iputils-ping \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# WORKDIR
WORKDIR /app

# Dependencias Python
COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar backend completo
COPY . .

# Certificado SSL de Supabase
RUN chmod 644 app/certs/supabase-ca.crt

# Variables Supabase
ENV SUPABASE_USER="postgres.tiortfqvhbpulhovbtmz" \
    SUPABASE_PASSWORD="Vacios%23Port9900%2A" \
    SUPABASE_HOST="aws-1-us-east-1.pooler.supabase.com" \
    SUPABASE_PORT="6543" \
    SUPABASE_DB="postgres"


# DATABASE_URL FINAL (SSL verify-full)
ENV DATABASE_URL="postgresql+psycopg2://${SUPABASE_USER}:${SUPABASE_PASSWORD}@${SUPABASE_HOST}:${SUPABASE_PORT}/${SUPABASE_DB}?sslmode=verify-full&sslrootcert=/app/app/certs/supabase-ca.crt"

# Exponer FastAPI
EXPOSE 8000

# Ejecutar FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]



