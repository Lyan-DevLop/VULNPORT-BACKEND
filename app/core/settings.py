from pydantic import BaseModel
from pydantic_settings import BaseSettings
from functools import lru_cache

# Carga ce variables y configuracion que se usa en el .env
class Settings(BaseSettings):
    APP_NAME: str = "VULNPORTS Backend"
    DEBUG: bool = False

    DATABASE_URL: str = "sqlite:///network.db"

    JWT_SECRET_KEY: str = "supersecret"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRES_MINUTES: int = 60 * 24  # 1 día

    NVD_API_KEY: str | None = None
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_MAX_RESULTS: int = 10
    NVD_YEARS_BACK: int = 5

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings():
    return Settings()
