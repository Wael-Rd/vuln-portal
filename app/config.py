import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

dataclass
class Settings:
    app_name: str = os.getenv("APP_NAME", "Vuln Portal")
    secret_key: str = os.getenv("SECRET_KEY", "change-this-in-production")
    env: str = os.getenv("ENV", "dev")
    scheduler_enabled: bool = os.getenv("SCHEDULER_ENABLED", "true").lower() == "true"
    timezone: str = os.getenv("TIMEZONE", "UTC")
    base_url: str = os.getenv("BASE_URL", "http://localhost:8000")

    database_url: str = os.getenv("DATABASE_URL", "sqlite:///data/vulns.db")

    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None
    nvd_lookback_days: int = int(os.getenv("NVD_LOOKBACK_DAYS", "3"))
    ingest_interval_minutes: int = int(os.getenv("INGEST_INTERVAL_MINUTES", "60"))

settings = Settings()