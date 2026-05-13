"""
config.py — SentinelAI Gateway Configuration
Centralizes all settings, loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from typing import List, Optional
import json
import os


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SentinelAI Gateway"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1

    # Security
    SECRET_KEY: str 
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    API_KEY_HEADER: str = "X-API-Key"
    DEMO_API_KEY: str 

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # LLM Providers
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GOOGLE_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # Database
    DATABASE_URL: str 
    REDIS_URL: str 

    # Observability
    PROMETHEUS_ENABLED: bool = True
    SEED_DEMO_DATA: bool = False   # True → seed 500 synthetic events on startup
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    GRAFANA_USERNAME: str = "admin"
    GRAFANA_PASSWORD: str
    # CORS — stored as raw string to avoid pydantic-settings JSON-list parsing issues.
    # Use the `ALLOWED_ORIGINS` property (List[str]) in application code.
    ALLOWED_ORIGINS_RAW: str = "http://localhost:3000,http://localhost:5173"

    # Policy
    DEFAULT_POLICY_PATH: str = "policies/default.yaml"

    # Security Thresholds
    INJECTION_CONFIDENCE_THRESHOLD: float = 0.7
    TOXICITY_THRESHOLD: float = 0.8
    RISK_SCORE_BLOCK_THRESHOLD: float = 0.85

    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        """Parse ALLOWED_ORIGINS_RAW — accepts JSON array or comma-separated string."""
        raw = self.ALLOWED_ORIGINS_RAW.strip()
        if raw.startswith("["):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                pass
        return [o.strip() for o in raw.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
